"""An opt-in, owned Chrome pipe session and fixed-target request collector."""
from dataclasses import dataclass, field
from contextlib import contextmanager, nullcontext
import base64
import ctypes
from ctypes import wintypes
import hashlib
import ipaddress
import json
import math
import ntpath
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import threading
import time

from .cdp_pipe import CdpChannel, PipeTransport, ProbeError, spawn_with_pipe
from .session_binding import (DedicatedTarget, DedicatedSession, _target_fingerprint,
                              capture_process_snapshot, profile_directory_identity,
                              validate_bound_processes)

TARGET = 'https://claude.ai/cdn-cgi/trace'
REVIEWED_VERSION = '156.0.8078.48'


@dataclass(frozen=True, repr=False)
class LaunchPlan:
    target: DedicatedTarget
    proxy_port: int
    version: str
    executable_sha256: str
    fingerprint: tuple
    arguments: tuple[str, ...]
    target_url: str
    digest: str

    def __repr__(self):
        return 'LaunchPlan(<redacted>)'


@dataclass(frozen=True)
class ProbeApproval:
    plan_digest: str
    launch_and_exit: bool = False
    target_request: bool = False


@dataclass(frozen=True, repr=False)
class ProtectedProbePlan:
    launch: LaunchPlan
    policy_digest: str
    profile_directory: str = 'Default'
    max_rounds: int = 3
    round_timeout_seconds: float = 20.0

    @property
    def digest(self):
        body = [self.launch.digest, self.policy_digest, self.profile_directory,
                self.max_rounds, self.round_timeout_seconds]
        return hashlib.sha256(b'claude-protected-probe/r20\0' + json.dumps(body).encode()).hexdigest()


@dataclass(frozen=True)
class ProtectedProbeApproval:
    plan_digest: str
    grant_id: str
    max_rounds: int
    expires_at: float
    launch_and_exit: bool = False
    diagnostics: bool = False


_GRANT_LOCK = threading.Lock()
_PROTECTED_GRANTS = {}


class ProtectedProbeGrant:
    """Host-authorized R20 budget; the central runner owns the aggregate real-test quota."""
    def __init__(self, plan, approval):
        now = time.monotonic()
        if (not isinstance(plan, ProtectedProbePlan) or not isinstance(approval, ProtectedProbeApproval)
                or approval.plan_digest != plan.digest or approval.launch_and_exit is not True
                or approval.diagnostics is not True or type(approval.max_rounds) is not int
                or type(plan.max_rounds) is not int or plan.profile_directory != 'Default'
                or not 1 <= approval.max_rounds <= plan.max_rounds <= 3
                or type(approval.expires_at) not in (int, float) or not math.isfinite(approval.expires_at)
                or not now < approval.expires_at <= now+300):
            raise ProbeError('protected_authorization_required')
        _identifier(approval.grant_id)
        self.plan, self.approval = plan, approval
        self._issued_at = now
        self._launched = self._closed = False
        self._samples = set()
        self._rounds = 0
        self._lock = threading.RLock()
        with _GRANT_LOCK:
            if approval.grant_id in _PROTECTED_GRANTS:
                raise ProbeError('diagnostic_grant_reused')
            _PROTECTED_GRANTS[approval.grant_id] = self

    def is_live(self):
        now = time.monotonic()
        return (not self._closed and _PROTECTED_GRANTS.get(self.approval.grant_id) is self
                and type(now) in (int, float) and math.isfinite(now)
                and self._issued_at <= now < self.approval.expires_at
                and self.plan.digest == self.approval.plan_digest)

    def consume_launch(self, plan):
        with self._lock:
            if self._launched or not self.is_live() or plan != self.plan:
                raise ProbeError('diagnostic_launch_grant_consumed')
            self._launched = True

    def consume_round(self, sample_id):
        with self._lock:
            _identifier(sample_id)
            if (not self._launched or not self.is_live() or self._rounds >= self.approval.max_rounds
                    or sample_id in self._samples):
                raise ProbeError('diagnostic_grant_consumed')
            self._samples.add(sample_id)
            self._rounds += 1
            return self._rounds

    @property
    def rounds_used(self):
        return self._rounds

    def close(self):
        self._closed = True


@dataclass(frozen=True)
class RequestTrace:
    request_status: str
    observed_ip: str = field(repr=False)
    target_id: str
    frame_id: str
    loader_id: str
    request_id: str
    proxy_status: str = 'unknown'


@dataclass(frozen=True)
class ExitObservation:
    status: str
    reason_code: str
    root_exit_code: int | None = None


def _file_version(executable):
    version = ctypes.WinDLL('version', use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
                                     ctypes.POINTER(wintypes.UINT)]
    version.VerQueryValueW.restype = wintypes.BOOL
    ignored = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(executable, ctypes.byref(ignored))
    if not 52 <= size <= 1048576:
        raise ProbeError('version_unavailable')
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(executable, 0, size, data):
        raise ProbeError('version_unavailable')
    pointer, length = ctypes.c_void_p(), wintypes.UINT()
    if not version.VerQueryValueW(data, '\\', ctypes.byref(pointer), ctypes.byref(length)) or length.value < 52:
        raise ProbeError('version_unavailable')
    values = struct.unpack('<13I', ctypes.string_at(pointer, 52))
    if values[0] != 0xFEEF04BD:
        raise ProbeError('version_unavailable')
    high, low = values[4:6]
    return f'{high >> 16}.{high & 65535}.{low >> 16}.{low & 65535}'


def _plan_digest(target, port, version, sha, fingerprint, arguments):
    payload = [target.executable, target.user_data_dir, port, version, sha, fingerprint, arguments, TARGET]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def prepare_launch(target, proxy_port, *, selected=False):
    if selected is not True:
        raise ProbeError('target_not_selected')
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise ProbeError('invalid_proxy_port')
    try:
        fingerprint = _target_fingerprint(target)
        if any(Path(target.user_data_dir).iterdir()):
            raise ProbeError('data_directory_not_empty')
        version = _file_version(target.executable)
        if version != REVIEWED_VERSION:
            raise ProbeError('version_not_reviewed')
        sha = hashlib.sha256(Path(target.executable).read_bytes()).hexdigest()
        if fingerprint != _target_fingerprint(target):
            raise ProbeError('target_changed')
        arguments = (target.executable, '--user-data-dir=' + target.user_data_dir,
                     '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                     '--disable-component-update', '--disable-quic', '--remote-debugging-pipe',
                     '--proxy-server=http://127.0.0.1:' + str(proxy_port), 'about:blank')
        digest = _plan_digest(target, proxy_port, version, sha, fingerprint, arguments)
        return LaunchPlan(target, proxy_port, version, sha, fingerprint, arguments, TARGET, digest)
    except (OSError, ValueError, TypeError, AttributeError):
        raise ProbeError('launch_plan_unavailable') from None


def prepare_protected_launch(target, relay_port, policy_digest, *, selected=False,
                             max_rounds=3, round_timeout_seconds=20.0):
    if (not isinstance(policy_digest, str) or re.fullmatch('[0-9a-f]{64}', policy_digest) is None
            or type(max_rounds) is not int or not 1 <= max_rounds <= 3
            or type(round_timeout_seconds) not in (int, float) or not math.isfinite(round_timeout_seconds)
            or not 0 < round_timeout_seconds <= 30):
        raise ProbeError('protected_plan_invalid')
    return ProtectedProbePlan(prepare_launch(target, relay_port, selected=selected),
                              policy_digest, max_rounds=max_rounds,
                              round_timeout_seconds=round_timeout_seconds)


def launch_probe(plan, *, approval=None, proxy_preflight=None):
    if (not isinstance(plan, LaunchPlan) or not isinstance(approval, ProbeApproval)
            or approval.plan_digest != plan.digest or approval.launch_and_exit is not True
            or approval.target_request is not True):
        raise ProbeError('authorization_required')
    current = prepare_launch(plan.target, plan.proxy_port, selected=True)
    if current != plan:
        raise ProbeError('launch_plan_changed')
    snapshot = capture_process_snapshot(plan.target)
    if not snapshot.complete or snapshot.processes:
        raise ProbeError('existing_or_unknown_browser')
    if not callable(proxy_preflight) or proxy_preflight(plan) is not True:
        raise ProbeError('proxy_preflight_required')
    if prepare_launch(plan.target, plan.proxy_port, selected=True) != plan:
        raise ProbeError('launch_plan_changed')
    snapshot = capture_process_snapshot(plan.target)
    if not snapshot.complete or snapshot.processes:
        raise ProbeError('existing_or_unknown_browser')
    # Numeric values are inherited HANDLEs, not CRT fd numbers 3/4.
    process, transport = spawn_with_pipe(lambda read, write: [*plan.arguments[:-1],
                                      f'--remote-debugging-io-pipes={read},{write}', 'about:blank'])
    owned = _OwnedProbe(plan, process, transport)
    try:
        version = owned._channel.command('Browser.getVersion', {}, time.monotonic()+8)
        if version.get('product') not in ('Chrome/'+plan.version, 'HeadlessChrome/'+plan.version):
            raise ProbeError('runtime_version_mismatch')
        if type(process) is not subprocess.Popen or type(transport) is not PipeTransport:
            raise ProbeError('runtime_channel_unconfirmed')
        owned._runtime_verified = True
        return owned
    except Exception:
        owned.close()
        failure = ProbeError('pipe_handshake_failed')
        failure.owned_probe = owned
        raise failure from None


def _read_policy(plan, reader):
    from src.protection.dedicated_wfp import PolicyReadbackVerifier
    if (type(reader) is not PolicyReadbackVerifier or reader._factory is not None
            or reader.plan.digest != plan.policy_digest or reader.plan.target != plan.launch.target
            or reader.plan.identity.source != 'windows_wfp'
            or reader.plan.identity.executable_sha256 != plan.launch.executable_sha256
            or reader.plan.identity.fingerprint != plan.launch.fingerprint
            or reader.plan.relay_port != plan.launch.proxy_port):
        raise ProbeError('native_policy_readback_required')
    proof = reader.read()
    if proof.source != 'native_wfp' or reader.accepts(proof) is not True:
        raise ProbeError('native_policy_readback_unconfirmed')
    return proof


def launch_protected_probe(plan, *, grant=None, policy_verifier=None,
                           proxy_preflight=None, diagnostic_gate=None):
    """R20 only. The caller owns system-policy deployment and the real-test budget."""
    if (not isinstance(plan, ProtectedProbePlan) or type(grant) is not ProtectedProbeGrant
            or grant.plan != plan or not grant.is_live() or not callable(diagnostic_gate)):
        raise ProbeError('protected_authorization_required')
    _read_policy(plan, policy_verifier)
    current = prepare_protected_launch(plan.launch.target, plan.launch.proxy_port, plan.policy_digest,
        selected=True, max_rounds=plan.max_rounds, round_timeout_seconds=plan.round_timeout_seconds)
    if current != plan:
        raise ProbeError('launch_plan_changed')
    snapshot = capture_process_snapshot(plan.launch.target)
    if not snapshot.complete or snapshot.processes:
        raise ProbeError('existing_or_unknown_browser')
    if not callable(proxy_preflight) or proxy_preflight(plan.launch) is not True:
        raise ProbeError('proxy_preflight_required')
    if prepare_launch(plan.launch.target, plan.launch.proxy_port, selected=True) != plan.launch:
        raise ProbeError('launch_plan_changed')
    snapshot = capture_process_snapshot(plan.launch.target)
    if not snapshot.complete or snapshot.processes:
        raise ProbeError('existing_or_unknown_browser')
    _read_policy(plan, policy_verifier)
    grant.consume_launch(plan)
    process, transport = spawn_with_pipe(lambda read, write: [*plan.launch.arguments[:-1],
        f'--remote-debugging-io-pipes={read},{write}', 'about:blank'])
    owned = _ProtectedProbe(plan, process, transport, grant, policy_verifier, diagnostic_gate)
    try:
        version = owned._channel.command('Browser.getVersion', {}, time.monotonic()+8)
        if version.get('product') not in ('Chrome/'+plan.launch.version, 'HeadlessChrome/'+plan.launch.version):
            raise ProbeError('runtime_version_mismatch')
        if type(process) is not subprocess.Popen or type(transport) is not PipeTransport:
            raise ProbeError('runtime_channel_unconfirmed')
        _read_policy(plan, policy_verifier)
        owned._runtime_verified = True
        return owned
    except BaseException as failure:
        failure.owned_probe = owned
        try:
            owned.close()
        except BaseException as close_error:
            failure.add_note('owned_probe_close_failed:' + type(close_error).__name__)
            failure.cleanup_error = close_error
        raise


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,256}', value):
        raise ProbeError('invalid_protocol_identifier')
    return value


def _trace_ip(body):
    if (not isinstance(body, dict) or not isinstance(body.get('body'), str)
            or type(body.get('base64Encoded')) is not bool or len(body['body']) > 8192):
        raise ProbeError('trace_body_invalid')
    try:
        raw = base64.b64decode(body['body'], validate=True) if body['base64Encoded'] else body['body'].encode('utf-8')
        if len(raw) > 4096:
            raise ValueError()
        fields = {}
        for line in raw.decode('utf-8').splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ('h', 'ip'):
                if key in fields:
                    raise ValueError()
                fields[key] = value.strip()
        if fields.get('h') != 'claude.ai':
            raise ValueError()
        return str(ipaddress.ip_address(fields.get('ip', '')))
    except (ValueError, UnicodeError):
        raise ProbeError('trace_body_invalid') from None


class _TraceEvents:
    def __init__(self, channel, session, frame, deadline, byte_limit=None):
        self.channel, self.session, self.frame, self.deadline = channel, session, frame, deadline
        self.request = self.loader = self.fetch_network = None
        self.response = self.finished = False
        self.byte_limit, self.received = byte_limit, 0

    def __call__(self, message):
        if message.get('sessionId') != self.session:
            return
        method, params = message['method'], message.get('params', {})
        if method == 'Fetch.requestPaused':
            fetch_id = _identifier(params.get('requestId'))
            request = params.get('request', {})
            allowed = (self.fetch_network is None and params.get('frameId') == self.frame
                       and params.get('resourceType') == 'Document' and request.get('url') == TARGET
                       and request.get('method') == 'GET' and not request.get('hasPostData')
                       and 'redirectedRequestId' not in params and 'responseStatusCode' not in params)
            if not allowed:
                self.channel.send('Fetch.failRequest', {'requestId': fetch_id, 'errorReason': 'BlockedByClient'},
                                  self.deadline, self.session)
                if params.get('resourceType') == 'Document':
                    raise ProbeError('request_scope_mismatch')
                return
            self.fetch_network = _identifier(params.get('networkId'))
            self.channel.send('Fetch.continueRequest', {'requestId': fetch_id}, self.deadline, self.session)
        elif method == 'Network.requestWillBeSent' and params.get('type') == 'Document':
            request = params.get('request', {})
            if (self.request is not None or params.get('frameId') != self.frame or 'redirectResponse' in params
                    or request.get('url') != TARGET or request.get('method') != 'GET' or request.get('hasPostData')):
                raise ProbeError('request_scope_mismatch')
            self.request = _identifier(params.get('requestId'))
            self.loader = _identifier(params.get('loaderId'))
        elif method == 'Network.responseReceived' and params.get('requestId') == self.request:
            response = params.get('response', {})
            if (self.response or params.get('loaderId') != self.loader or params.get('frameId') != self.frame
                    or params.get('type') != 'Document' or response.get('url') != TARGET
                    or response.get('status') != 200 or response.get('mimeType') != 'text/plain'
                    or response.get('securityState') != 'secure'
                    or any(response.get(key, False) is not False for key in
                           ('fromDiskCache', 'fromServiceWorker', 'fromPrefetchCache'))):
                raise ProbeError('response_untrusted')
            self.response = True
        elif (method == 'Network.requestServedFromCache' or
              method == 'Network.loadingFailed' and params.get('requestId') == self.request):
            raise ProbeError('request_failed_or_cached')
        elif method == 'Network.loadingFinished' and params.get('requestId') == self.request:
            if not self.response or self.finished:
                raise ProbeError('request_event_order')
            if self.byte_limit is not None:
                length = params.get('encodedDataLength')
                if (type(length) not in (int, float) or not math.isfinite(length)
                        or not 0 <= length <= self.byte_limit):
                    raise ProbeError('response_too_large')
            self.finished = True
        elif method == 'Network.dataReceived' and params.get('requestId') == self.request and self.byte_limit is not None:
            length = params.get('dataLength')
            if type(length) is not int or length < 0:
                raise ProbeError('response_size_unconfirmed')
            self.received += length
            if self.received > self.byte_limit:
                raise ProbeError('response_too_large')


def _run_trace(channel, expected, target, session, frame, deadline, *, observer=None, gate=None, bounded=False):
    events = _TraceEvents(channel, session, frame, deadline, 16384 if bounded else None)
    def dispatch(message):
        if observer is not None:
            observer(message)
        events(message)
    channel.on_event = dispatch
    channel.command('Network.enable', {'maxTotalBufferSize': 16384, 'maxResourceBufferSize': 8192,
                                      'maxPostDataSize': 0}, deadline, session)
    channel.command('Network.setCacheDisabled', {'cacheDisabled': True}, deadline, session)
    channel.command('Network.setBypassServiceWorker', {'bypass': True}, deadline, session)
    channel.command('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]}, deadline, session)
    with nullcontext() if gate is None else gate() as permission:
        if isinstance(permission, DiagnosticIntent):
            deadline = min(deadline, permission.expires_at)
            events.deadline = deadline
        navigation = channel.command('Page.navigate', {'url': TARGET, 'frameId': frame}, deadline, session)
        if navigation.get('errorText') or navigation.get('isDownload') or navigation.get('frameId') != frame:
            raise ProbeError('navigation_failed')
        loader = _identifier(navigation.get('loaderId'))
        while not events.finished:
            channel.pump(deadline)
        channel.flush(deadline)
        if events.loader != loader or events.fetch_network != events.request:
            raise ProbeError('request_correlation_failed')
        observed = _trace_ip(channel.command('Network.getResponseBody', {'requestId': events.request}, deadline, session))
        return RequestTrace('pass' if observed == expected else 'fail', observed, target, frame, loader, events.request)


def collect_trace(channel, expected_ip, *, deadline):
    """Collect only a newly created blank context's fixed trace page; no runtime label."""
    context = None
    try:
        expected = str(ipaddress.ip_address(expected_ip))
        context = _identifier(channel.command('Target.createBrowserContext', {'disposeOnDetach': True}, deadline).get('browserContextId'))
        target = _identifier(channel.command('Target.createTarget', {'url': 'about:blank',
                             'browserContextId': context, 'background': True}, deadline).get('targetId'))
        session = _identifier(channel.command('Target.attachToTarget', {'targetId': target, 'flatten': True}, deadline).get('sessionId'))
        channel.command('Page.enable', {}, deadline, session)
        tree = channel.command('Page.getFrameTree', {}, deadline, session)['frameTree']
        if tree['frame'].get('url') != 'about:blank' or tree.get('childFrames'):
            raise ProbeError('new_blank_page_unconfirmed')
        frame = _identifier(tree['frame']['id'])
        return _run_trace(channel, expected, target, session, frame, deadline)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ProbeError('request_unconfirmed') from None
    finally:
        channel.on_event = None
        if context is not None:
            channel.command('Target.disposeBrowserContext', {'browserContextId': context}, deadline)


@dataclass(frozen=True)
class ProfileRequestContext:
    browser_context_id: str
    version_target_id: str
    version_frame_id: str
    unique_execution_context_id: str
    trace_target_id: str
    trace_frame_id: str
    profile: object = field(repr=False)
    observed_at: float


@dataclass(frozen=True)
class ProfileTrace:
    context: ProfileRequestContext
    trace: RequestTrace
    completed_at: float

    @property
    def profile(self):
        return self.context.profile

    @property
    def browser_context_id(self):
        return self.context.browser_context_id


def _target_info(channel, target, context, url, deadline):
    info = channel.command('Target.getTargetInfo', {'targetId': target}, deadline).get('targetInfo', {})
    if (info.get('targetId') != target or info.get('type') != 'page'
            or info.get('browserContextId') != context or info.get('url') != url):
        raise ProbeError('owned_context_unconfirmed')


def _profile_frame(channel, session, frame, deadline):
    tree = channel.command('Page.getFrameTree', {}, deadline, session).get('frameTree', {})
    actual = tree.get('frame', {})
    if actual.get('id') != frame or actual.get('url') != 'chrome://version/' or tree.get('childFrames'):
        raise ProbeError('profile_frame_unconfirmed')


def _new_page(channel, context, owned, deadline):
    target = _identifier(channel.command('Target.createTarget', {'url': 'about:blank',
        'browserContextId': context, 'background': True}, deadline).get('targetId'))
    if target in owned:
        raise ProbeError('owned_target_reused')
    owned.append(target)
    _target_info(channel, target, context, 'about:blank', deadline)
    session = _identifier(channel.command('Target.attachToTarget',
        {'targetId': target, 'flatten': True}, deadline).get('sessionId'))
    channel.command('Page.enable', {}, deadline, session)
    tree = channel.command('Page.getFrameTree', {}, deadline, session)['frameTree']
    if tree['frame'].get('url') != 'about:blank' or tree.get('childFrames'):
        raise ProbeError('new_blank_page_unconfirmed')
    return target, session, _identifier(tree['frame']['id'])


class _ProfileEvents:
    def __init__(self, session, frame):
        self.session, self.frame = session, frame
        self.unique = self.context_id = None
        self.invalid = False

    def __call__(self, message):
        params = message.get('params', {})
        if (message.get('method') == 'Target.detachedFromTarget'
                and params.get('sessionId') == self.session):
            self.invalid = True
        if message.get('sessionId') != self.session:
            return
        method = message['method']
        if method == 'Runtime.executionContextCreated':
            context = params.get('context', {});aux = context.get('auxData', {})
            if aux.get('frameId') == self.frame and aux.get('isDefault') is True and context.get('origin') in ('chrome://version', 'chrome://version/'):
                unique = _identifier(context.get('uniqueId'))
                if self.unique is not None and self.unique != unique:
                    self.invalid = True
                self.unique, self.context_id = unique, context.get('id')
        elif method == 'Runtime.executionContextsCleared' and self.unique is not None:
            self.invalid = True
        elif method == 'Runtime.executionContextDestroyed' and self.unique is not None:
            if params.get('executionContextId') == self.context_id or params.get('executionContextUniqueId') == self.unique:
                self.invalid = True
        elif method in ('Page.frameAttached', 'Page.frameDetached'):
            self.invalid = True
        elif method == 'Page.frameNavigated':
            frame = params.get('frame', {})
            if frame.get('id') != self.frame or frame.get('url') != 'chrome://version/':
                self.invalid = True

    def check(self):
        if self.invalid or self.unique is None:
            raise ProbeError('profile_execution_context_unconfirmed')
        return self.unique


def collect_profile_trace(channel, target, profile_directory, expected_ip, *, deadline, on_ready=None):
    """Owned pages only; returned protocol evidence is not by itself a runtime attestation."""
    owned, failure = [], None
    try:
        if not callable(on_ready):
            raise ProbeError('diagnostic_gate_required')
        expected = str(ipaddress.ip_address(expected_ip))
        context = _identifier(channel.command('Target.getBrowserContexts', {}, deadline).get('defaultBrowserContextId'))
        version, version_session, version_frame = _new_page(channel, context, owned, deadline)
        events = _ProfileEvents(version_session, version_frame)
        channel.on_event = events
        channel.command('Runtime.enable', {}, deadline, version_session)
        navigation = channel.command('Page.navigate', {'url': 'chrome://version/',
            'frameId': version_frame}, deadline, version_session)
        if navigation.get('errorText') or navigation.get('isDownload') or navigation.get('frameId') != version_frame:
            raise ProbeError('profile_navigation_failed')
        while events.unique is None:
            if events.invalid:raise ProbeError('profile_execution_context_unconfirmed')
            channel.pump(deadline)
        unique = events.check()
        path = ''
        while not path:
            path = channel.read_profile_path(unique, deadline, version_session)
            if events.check() != unique:raise ProbeError('profile_execution_context_unconfirmed')
            if not path:
                if time.monotonic() + .05 >= deadline:raise ProbeError('profile_path_timeout')
                time.sleep(.05)
        profile = profile_directory_identity(target, profile_directory, path)
        _target_info(channel, version, context, 'chrome://version/', deadline)
        _profile_frame(channel, version_session, version_frame, deadline)
        trace_target, trace_session, trace_frame = _new_page(channel, context, owned, deadline)
        if trace_session == version_session:
            raise ProbeError('owned_session_reused')
        correlation = ProfileRequestContext(context, version, version_frame, unique,
            trace_target, trace_frame, profile, time.monotonic())
        trace = _run_trace(channel, expected, trace_target, trace_session, trace_frame, deadline,
            observer=events, gate=lambda: on_ready(correlation), bounded=True)
        if events.check() != unique:raise ProbeError('profile_execution_context_unconfirmed')
        _target_info(channel, version, context, 'chrome://version/', deadline)
        _profile_frame(channel, version_session, version_frame, deadline)
        _target_info(channel, trace_target, context, TARGET, deadline)
        current_path = channel.read_profile_path(unique, deadline, version_session)
        if (events.check() != unique or profile_directory_identity(target, profile_directory, current_path) != profile
                or _identifier(channel.command('Target.getBrowserContexts', {}, deadline).get('defaultBrowserContextId')) != context):
            raise ProbeError('profile_changed')
        return ProfileTrace(correlation, trace, time.monotonic())
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        failure = ProbeError('profile_request_unconfirmed')
        raise failure from error
    except BaseException as error:
        failure = error
        raise
    finally:
        channel.on_event = None
        errors = []
        for target_id in reversed(owned):
            try:
                result = channel.command('Target.closeTarget', {'targetId': target_id}, time.monotonic()+2)
                if result.get('success') is not True:raise ProbeError('owned_target_close_unconfirmed')
            except BaseException as error:
                errors.append(error)
        if errors:
            if failure is not None:
                failure.add_note('owned_target_cleanup_failed')
                failure.cleanup_errors = tuple(errors)
            else:
                failure = ProbeError('owned_target_cleanup_failed')
                failure.cleanup_errors = tuple(errors)
                raise failure from errors[0]


class _OwnedProbe:
    def __init__(self, plan, process, transport):
        self.plan, self._process, self._transport = plan, process, transport
        self._channel = CdpChannel(transport)
        self._identity = DedicatedSession(plan.target, selected=True, max_age_seconds=60)
        self._consumed = False
        self._runtime_verified = False
        self._closed = threading.Event()
        self._lock = threading.Lock()

    def binding(self):
        from src.core.monitoring import binding_from_session
        from .inspection import BrowserSelection
        if not self._runtime_verified:
            raise ProbeError('runtime_channel_unconfirmed')
        try:
            if (_target_fingerprint(self.plan.target) != self.plan.fingerprint or
                    hashlib.sha256(Path(self.plan.target.executable).read_bytes()).hexdigest() != self.plan.executable_sha256):
                raise ProbeError('launch_target_changed')
        except (OSError, ValueError, TypeError):
            raise ProbeError('launch_target_changed') from None
        if self._closed.is_set() or self._process.poll() is not None:
            raise ProbeError('owned_browser_unavailable')
        evidence = self._identity.poll()
        if (evidence.root is None or evidence.root.pid != self._process.pid
                or self._process.poll() is not None):
            raise ProbeError('owned_browser_unconfirmed')
        selection = BrowserSelection(TARGET, self.plan.target.executable, self.plan.target.user_data_dir, 'Default')
        try:
            return binding_from_session(selection, evidence, now=time.monotonic())
        except ValueError:
            raise ProbeError('owned_browser_unconfirmed') from None

    def __call__(self, config, binding, sample_id):
        from src.core.monitoring import BrowserBindingEvidence
        started = time.monotonic()
        with self._lock:
            if self._consumed:
                raise ProbeError('single_request_authorization_consumed')
            if self.binding() != binding:
                raise ProbeError('binding_changed')
            self._consumed = True
            trace = collect_trace(self._channel, config.expected_ip, deadline=started+15)
            if self._closed.is_set() or self.binding() != binding:
                raise ProbeError('binding_changed')
            if time.monotonic() >= started+30:
                raise ProbeError('request_evidence_expired')
            # CDP identifies the response but cannot prove its proxy route.
            return BrowserBindingEvidence(binding, sample_id, started, identity_status='pass',
                                          request_status=trace.request_status, observed_ip=trace.observed_ip,
                                          source='runtime', expires_at=started+30)

    def close(self):
        self._closed.set()
        self._identity.close()
        self._transport.close()

    def exit_status(self):
        if not self._closed.is_set():
            return ExitObservation('unknown', 'pipe_not_closed')
        code = self._process.poll()
        if code is None:
            return ExitObservation('unknown', 'owned_root_still_running')
        snapshot = capture_process_snapshot(self.plan.target)
        if not snapshot.complete:
            return ExitObservation('unknown', 'exit_snapshot_unavailable', code)
        if snapshot.processes:
            return ExitObservation('unknown', 'selected_processes_remain', code)
        return ExitObservation('exited', 'owned_root_and_selected_processes_absent', code)


@dataclass(frozen=True, repr=False)
class DiagnosticIntent:
    intent_id: str
    grant_id: str
    round_number: int
    binding: object
    sample_id: str
    policy_readback: object
    profile_context: ProfileRequestContext
    issued_at: float
    expires_at: float
    target_url: str = TARGET


@dataclass(frozen=True, repr=False)
class DiagnosticResult:
    intent: DiagnosticIntent
    profile_trace: ProfileTrace
    policy_after: object
    evidence: object
    started_at: float
    completed_at: float
    expires_at: float


class _ProtectedProbe(_OwnedProbe):
    """Issuer for one owned pipe and R20 grant; not an adversarial Python boundary."""
    def __init__(self, plan, process, transport, grant, policy_verifier, diagnostic_gate):
        super().__init__(plan.launch, process, transport)
        self.protected_plan, self.grant = plan, grant
        self._policy_verifier, self._gate = policy_verifier, diagnostic_gate
        self._binding = self._session_evidence = None
        self._active_intent = self._last_result = None
        self._invalidated = False

    @property
    def session_evidence(self):
        # Original double-CIM result, never retimestamped as a fresh observation.
        return self._session_evidence

    @property
    def last_result(self):
        return self._last_result

    def _invalidate(self):
        self._invalidated = True
        self._active_intent = self._last_result = None
        self._identity.close()

    def _check_profile(self, context):
        path = str(Path(self.plan.target.user_data_dir)/self.protected_plan.profile_directory)
        if profile_directory_identity(self.plan.target, self.protected_plan.profile_directory, path) != context.profile:
            raise ProbeError('profile_changed')

    def binding(self):
        from src.core.monitoring import binding_from_session
        from .inspection import BrowserSelection
        if not self._runtime_verified:
            raise ProbeError('runtime_channel_unconfirmed')
        if self._invalidated or self._closed.is_set() or not self.grant.is_live() or self._process.poll() is not None:
            raise ProbeError('owned_browser_unavailable')
        try:
            if (_target_fingerprint(self.plan.target) != self.plan.fingerprint
                    or hashlib.sha256(Path(self.plan.target.executable).read_bytes()).hexdigest() != self.plan.executable_sha256):
                raise ProbeError('launch_target_changed')
            if self._binding is None:
                evidence = self._identity.poll()
                if evidence.root is None or evidence.root.pid != self._process.pid:
                    raise ProbeError('owned_browser_unconfirmed')
                selection = BrowserSelection(TARGET, self.plan.target.executable, self.plan.target.user_data_dir,
                                             self.protected_plan.profile_directory)
                binding = binding_from_session(selection, evidence, now=time.monotonic())
                validate_bound_processes(binding, self.plan.fingerprint)
                self._binding, self._session_evidence = binding, evidence
            else:
                validate_bound_processes(self._binding, self.plan.fingerprint)
            if self._process.poll() is not None:
                raise ProbeError('owned_browser_unavailable')
            return self._binding
        except Exception:
            self._invalidate()
            raise ProbeError('owned_browser_unconfirmed') from None

    def accepts_intent(self, intent):
        try:
            now = time.monotonic()
            valid = (isinstance(intent, DiagnosticIntent) and intent is self._active_intent
                and math.isfinite(now) and intent.issued_at <= now < intent.expires_at
                and intent.target_url == TARGET and intent.grant_id == self.grant.approval.grant_id
                and self._policy_verifier.accepts(intent.policy_readback) is True
                and self.binding() == intent.binding)
            if valid:
                self._check_profile(intent.profile_context)
            if not valid:
                return False
            live = (self.grant.is_live() and self._policy_verifier.accepts(intent.policy_readback) is True)
            ended = time.monotonic()
            return (live and not self._closed.is_set() and not self._invalidated
                    and intent is self._active_intent and math.isfinite(ended)
                    and now <= ended < intent.expires_at)
        except Exception:
            self._invalidate()
            return False

    def accepts_result(self, result):
        try:
            now = time.monotonic()
            valid = (isinstance(result, DiagnosticResult) and result is self._last_result
                and math.isfinite(now) and result.completed_at <= now < result.expires_at
                and self._policy_verifier.accepts(result.policy_after) is True
                and self.binding() == result.intent.binding)
            if valid:
                self._check_profile(result.profile_trace.context)
            if not valid:
                return False
            live = (self.grant.is_live() and self._policy_verifier.accepts(result.policy_after) is True)
            ended = time.monotonic()
            return (live and not self._closed.is_set() and not self._invalidated
                    and result is self._last_result and math.isfinite(ended)
                    and now <= ended < result.expires_at)
        except Exception:
            self._invalidate()
            return False

    def __call__(self, config, binding, sample_id):
        from src.core.monitoring import BrowserBindingEvidence
        started = time.monotonic()
        with self._lock:
            self._last_result = None
            round_number = self.grant.consume_round(sample_id)
            if self.binding() != binding:
                raise ProbeError('binding_changed')
            deadline = min(started+self.protected_plan.round_timeout_seconds, self.grant.approval.expires_at)
            issued = []
            @contextmanager
            def ready(context):
                if self.binding() != binding:
                    raise ProbeError('binding_changed')
                proof = _read_policy(self.protected_plan, self._policy_verifier)
                now = time.monotonic()
                intent = DiagnosticIntent(secrets.token_hex(16), self.grant.approval.grant_id, round_number,
                    binding, sample_id, proof, context, now, min(deadline, proof.expires_at))
                self._active_intent = intent
                issued.append(intent)
                try:
                    if not self.accepts_intent(intent):
                        raise ProbeError('diagnostic_intent_unconfirmed')
                    with self._gate(intent):
                        if not self.accepts_intent(intent):
                            raise ProbeError('diagnostic_intent_unconfirmed')
                        yield intent
                        if not self.accepts_intent(intent):
                            raise ProbeError('diagnostic_intent_expired')
                finally:
                    self._active_intent = None
            profile_trace = collect_profile_trace(self._channel, self.plan.target,
                self.protected_plan.profile_directory, config.expected_ip, deadline=deadline, on_ready=ready)
            if len(issued) != 1 or self.binding() != binding:
                raise ProbeError('binding_changed')
            after = _read_policy(self.protected_plan, self._policy_verifier)
            ended = time.monotonic()
            expires = min(issued[0].expires_at, after.expires_at, deadline)
            if not started <= ended < expires:
                raise ProbeError('request_evidence_expired')
            evidence = BrowserBindingEvidence(binding, sample_id, started, identity_status='pass',
                request_status=profile_trace.trace.request_status, observed_ip=profile_trace.trace.observed_ip,
                source='runtime', expires_at=expires, request_profile_status='pass',
                request_profile_directory=self.protected_plan.profile_directory,
                request_profile_source='selected_profile_context')
            result = DiagnosticResult(issued[0], profile_trace, after, evidence, started, ended, expires)
            self._last_result = result
            if not self.accepts_result(result):
                self._last_result = None
                raise ProbeError('request_evidence_expired')
            return evidence

    def close(self):
        self._active_intent = self._last_result = None
        self.grant.close()
        super().close()


@dataclass(frozen=True, repr=False)
class ProductionProbePlan:
    launch: LaunchPlan
    policy_digest: str
    profile_directory: str
    round_timeout_seconds: float = 10.0
    evidence_ttl_seconds: float = 30.0

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(['production-v1', self.launch.digest, self.policy_digest,
            self.profile_directory, self.round_timeout_seconds, self.evidence_ttl_seconds]).encode()).hexdigest()


class ProductionSessionGrant:
    """One user-started application session, independent of historical trial grants."""
    def __init__(self, plan, cancelled):
        from types import SimpleNamespace
        self.plan, self.cancelled = plan, cancelled
        self.approval = SimpleNamespace(plan_digest=plan.digest, grant_id=secrets.token_hex(16),
                                        expires_at=math.inf)
        self._launched = self._closed = False
        self._samples, self._inflight = set(), None
        self._lock = threading.Lock()

    def is_live(self):
        return not self._closed and not self.cancelled.is_set() and self.plan.digest == self.approval.plan_digest

    def consume_launch(self, plan):
        with self._lock:
            if self._launched or not self.is_live() or plan is not self.plan:
                raise ProbeError('production_launch_not_authorized')
            self._launched = True

    def consume_round(self, sample_id):
        _identifier(sample_id)
        with self._lock:
            if (not self._launched or not self.is_live() or self._inflight is not None
                    or sample_id in self._samples):
                raise ProbeError('production_request_not_authorized')
            self._samples.add(sample_id)
            self._inflight = sample_id
            return len(self._samples)

    def finish_round(self, sample_id):
        with self._lock:
            if self._inflight == sample_id:
                self._inflight = None

    def close(self):
        self._closed = True
        self.cancelled.set()


def _overlapping_paths(left, right):
    a, b = (ntpath.normcase(ntpath.normpath(str(Path(value).resolve()))) for value in (left, right))
    try:
        return ntpath.commonpath((a, b)) in (a, b)
    except ValueError:
        return False


PRODUCTION_METADATA_PROJECTOR = r'''$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new()
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ClaudePathProjection {
  [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CommandLineToArgvW(string command, out int count);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
  public static string DataDirectory(string command) {
    int count; IntPtr pointer=CommandLineToArgvW(command,out count);
    if (pointer==IntPtr.Zero || count<1) throw new Exception("metadata unavailable");
    try {
      string result=""; bool seen=false;
      for(int i=1;i<count;i++) {
        string arg=Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer,i*IntPtr.Size));
        if(arg=="--") break;
        string value=null;
        if(arg.StartsWith("--user-data-dir=",StringComparison.Ordinal)) value=arg.Substring(16);
        else if(arg=="--user-data-dir") {
          if(++i>=count) throw new Exception("metadata unavailable");
          value=Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer,i*IntPtr.Size));
        } else {
          string normalized=arg.TrimStart('-','/').ToLowerInvariant();
          if(normalized=="user-data-dir" || normalized.StartsWith("user-data-dir="))
            throw new Exception("metadata unavailable");
        }
        if(value!=null) {
          if(seen || String.IsNullOrEmpty(value)) throw new Exception("metadata unavailable");
          seen=true; result=value;
        }
      }
      return result;
    } finally { LocalFree(pointer); }
  }
}
'@
function Get-ClaudePathMetadata($item) {
  if (!$item.ExecutablePath -or !$item.CommandLine) { throw 'metadata unavailable' }
  [PSCustomObject]@{executable=$item.ExecutablePath;
    user_data_dir=[ClaudePathProjection]::DataDirectory($item.CommandLine)}
}
'''


def inspect_production_target(target):
    """Read only paths/process metadata; reject ordinary Chrome programs/data."""
    _target_fingerprint(target)
    local = Path(os.environ['LOCALAPPDATA'])
    programs, data = set(), [str(local/'Google'), str(local/'Chromium')]
    for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'), str(local)):
        if base:
            for channel in ('Chrome', 'Chrome Beta', 'Chrome Dev', 'Chrome SxS'):
                executable = Path(base)/'Google'/channel/'Application/chrome.exe'
                if executable.is_file():
                    programs.add(str(executable.resolve()))
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe') as key:
                    path = winreg.QueryValue(key, None)
                    if isinstance(path, str) and Path(path.strip('"')).is_file():
                        programs.add(str(Path(path.strip('"')).resolve()))
            except FileNotFoundError:
                pass
    except OSError:
        raise ProbeError('ordinary_browser_identity_unknown') from None
    settings = local/'ClaudeLaunchCenter/settings.json'
    if settings.exists():
        saved = json.loads(settings.read_text(encoding='utf-8-sig'))
        if isinstance(saved.get('chrome_path'), str) and Path(saved['chrome_path']).is_file():
            programs.add(str(Path(saved['chrome_path']).resolve()))
        if isinstance(saved.get('user_data_dir'), str) and ntpath.isabs(saved['user_data_dir']):
            data.append(saved['user_data_dir'])
    script = PRODUCTION_METADATA_PROJECTOR + r'''
    $rows=@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | ForEach-Object {
      Get-ClaudePathMetadata $_
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress'''
    shell = str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
    completed = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, check=True, timeout=12, creationflags=subprocess.CREATE_NO_WINDOW)
    rows = json.loads(completed.stdout.decode('utf-8-sig'))
    if not isinstance(rows, list):
        raise ProbeError('ordinary_browser_identity_unknown')
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'executable','user_data_dir'}
                or not isinstance(row['executable'], str) or not ntpath.isabs(row['executable'])
                or not isinstance(row['user_data_dir'], str)
                or (row['user_data_dir'] and not ntpath.isabs(row['user_data_dir']))):
            raise ProbeError('ordinary_browser_identity_unknown')
        if _overlapping_paths(row['executable'], target.executable):
            raise ProbeError('selected_browser_already_running')
        programs.add(row['executable'])
        if row['user_data_dir']:
            data.append(row['user_data_dir'])
    if (not programs or any(_overlapping_paths(target.executable, value) for value in programs)
            or any(_overlapping_paths(target.user_data_dir, value) for value in data)):
        raise ProbeError('shared_browser_or_data_directory')
    return tuple(sorted(programs))


def prepare_production_launch(target, relay_port, policy_digest, profile_directory, *, request_seconds=10,
                              evidence_seconds=30):
    if (type(relay_port) is not int or not 0 < relay_port <= 65535
            or not isinstance(profile_directory, str) or not profile_directory
            or profile_directory in ('.', '..') or any(c in profile_directory for c in '\\/:\x00')
            or type(request_seconds) not in (int, float) or not 0 < request_seconds <= 10
            or type(evidence_seconds) not in (int, float) or not request_seconds < evidence_seconds <= 30):
        raise ProbeError('production_plan_invalid')
    fingerprint = _target_fingerprint(target)
    version = _file_version(target.executable)
    if version != REVIEWED_VERSION:
        raise ProbeError('version_not_reviewed')
    sha = hashlib.sha256(Path(target.executable).read_bytes()).hexdigest()
    if _target_fingerprint(target) != fingerprint:
        raise ProbeError('target_changed')
    arguments = (target.executable, '--user-data-dir='+target.user_data_dir,
        '--profile-directory='+profile_directory, '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-component-update', '--disable-quic',
        '--remote-debugging-pipe', '--proxy-server=http://127.0.0.1:'+str(relay_port), 'about:blank')
    launch = LaunchPlan(target, relay_port, version, sha, fingerprint, arguments, TARGET,
                         _plan_digest(target, relay_port, version, sha, fingerprint, arguments))
    return ProductionProbePlan(launch, policy_digest, profile_directory, request_seconds, evidence_seconds)


class ProductionProbe(_ProtectedProbe):
    def __init__(self, plan, process, transport, grant, reader, gate):
        from collections import deque
        super().__init__(plan, process, transport, grant, reader, gate)
        self._exit_receipts = deque(maxlen=64)
        self._first_config = None
        self.route_provider = None
        self._channel.cancelled = transport.cancelled = grant.cancelled

    def __call__(self, config, binding, sample_id):
        try:
            self._channel._events = 0
            result = super().__call__(config, binding, sample_id)
            self._first_config = config
            return result
        finally:
            self.grant.finish_round(sample_id)

    def _issue_exit(self, config, binding, sample_id, started, trace, owner):
        from src.core.monitoring import BrowserBindingEvidence
        if not self.grant.is_live() or time.monotonic() >= started+self.protected_plan.round_timeout_seconds:
            raise ProbeError('production_request_expired')
        evidence = BrowserBindingEvidence(binding, sample_id, started, 'pass', trace.request_status,
            'pass', config.proxy_port, owner, trace.observed_ip, source='runtime',
            expires_at=started+self.protected_plan.evidence_ttl_seconds,
            request_profile_status='pass', request_profile_directory=self.protected_plan.profile_directory,
            request_profile_source='selected_profile_context')
        self._exit_receipts.append(evidence)
        return evidence

    def seal_first_exit(self, route):
        result = self._last_result
        if (result is None or not self.accepts_result(result) or self._first_config is None
                or route.sample_id != result.intent.sample_id or route.binding != result.intent.binding
                or route.request_id != result.intent.intent_id or time.monotonic() >= route.expires_at):
            raise ProbeError('initial_route_unconfirmed')
        return self._issue_exit(self._first_config, route.binding, route.sample_id, result.started_at,
                                result.profile_trace.trace, route.proxy_owner)

    def accepts_exit_evidence(self, evidence):
        return (self.grant.is_live() and not self._closed.is_set() and not self._invalidated
                and any(value is evidence for value in self._exit_receipts)
                and evidence.sampled_at <= time.monotonic() < evidence.expires_at)

    def collect_exit(self, config, binding, sample_id):
        started = time.monotonic()
        deadline = started+self.protected_plan.round_timeout_seconds
        with self._lock:
            self.grant.consume_round(sample_id)
            try:
                self._channel._events = 0
                if self.binding() != binding or not callable(self.route_provider):
                    raise ProbeError('production_binding_unconfirmed')
                before = self.route_provider()
                if before is None:
                    raise ProbeError('production_route_unconfirmed')
                @contextmanager
                def ready(context):
                    if not self.grant.is_live() or self.binding() != binding:
                        raise ProbeError('production_request_cancelled')
                    self._check_profile(context)
                    _read_policy(self.protected_plan, self._policy_verifier)
                    yield None
                    if not self.grant.is_live():
                        raise ProbeError('production_request_cancelled')
                trace = collect_profile_trace(self._channel, self.plan.target,
                    self.protected_plan.profile_directory, config.expected_ip, deadline=deadline, on_ready=ready)
                after = self.route_provider()
                _read_policy(self.protected_plan, self._policy_verifier)
                if (after is None or after.proxy_owner != before.proxy_owner or self.binding() != binding
                        or time.monotonic() >= deadline):
                    raise ProbeError('production_route_changed')
                return self._issue_exit(config, binding, sample_id, started, trace.trace, after.proxy_owner)
            finally:
                self.grant.finish_round(sample_id)

    def normal_close(self):
        # Called only after the request worker is quiescent and forwarding is closed.
        try:
            self._channel.cancelled = self._transport.cancelled = None
            self._channel.send('Browser.close', {}, time.monotonic()+2)
        finally:
            self.close()

    def open_selected_url(self, url):
        from .inspection import _valid_url
        with self._lock:
            if (not _valid_url(url) or not self.grant.is_live() or not self._exit_receipts
                    or not self.accepts_exit_evidence(self._exit_receipts[-1])):
                raise ProbeError('production_navigation_not_authorized')
            route = self.route_provider() if callable(self.route_provider) else None
            if route is None or time.monotonic() >= route.expires_at or self._last_result is None:
                raise ProbeError('production_navigation_not_authorized')
            context = self._last_result.profile_trace.context.browser_context_id
            deadline = min(time.monotonic()+self.protected_plan.round_timeout_seconds,
                           route.expires_at, self._exit_receipts[-1].expires_at)
            self._channel._events = 0
            result = self._channel.command('Target.createTarget', {'url':url, 'browserContextId':context}, deadline)
            return _identifier(result.get('targetId'))


def launch_production_probe(plan, *, grant, policy_verifier, proxy_preflight, diagnostic_gate):
    if (type(plan) is not ProductionProbePlan or type(grant) is not ProductionSessionGrant
            or grant.plan is not plan or not grant.is_live() or not callable(proxy_preflight)):
        raise ProbeError('production_authorization_required')
    inspect_production_target(plan.launch.target)
    current = prepare_production_launch(plan.launch.target, plan.launch.proxy_port, plan.policy_digest,
        plan.profile_directory, request_seconds=plan.round_timeout_seconds, evidence_seconds=plan.evidence_ttl_seconds)
    if current != plan or proxy_preflight(plan.launch) is not True:
        raise ProbeError('production_preflight_failed')
    _read_policy(plan, policy_verifier)
    grant.consume_launch(plan)
    def arguments(read, write):
        if not grant.is_live():
            raise ProbeError('production_request_cancelled')
        return [*plan.launch.arguments[:-1], f'--remote-debugging-io-pipes={read},{write}', 'about:blank']
    process, transport = spawn_with_pipe(arguments)
    owned = ProductionProbe(plan, process, transport, grant, policy_verifier, diagnostic_gate)
    try:
        version = owned._channel.command('Browser.getVersion', {}, time.monotonic()+8)
        if (version.get('product') != 'Chrome/'+plan.launch.version
                or type(process) is not subprocess.Popen or type(transport) is not PipeTransport):
            raise ProbeError('production_runtime_unconfirmed')
        _read_policy(plan, policy_verifier)
        owned._runtime_verified = True
        return owned
    except BaseException as error:
        error.owned_probe = owned
        raise
