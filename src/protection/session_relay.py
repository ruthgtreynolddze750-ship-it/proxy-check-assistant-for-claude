"""Explicitly bound, leased TCP relay. Not WFP protection or a production entry."""
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import math
import ntpath
import select
import socket
import threading
import time
import uuid

from src.core.backend import Config
from src.core.monitoring import BrowserBinding, MonitorSession, RelayLease, ForwardLeaseV2, LayeredMonitorSession
from .relay_identity import BindingChanged, ClientProof, ProxyProof, WindowsRelayVerifier


TRACE_URL = 'https://claude.ai/cdn-cgi/trace'
_CONNECT = b'CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\nProxy-Connection: keep-alive\r\n\r\n'


@dataclass(frozen=True, repr=False)
class RelayReservation:
    reservation_id: str
    endpoint: tuple


@dataclass(frozen=True, repr=False)
class TraceRequestGuard:
    binding: BrowserBinding
    reservation_id: str
    request_id: str
    sample_id: str
    profile_context_id: str
    issued_at: float
    expires_at: float
    source: str = 'unknown'
    target_url: str = TRACE_URL
    revoked: threading.Event = field(default_factory=threading.Event, compare=False)


@dataclass(frozen=True, repr=False)
class DiagnosticAuthorization:
    reservation_id: str
    plan_digest: str
    binding: BrowserBinding
    request_id: str
    sample_id: str
    approval_id: str
    issued_at: float
    expires_at: float
    max_bytes: int


@dataclass(frozen=True, repr=False)
class RelayPolicyReadback:
    reservation_id: str
    plan_digest: str
    executable: str
    user_data_dir: str
    sampled_at: float
    expires_at: float
    source: str
    revoked: threading.Event = field(default_factory=threading.Event, compare=False)


@dataclass(frozen=True, repr=False)
class DiagnosticRoute:
    reservation_id: str
    plan_digest: str
    binding: BrowserBinding
    request_id: str
    sample_id: str
    proxy_owner: tuple
    client_endpoint: tuple
    server_endpoint: tuple
    started_at: float
    completed_at: float
    expires_at: float
    connect_count: int
    upstream_bytes: int
    downstream_bytes: int
    source: str


@dataclass(frozen=True)
class WorkerFailureDiagnostic:
    stage: str
    error_code: str
    incomplete: bool = False


@dataclass(frozen=True)
class RelaySnapshot:
    state: str
    reason_code: str
    active_connections: int
    mode: str
    protection: str = 'not_enabled'
    worker_diagnostic: WorkerFailureDiagnostic | None = None


def _close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


_WORKER_STAGES = frozenset(('unknown', 'client_identity', 'client_setup', 'diagnostic_header',
    'diagnostic_send', 'upstream_listener', 'upstream_socket', 'upstream_setup',
    'upstream_connect', 'upstream_identity', 'pump', 'pump_setup', 'pump_select',
    'client_recv', 'upstream_recv', 'client_send', 'upstream_send',
    'client_half_close', 'upstream_half_close'))


_CLIENT_DROPPED = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


def _worker_error_category(error):
    for kind, label in ((ConnectionResetError, 'connection_reset'),
        (ConnectionAbortedError, 'connection_aborted'),
        (ConnectionRefusedError, 'connection_refused'), (BrokenPipeError, 'broken_pipe'),
        (TimeoutError, 'timeout'), (OSError, 'os_error'),
        ((ValueError, TypeError, KeyError, AttributeError), 'invalid_data')):
        if isinstance(error, kind):
            return label
    return 'other_error'


class SessionRelay:
    def __init__(self, monitor, config, *, verifier=None, max_lease_seconds=2.0, request_authority=None):
        if ((monitor is not None and not isinstance(monitor, MonitorSession)) or not isinstance(config, Config)
                or type(config.proxy_port) is not int or not 0 < config.proxy_port <= 65535
                or type(max_lease_seconds) not in (int, float)
                or not math.isfinite(max_lease_seconds) or not 0 < max_lease_seconds <= 10
                or (monitor is not None and (monitor.relay_config != config
                    or (monitor.relay_sample_limit != 1 and monitor.relay_interval_seconds >= max_lease_seconds)))):
            raise ValueError('转发参数无效')
        self._monitor, self._config = monitor, config
        self._verifier = WindowsRelayVerifier() if verifier is None else verifier
        self._mode = 'runtime_unverified' if verifier is None else 'local_test'
        self._max_lease = max_lease_seconds
        self._binding = None
        self._lease = None
        self._deadline = None
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._listener = None
        self._sockets = set()
        self._clients = set()
        self._state, self._reason = 'unbound', 'not_started'
        self._reservation = None
        self._policies = []
        self._policy_digest = None
        self._request_authority = request_authority
        self._diagnostic = None
        self._route = None
        self._diagnostic_used = False
        self._generation = 0
        self._threads_started = False
        self._worker_diagnostic_local = threading.local()
        self._worker_diagnostic_lock = threading.Lock()
        self._worker_failure = self._worker_failure_token = None
        self._worker_diagnostic_broken = False

    def _begin_worker_diagnostic(self):
        try:
            self._worker_diagnostic_local.token = None
            self._worker_diagnostic_local.stage = 'unknown'
            self._worker_diagnostic_local.token = object()
        except BaseException:
            self._worker_diagnostic_broken = True

    def _mark_worker_stage(self, stage):
        try:
            self._worker_diagnostic_local.stage = stage if stage in _WORKER_STAGES else 'unknown'
        except BaseException:
            self._worker_diagnostic_broken = True

    def _reserve_worker_failure(self, reason):
        # The original close returned early for every losing/old-generation call.
        try:
            if reason == 'worker_error':
                self._worker_failure_token = getattr(self._worker_diagnostic_local, 'token', None)
        except BaseException:
            self._worker_diagnostic_broken = True

    def _publish_worker_failure(self, error):
        if not self._worker_diagnostic_lock.acquire(blocking=False):
            return
        try:
            if self._worker_failure is None:
                stage = getattr(self._worker_diagnostic_local, 'stage', 'unknown')
                incomplete = self._worker_diagnostic_broken or stage not in _WORKER_STAGES
                self._worker_failure = WorkerFailureDiagnostic('unknown' if incomplete else stage,
                    _worker_error_category(error), incomplete)
        finally:
            self._worker_diagnostic_lock.release()

    def _record_worker_failure(self, error):
        try:
            token = getattr(self._worker_diagnostic_local, 'token', None)
            if token is not None and token is self._worker_failure_token:
                self._publish_worker_failure(error)
        except BaseException:
            pass

    def _worker_diagnostic_snapshot(self):
        if self._reason != 'worker_error':
            return None
        # Immutable reference: reporting never waits for the diagnostic writer.
        return self._worker_failure or WorkerFailureDiagnostic('unknown', 'unavailable', True)

    @property
    def endpoint(self):
        with self._lock:
            return self._listener.getsockname() if self._listener is not None else None

    def snapshot(self):
        with self._lock:
            return RelaySnapshot(self._state, self._reason, len(self._clients), self._mode,
                                 worker_diagnostic=self._worker_diagnostic_snapshot())

    def bind(self, binding):
        if not isinstance(binding, BrowserBinding):
            raise ValueError('专用浏览器绑定无效')
        with self._lock:
            if self._binding is not None or self._state not in ('unbound', 'reserved'):
                if binding != self._binding:
                    self._close('binding_changed')
                raise ValueError('转发会话不可重新绑定')
            if self._monitor is not None and self._monitor.relay_binding != binding:
                raise ValueError('监测器与浏览器绑定不一致')
            self._binding = binding
            if self._state == 'unbound':
                self._state = 'bound'

    def attach_monitor(self, monitor):
        if (not isinstance(monitor, MonitorSession) or monitor.relay_config != self._config
                or monitor.relay_binding != self._binding or self._binding is None
                or (monitor.relay_sample_limit != 1 and monitor.relay_interval_seconds >= self._max_lease)):
            raise ValueError('真实监测器、绑定或采样预算不匹配')
        with self._lock:
            if self._monitor is not None or self._state not in ('bound', 'reserved') or self._diagnostic_used:
                raise ValueError('监测器仅可在诊断前绑定一次')
            self._monitor = monitor

    def attach_request_authority(self, authority):
        if not callable(getattr(authority, 'accepts_request', None)):
            raise ValueError('受控请求签发器无效')
        with self._lock:
            if self._request_authority is not None or self._state not in ('unbound', 'bound', 'reserved'):
                raise ValueError('受控请求签发器仅可接入一次')
            self._request_authority = authority

    def reserve(self):
        with self._lock:
            if self._state not in ('unbound', 'bound') or self._listener is not None:
                raise ValueError('端口已经预留或会话已使用')
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                listener.bind(('127.0.0.1', 0))
                listener.settimeout(0.05)
                self._reservation = RelayReservation(uuid.uuid4().hex, listener.getsockname())
                self._listener = listener
                self._state, self._reason = 'reserved', 'port_reserved_no_forwarding'
                return self._reservation
            except BaseException:
                _close_socket(listener)
                raise

    def read_policy(self, plan, *, backend=None, proof=None):
        from .dedicated_wfp import PolicyPlan, PolicyReadbackVerifier
        with self._lock:
            reservation = self._reservation
            if reservation is None or self._state == 'closed' or (backend is not None and self._mode != 'local_test'):
                raise ValueError('策略回读范围无效')
        try:
            if isinstance(plan, PolicyReadbackVerifier):
                if backend is not None:
                    raise ValueError('不能替换策略读取器')
                verifier, policy_plan = plan, plan.plan
            elif isinstance(plan, PolicyPlan):
                if proof is not None:
                    raise ValueError('采纳原始凭据必须提供原签发器')
                policy_plan = plan
                verifier = PolicyReadbackVerifier(plan, backend_factory=(lambda: backend) if backend is not None else None)
            else:
                raise ValueError('策略读取器无效')
            if policy_plan.relay_port != reservation.endpoint[1]:
                raise ValueError('策略端口不匹配')
            # Adopting a browser-issued intent must not read again and revoke its original proof.
            native = verifier.read() if proof is None else proof
            if (verifier.accepts(native) is not True or native.plan_digest != policy_plan.digest
                    or native.relay_port != reservation.endpoint[1]
                    or native.source not in (('native_wfp', 'injected') if self._mode == 'local_test' else ('native_wfp',))
                    or not self._window(native.observed_at, native.expires_at, time.monotonic())):
                raise ValueError('策略读取凭据无效')
            proof = RelayPolicyReadback(reservation.reservation_id, policy_plan.digest, policy_plan.identity.executable,
                                        policy_plan.identity.user_data_dir, native.observed_at, native.expires_at, native.source)
        except BaseException:
            self._close('policy_unconfirmed')
            raise ValueError('策略回读未确认') from None
        with self._lock:
            if self._state == 'closed' or (self._policy_digest is not None and self._policy_digest != proof.plan_digest):
                self._close('policy_changed')
                raise ValueError('策略或会话已改变')
            self._policy_digest = proof.plan_digest
            self._policies.append(proof)
            if self._state == 'diagnostic':
                self._diagnostic['policy'] = proof
            elif self._state == 'listening' and self._diagnostic_used:
                self._active_policy = proof
            if len(self._policies) > 32:
                self._policies.pop(0).revoked.set()
            return proof

    @staticmethod
    def _window(issued, expires, now):
        try:
            return (all(type(value) in (float, int) and math.isfinite(value) for value in (issued, expires))
                    and 0 <= issued <= now < expires <= issued + 30)
        except OverflowError:
            return False

    def _policy_valid(self, policy):
        return (isinstance(policy, RelayPolicyReadback) and any(item is policy for item in self._policies)
                and not policy.revoked.is_set() and 0 <= policy.sampled_at <= time.monotonic() < policy.expires_at
                and policy.reservation_id == self._reservation.reservation_id
                and policy.plan_digest == self._policy_digest
                and ntpath.normcase(policy.executable) == ntpath.normcase(self._binding.executable)
                and ntpath.normcase(policy.user_data_dir) == ntpath.normcase(self._binding.user_data_dir))

    def start_diagnostic(self, authorization, *, policy, binding_evidence, request):
        from src.browser.inspection import BrowserSelection
        from src.core.monitoring import binding_from_session
        with self._lock:
            if (self._state != 'reserved' or self._binding is None or self._diagnostic_used
                    or self._monitor is None
                    or (self._monitor.relay_sample_limit != 1
                        and not (type(self._monitor) is LayeredMonitorSession
                                 and type(self._request_authority) is ProductionBootstrapBridge))
                    or self._monitor.relay_revocation.is_set()):
                raise ValueError('诊断必须使用未消费的绑定与预留端口')
            monitor_revoked = self._monitor.relay_revocation
        now = time.monotonic()
        if (not isinstance(authorization, DiagnosticAuthorization) or not isinstance(request, TraceRequestGuard)
                or not self._policy_valid(policy) or authorization.binding != self._binding
                or request.binding != self._binding or request.reservation_id != self._reservation.reservation_id
                or authorization.reservation_id != request.reservation_id or authorization.plan_digest != policy.plan_digest
                or authorization.request_id != request.request_id or authorization.sample_id != request.sample_id
                or not all(isinstance(value, str) and 0 < len(value) <= 200 for value in
                           (authorization.approval_id, request.request_id, request.sample_id, request.profile_context_id))
                or request.target_url != TRACE_URL or request.revoked.is_set()
                or request.source not in (('owned_selected_profile_executor', 'injected') if self._mode == 'local_test'
                                          else ('owned_selected_profile_executor',))
                or not self._window(authorization.issued_at, authorization.expires_at, now)
                or not self._window(request.issued_at, request.expires_at, now)
                or type(authorization.max_bytes) is not int or not 1024 <= authorization.max_bytes <= 1048576):
            raise ValueError('诊断授权、请求约束或策略证据无效')
        try:
            selection = BrowserSelection(TRACE_URL, self._binding.executable,
                                         self._binding.user_data_dir, self._binding.profile_directory)
            current = binding_from_session(selection, binding_evidence, now=now)
            if current != self._binding or self._request_authority.accepts_request(request) is not True:
                raise ValueError('binding or request unconfirmed')
            upstream = self._verifier.listener(self._config)
            if not isinstance(upstream, ProxyProof) or not self._fresh(upstream.sampled_at) or not isinstance(upstream.owner, tuple):
                raise ValueError('proxy owner unconfirmed')
        except Exception:
            raise ValueError('独立进程、受控请求或上游未确认') from None
        with self._lock:
            now = time.monotonic()
            if (self._state != 'reserved' or self._diagnostic_used or not self._policy_valid(policy)
                    or monitor_revoked.is_set() or self._monitor.relay_revocation is not monitor_revoked
                    or not self._fresh(upstream.sampled_at)
                    or not self._window(authorization.issued_at, authorization.expires_at, now)
                    or not self._window(request.issued_at, request.expires_at, now)
                    or request.revoked.is_set() or not binding_evidence.is_fresh(now)):
                raise ValueError('诊断证据已失效')
            self._diagnostic_used = True
            self._diagnostic = {'authorization': authorization, 'policy': policy, 'request': request,
                                'binding_evidence': binding_evidence, 'proxy_owner': upstream.owner,
                                'monitor_revoked': monitor_revoked,
                                'started_at': now, 'connections': 0, 'up': 0, 'down': 0, 'connected': False,
                                'client': None, 'server': None}
            self._deadline = min(authorization.expires_at, request.expires_at, binding_evidence.expires_at)
            self._generation += 1
            self._state, self._reason = 'diagnostic', 'bounded_trace_only'
            self._listener.listen(16)
        self._start_threads()
        return self.endpoint

    def complete_diagnostic(self, request):
        with self._lock:
            if (self._state != 'diagnostic' or not self._live_locked() or request is not self._diagnostic['request']
                    or not self._diagnostic['connected'] or self._diagnostic['connections'] != 1
                    or self._diagnostic['up'] <= len(_CONNECT)):
                raise ValueError('诊断连接证据不完整')
            data = self._diagnostic
            self._route = DiagnosticRoute(self._reservation.reservation_id, self._policy_digest, self._binding,
                                          request.request_id, request.sample_id, data['proxy_owner'],
                                          data['client'], data['server'], data['started_at'], time.monotonic(),
                                          self._deadline, data['connections'], data['up'], data['down'],
                                          'native_tcp' if self._mode != 'local_test' else 'injected')
            self._state, self._reason = 'sealed', 'diagnostic_complete_no_forwarding'
            self._generation += 1
            sockets = tuple(self._sockets)
            self._sockets.clear()
            self._clients.clear()
        for sock in sockets:
            _close_socket(sock)
        return self._route

    def promote(self, lease, route, *, policy):
        if not self._valid_lease(lease):
            raise ValueError('正式租约尚未签发或已失效')
        with self._lock:
            if (self._state != 'sealed' or route is not self._route or not isinstance(route, DiagnosticRoute)
                    or not self._policy_valid(policy) or not self._lease_live(lease)
                    or time.monotonic() >= route.expires_at or lease.sample_id != route.sample_id
                    or lease.proxy_owner != route.proxy_owner or lease.accepted_at < route.completed_at):
                raise ValueError('正式租约与本次诊断不对应')
            self._lease = lease
            self._active_policy = policy
            self._deadline = min(lease.expires_at, lease.accepted_at + self._max_lease)
            self._generation += 1
            self._state, self._reason = 'listening', 'lease_active'
            return self.endpoint

    def _start_threads(self):
        with self._lock:
            if self._threads_started:
                return
            self._threads_started = True
        threading.Thread(target=self._watch, name='dedicated-relay-watch', daemon=True).start()
        threading.Thread(target=self._accept, name='dedicated-relay-accept', daemon=True).start()

    def _lease_live(self, lease):
        if (not isinstance(lease, RelayLease) or type(lease.sequence) is not int or lease.sequence <= 0
                or lease.binding != self._binding or lease.config != self._config):
            return False
        try:
            if any(type(value) not in (int, float) or not math.isfinite(value)
                   for value in (lease.accepted_at, lease.expires_at)):
                return False
            now = time.monotonic()
            return (0 <= lease.accepted_at <= now < min(lease.expires_at, lease.accepted_at + self._max_lease)
                    and lease.expires_at > lease.accepted_at and not lease.revoked.is_set())
        except (OverflowError, TypeError, AttributeError):
            return False

    def _valid_lease(self, lease):
        # Calls into the issuer must never hold the relay lock used by its watchdog.
        try:
            return (self._lease_live(lease) and self._monitor.accepts_relay_lease(lease)
                    and self._lease_live(lease))
        except Exception:
            return False

    @staticmethod
    def _fresh(sampled):
        return type(sampled) in (float, int) and math.isfinite(sampled) and 0 <= time.monotonic() - sampled <= 3

    def _proxy_proof(self, proof, expected_owner, connected=None):
        if not isinstance(proof, ProxyProof) or proof.owner != expected_owner or not self._fresh(proof.sampled_at):
            return False
        if connected is None:
            return proof.client_endpoint is None and proof.server_endpoint is None
        return (proof.client_endpoint == connected.getsockname() and proof.server_endpoint == connected.getpeername()
                and proof.server_endpoint == ('127.0.0.1', self._config.proxy_port))

    def start(self, lease):
        with self._lock:
            if self._state not in ('bound', 'reserved') or self._binding is None or self._policy_digest is not None:
                raise ValueError('须先显式绑定且不能复用已关闭会话')
        if not self._valid_lease(lease):
            raise ValueError('完整监测租约未确认')
        try:
            proof = self._verifier.listener(self._config)
        except Exception:
            proof = None
        if not self._proxy_proof(proof, lease.proxy_owner) or not self._valid_lease(lease):
            raise ValueError('上游监听归属或租约未确认')
        if self._reservation is None:
            self.reserve()
        listener = self._listener
        try:
            with self._lock:
                if self._state != 'reserved' or not self._lease_live(lease):
                    raise ValueError('转发会话已失效')
                listener.listen(16)
                self._listener, self._lease = listener, lease
                self._deadline = min(lease.expires_at, lease.accepted_at + self._max_lease)
                self._generation += 1
                self._state, self._reason = 'listening', 'lease_active'
            self._start_threads()
            return self.endpoint
        except BaseException:
            _close_socket(listener)
            self._close('start_error')
            raise

    def renew(self, lease):
        if isinstance(lease, ForwardLeaseV2):
            return False
        with self._lock:
            if self._state != 'listening':
                return False
        if not self._valid_lease(lease):
            self._close('lease_invalid')
            return False
        with self._lock:
            if not self._live_locked():
                return False
            if not self._lease_live(lease):
                self._close('lease_invalid')
                return False
            if lease.sequence <= self._lease.sequence:
                return False
            self._lease = lease
            self._deadline = min(lease.expires_at, lease.accepted_at + self._max_lease)
            return True

    def renew_production(self, lease, *, policy):
        if (type(lease) is not ForwardLeaseV2 or not isinstance(self._monitor, LayeredMonitorSession)
                or not self._valid_lease(lease)):
            self._close('lease_invalid')
            return False
        with self._lock:
            if not self._live_locked() or not self._policy_valid(policy) or not self._lease_live(lease):
                self._close('production_evidence_expired')
                return False
            if lease.sequence <= self._lease.sequence:
                return False
            self._lease, self._active_policy = lease, policy
            self._deadline = min(lease.expires_at, lease.accepted_at+self._max_lease, policy.expires_at)
            return True

    def _live_locked(self):
        if self._state == 'diagnostic':
            data = self._diagnostic
            if (data['request'].revoked.is_set() or data['policy'].revoked.is_set()
                    or data['monitor_revoked'].is_set()
                    or not data['binding_evidence'].is_fresh(time.monotonic())):
                self._close('diagnostic_revoked')
                return False
            if time.monotonic() >= data['policy'].expires_at:
                self._close('policy_expired')
                return False
            if time.monotonic() >= self._deadline:
                self._close('diagnostic_expired')
                return False
            return True
        if self._state != 'listening':
            return False
        if self._diagnostic_used and (self._active_policy.revoked.is_set()
                                     or time.monotonic() >= self._active_policy.expires_at):
            self._close('policy_expired')
            return False
        if self._lease.revoked.is_set():
            self._close('lease_revoked')
            return False
        if time.monotonic() >= self._deadline:
            self._close('lease_expired')
            return False
        return True

    def _live(self):
        with self._lock:
            return self._live_locked()

    def _connection_live(self, generation):
        with self._lock:
            return generation == self._generation and self._live_locked()

    def _close_connection_generation(self, reason, generation):
        with self._lock:
            if generation == self._generation:
                self._close(reason)

    def _watch(self):
        try:
            while not self._closed.wait(0.01):
                self._live()
        except BaseException:
            self._close('watchdog_error')

    def _accept(self):
        try:
            while not self._closed.is_set():
                with self._lock:
                    listener = self._listener
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with self._lock:
                    if not self._live_locked() or len(self._clients) >= 16:
                        _close_socket(client)
                        continue
                    self._sockets.add(client)
                    self._clients.add(client)
                    generation = self._generation
                threading.Thread(target=self._connection, args=(client, generation), name='dedicated-relay-stream', daemon=True).start()
        except BaseException:
            if not self._closed.is_set():
                self._close('acceptor_error')

    def _client_proof(self, proof, client):
        if not isinstance(proof, ClientProof) or not self._fresh(proof.sampled_at):
            return False
        binding = self._binding
        if (type(proof.root_pid) is not int or type(proof.root_created) is not int
                or (proof.root_pid, proof.root_created) != (binding.root_pid, binding.root_created)):
            raise BindingChanged('browser binding changed')
        allowed = ((binding.root_pid, binding.root_created), *binding.network_processes)
        return (type(proof.pid) is int and type(proof.created) is int and (proof.pid, proof.created) in allowed
                and isinstance(proof.executable, str)
                and ntpath.normcase(ntpath.normpath(proof.executable)) == ntpath.normcase(ntpath.normpath(binding.executable))
                and proof.client_endpoint == client.getpeername() and proof.server_endpoint == client.getsockname())

    def _connection(self, client, generation):
        self._begin_worker_diagnostic()
        upstream = None
        try:
            self._mark_worker_stage('client_identity')
            proof = self._verifier.client(self._binding, client)
            if not self._connection_live(generation) or not self._client_proof(proof, client):
                return
            with self._lock:
                if not self._connection_live(generation):
                    return
                diagnostic = self._state == 'diagnostic'
                owner = self._diagnostic['proxy_owner'] if diagnostic else self._lease.proxy_owner
            if diagnostic:
                self._mark_worker_stage('client_setup')
                client.setblocking(False)
                try:
                    self._mark_worker_stage('diagnostic_header')
                    header = self._read_header(client, generation)
                except (ConnectionError, TimeoutError):
                    return
                except ValueError as error:
                    if str(error) != '诊断请求头不完整或超限':
                        raise
                    return
                if not self._valid_connect(header):
                    return
                with self._lock:
                    if not self._connection_live(generation) or not self._client_proof(proof, client):
                        return
                    if self._diagnostic['connections'] >= 1:
                        return
                    # Only a valid CONNECT claims the sole upstream slot; it is never refunded.
                    self._diagnostic['connections'] += 1
            self._mark_worker_stage('upstream_listener')
            if not self._proxy_proof(self._verifier.listener(self._config), owner) or not self._connection_live(generation):
                self._close_connection_generation('upstream_unconfirmed', generation)
                return
            self._mark_worker_stage('upstream_socket')
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self._lock:
                if not self._connection_live(generation):
                    return
                self._sockets.add(upstream)
                self._mark_worker_stage('upstream_setup')
                upstream.settimeout(min(0.2, max(0.001, self._deadline - time.monotonic())))
            self._mark_worker_stage('upstream_connect')
            upstream.connect(('127.0.0.1', self._config.proxy_port))
            self._mark_worker_stage('upstream_identity')
            if not self._connection_live(generation) or not self._proxy_proof(self._verifier.upstream(self._config, upstream), owner, upstream):
                self._close_connection_generation('upstream_unconfirmed', generation)
                return
            if diagnostic:
                upstream.setblocking(False)
                self._mark_worker_stage('diagnostic_send')
                self._send_diagnostic(upstream, _CONNECT, generation, 'up')
                self._mark_worker_stage('diagnostic_header')
                response = self._read_header(upstream, generation, direction='down')
                first = response.split(b'\r\n', 1)[0].split(b' ', 2)
                if len(first) < 2 or first[0] not in (b'HTTP/1.0', b'HTTP/1.1') or first[1] != b'200':
                    self._close_connection_generation('diagnostic_connect_failed', generation)
                    return
                self._mark_worker_stage('diagnostic_send')
                self._send_diagnostic(client, b'HTTP/1.1 200 Connection established\r\n\r\n', generation)
                with self._lock:
                    if not self._connection_live(generation):
                        return
                    self._diagnostic['connected'] = True
                    self._diagnostic['client'], self._diagnostic['server'] = proof.client_endpoint, proof.server_endpoint
            self._mark_worker_stage('pump')
            self._pump(client, upstream, generation)
        except BindingChanged:
            self._close_connection_generation('binding_changed', generation)
        except BaseException as error:
            self._close_connection_generation('worker_error', generation)
            self._record_worker_failure(error)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    _close_socket(sock)
            with self._lock:
                self._sockets.discard(client)
                self._sockets.discard(upstream)
                self._clients.discard(client)

    def _budget(self, generation, wanted):
        with self._lock:
            if not self._connection_live(generation):
                return 0
            if self._state != 'diagnostic':
                return wanted
            data = self._diagnostic
            left = data['authorization'].max_bytes - data['up'] - data['down']
            if left <= 0:
                self._close('diagnostic_byte_limit')
                return 0
            return min(wanted, left)

    def _count_bytes(self, generation, direction, count):
        with self._lock:
            if not self._connection_live(generation):
                return False
            if self._state == 'diagnostic':
                self._diagnostic[direction] += count
            return True

    def _read_header(self, sock, generation, direction=None):
        result = bytearray()
        while self._connection_live(generation) and len(result) < 8192:
            if direction is not None and not self._budget(generation, 1):
                break
            readable, _, _ = select.select([sock], [], [], 0.01)
            if not readable:
                continue
            try:
                piece = sock.recv(1)
            except BlockingIOError:
                continue
            if not piece:
                break
            if direction is not None and not self._count_bytes(generation, direction, len(piece)):
                break
            result.extend(piece)
            if result.endswith(b'\r\n\r\n'):
                return bytes(result)
        raise ValueError('诊断请求头不完整或超限')

    @staticmethod
    def _valid_connect(header):
        lines = header[:-4].split(b'\r\n')
        if lines[0] != b'CONNECT claude.ai:443 HTTP/1.1':
            return False
        seen = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b':')
            name, value = name.lower(), value.strip()
            if (not separator or name in seen or name not in (b'host', b'proxy-connection', b'user-agent', b'accept')
                    or any(byte < 32 or byte > 126 for byte in value)):
                return False
            seen[name] = value
        return seen.get(b'host') == b'claude.ai:443'

    def _send_diagnostic(self, sock, data, generation, direction=None):
        offset = 0
        while offset < len(data) and self._connection_live(generation):
            count = self._budget(generation, len(data)-offset) if direction is not None else len(data)-offset
            if count <= 0:
                break
            _, writable, _ = select.select([], [sock], [], 0.01)
            if not writable:
                continue
            try:
                sent = sock.send(data[offset:offset+count])
            except BlockingIOError:
                continue
            if sent <= 0:
                break
            if direction is not None and not self._count_bytes(generation, direction, sent):
                break
            offset += sent
        if offset != len(data):
            raise ValueError('诊断连接已失效')

    def _pump(self, client, upstream, generation):
        # R30: in production, the verified Chrome dropping one of its own streams ends only that stream.
        with self._lock:
            alone = self._state == 'listening'
        sockets = (client, upstream)
        for sock in sockets:
            self._mark_worker_stage('pump_setup')
            sock.setblocking(False)
        pending = {client: bytearray(), upstream: bytearray()}
        reading = set(sockets)
        write_closed = set()
        while self._connection_live(generation):
            for source, destination in ((client, upstream), (upstream, client)):
                if source not in reading and not pending[destination] and destination not in write_closed:
                    self._mark_worker_stage('client_half_close' if destination is client else 'upstream_half_close')
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except _CLIENT_DROPPED:
                        if not alone or destination is not client:
                            raise
                        return
                    write_closed.add(destination)
            if not reading and not any(pending.values()):
                return
            readable = [s for s in reading if len(pending[upstream if s is client else client]) < 65536]
            writable = [s for s in sockets if pending[s]]
            self._mark_worker_stage('pump_select')
            ready_read, ready_write, errors = select.select(readable, writable, sockets, 0.01)
            if errors or not self._connection_live(generation):
                return
            for source in ready_read:
                if not self._connection_live(generation):
                    return
                destination = upstream if source is client else client
                try:
                    allowance = self._budget(generation, 65536 - len(pending[destination]))
                    if not allowance:
                        return
                    self._mark_worker_stage('client_recv' if source is client else 'upstream_recv')
                    data = source.recv(allowance)
                except BlockingIOError:
                    continue
                except _CLIENT_DROPPED:
                    if not alone or source is not client:
                        raise
                    return
                if data:
                    if not self._count_bytes(generation, 'up' if source is client else 'down', len(data)):
                        return
                    pending[destination].extend(data)
                else:
                    reading.remove(source)
            for destination in ready_write:
                if not self._connection_live(generation):
                    return
                try:
                    self._mark_worker_stage('client_send' if destination is client else 'upstream_send')
                    sent = destination.send(pending[destination])
                except BlockingIOError:
                    continue
                except _CLIENT_DROPPED:
                    if not alone or destination is not client:
                        raise
                    return
                if sent <= 0:
                    return
                del pending[destination][:sent]

    def _close(self, reason):
        with self._lock:
            if self._state == 'closed':
                return
            self._state, self._reason = 'closed', reason
            self._generation += 1
            for policy in self._policies:
                policy.revoked.set()
            self._closed.set()
            sockets = tuple(self._sockets)
            listener, self._listener = self._listener, None
            self._sockets.clear()
            self._clients.clear()
        for sock in (*sockets, listener):
            if sock is not None:
                _close_socket(sock)
        self._reserve_worker_failure(reason)

    def stop(self):
        self._close('stopped')


class ProtectedBootstrapBridge:
    """Join the browser's issued intent/result to one relay diagnostic and one monitor sample."""
    def __init__(self, relay, policy_verifier, *, max_bytes=262144):
        from .dedicated_wfp import PolicyReadbackVerifier
        if (not isinstance(relay, SessionRelay) or relay.endpoint is None
                or type(policy_verifier) is not PolicyReadbackVerifier
                or policy_verifier.plan.relay_port != relay.endpoint[1]
                or type(max_bytes) is not int or not 1024 <= max_bytes <= 1048576):
            raise ValueError('首次诊断衔接参数无效')
        self._relay, self._reader, self._max_bytes = relay, policy_verifier, max_bytes
        self._probe = self._running = self._intent = self._guard = None
        self._used = self._gate_finished = False
        self._lock = threading.Lock()
        self._route = self._policy = None
        relay.attach_request_authority(self)

    def attach_probe(self, probe):
        from src.browser.request_probe import _ProtectedProbe
        if (type(probe) is not _ProtectedProbe or probe.protected_plan.policy_digest != self._reader.plan.digest
                or probe.plan.proxy_port != self._relay.endpoint[1]
                or probe._policy_verifier is not self._reader):
            raise ValueError('浏览器签发器与策略会话不一致')
        with self._lock:
            if self._probe is not None or self._used:
                raise ValueError('浏览器签发器仅可绑定一次')
            self._probe = probe

    @property
    def last_route(self):
        return self._route

    @property
    def last_policy(self):
        return self._policy

    def accepts_request(self, request):
        return (request is self._guard and self._intent is not None and not self._gate_finished
                and not request.revoked.is_set() and self._probe is not None
                and self._probe.accepts_intent(self._intent) is True)

    @contextmanager
    def gate(self, intent):
        from src.browser.request_probe import DiagnosticIntent
        if (self._running is None or self._intent is not None or type(intent) is not DiagnosticIntent
                or intent.binding != self._running[1] or intent.sample_id != self._running[2]
                or self._probe.accepts_intent(intent) is not True):
            raise ValueError('诊断意图不是本轮原签发对象')
        self._intent = intent
        policy = self._relay.read_policy(self._reader, proof=intent.policy_readback)
        reservation = self._relay._reservation
        self._guard = TraceRequestGuard(intent.binding, reservation.reservation_id, intent.intent_id,
                                        intent.sample_id, intent.profile_context.browser_context_id,
                                        intent.issued_at, intent.expires_at, source='owned_selected_profile_executor')
        authorization = DiagnosticAuthorization(reservation.reservation_id, policy.plan_digest,
                                                 intent.binding, intent.intent_id, intent.sample_id,
                                                 intent.grant_id, intent.issued_at, intent.expires_at, self._max_bytes)
        try:
            self._relay.start_diagnostic(authorization, policy=policy,
                                          binding_evidence=self._probe.session_evidence, request=self._guard)
            yield
            self._gate_finished = True
        except BaseException:
            self._guard.revoked.set()
            self._relay.stop()
            raise

    def __call__(self, config, binding, sample_id):
        from src.browser.request_probe import DiagnosticResult
        with self._lock:
            if (self._used or self._probe is None or config != self._relay._config
                    or binding != self._relay._binding):
                raise ValueError('首次诊断仅限本会话一次采样')
            self._used = True
            self._running = (config, binding, sample_id)
        try:
            original = self._probe(config, binding, sample_id)
            result = self._probe.last_result
            if (type(result) is not DiagnosticResult or self._probe.accepts_result(result) is not True
                    or result.intent is not self._intent or result.evidence is not original
                    or not self._gate_finished or result.intent.sample_id != sample_id
                    or result.intent.binding != binding):
                raise ValueError('完整请求结果不是本轮原签发对象')
            policy = self._relay.read_policy(self._reader, proof=result.policy_after)
            route = self._relay.complete_diagnostic(self._guard)
            if route.sample_id != sample_id or route.request_id != result.intent.intent_id:
                raise ValueError('请求与转发路由不一致')
            expires = min(original.expires_at, result.expires_at, route.expires_at, policy.expires_at)
            if time.monotonic() >= expires:
                raise ValueError('完整采样证据已到期')
            combined = replace(original, proxy_status='pass', proxy_port=config.proxy_port,
                               proxy_owner=route.proxy_owner, expires_at=expires)
            self._route, self._policy = route, policy
            return combined
        except BaseException:
            self._relay.stop()
            raise
        finally:
            if self._guard is not None:
                self._guard.revoked.set()
            self._running = None

    def close(self):
        if self._guard is not None:
            self._guard.revoked.set()
        self._relay.stop()


class ProductionBootstrapBridge(ProtectedBootstrapBridge):
    def attach_probe(self, probe):
        from src.browser.request_probe import ProductionProbe
        if (type(probe) is not ProductionProbe or probe.protected_plan.policy_digest != self._reader.plan.digest
                or probe.plan.proxy_port != self._relay.endpoint[1]
                or probe._policy_verifier is not self._reader):
            raise ValueError('生产浏览器签发器与策略会话不一致')
        with self._lock:
            if self._probe is not None or self._used:
                raise ValueError('浏览器签发器仅可绑定一次')
            self._probe = probe
