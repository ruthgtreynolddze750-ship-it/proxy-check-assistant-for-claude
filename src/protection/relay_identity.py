"""Read-only endpoint ownership checks; no listener, browser or rule changes."""
from dataclasses import dataclass
from contextlib import contextmanager
import ctypes
from functools import lru_cache
import math
import ntpath
import os
import re
import socket
import threading
import time

from src.core.backend import _file_sha256


GUARD_STAGES = frozenset(('guard_read', 'bound_before', 'proxy_before', 'routes', 'policy_read',
    'policy_engine_open', 'policy_capabilities', 'policy_identity_before', 'policy_objects_before',
    'policy_objects_after', 'policy_identity_after', 'policy_engine_close', 'relay_policy',
    'bound_after', 'proxy_after', 'lease_issue', 'relay_renew', 'relay_promote'))
_GUARD_SCOPE = threading.local()


@dataclass(frozen=True)
class GuardStageDiagnostic:
    stage: str
    status: str
    elapsed_seconds: float | None


@dataclass(frozen=True)
class GuardSampleDiagnostic:
    outcome: str
    elapsed_seconds: float | None
    budget_seconds: float
    steps: tuple[GuardStageDiagnostic, ...] = ()
    sample_sequence: int = 0
    scope: str = 'sample'
    incomplete: bool = False
    error_code: str = ''


def _diagnostic_time(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


class _GuardTrace:
    def __init__(self, started, budget, sequence, scope, *, clock=None):
        self._started, self._budget = started, budget
        self._sequence, self._scope = sequence, scope
        self._clock = clock or time.perf_counter
        self._budget_clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._rows = []
        self._incomplete = self._frozen = False
        self._frozen_at = None
        self._frozen_budget_at = None
        self._completed = False

    def begin(self, stage):
        if type(stage) is not str or stage not in GUARD_STAGES:
            self._incomplete = True
            return None
        if not self._lock.acquire(blocking=False):
            self._incomplete = True
            return None
        try:
            if self._frozen:
                return None
            now = self._clock()
            if len(self._rows) >= 24 or not _diagnostic_time(now):
                self._incomplete = True
                return None
            self._rows.append((stage, 'running', now, None))
            return len(self._rows)-1
        finally:
            self._lock.release()

    def end(self, token, status):
        if type(token) is not int or status not in ('returned', 'raised'):
            return
        if not self._lock.acquire(blocking=False):
            self._incomplete = True
            return
        try:
            if self._frozen or not 0 <= token < len(self._rows):
                return
            stage, _, started, _ = self._rows[token]
            now = self._clock()
            elapsed = now-started if _diagnostic_time(now) and now >= started else None
            self._incomplete |= elapsed is None
            self._rows[token] = (stage, status, started, elapsed)
        finally:
            self._lock.release()

    def snapshot(self, outcome, *, error_code='', freeze=False):
        now = self._clock()
        budget_now = self._budget_clock()
        if freeze and not self._frozen:
            self._frozen, self._frozen_at = True, now
            self._frozen_budget_at = budget_now
        at = self._frozen_at if self._frozen else now
        budget_at = self._frozen_budget_at if self._frozen else budget_now
        # Stage precision never replaces the existing runtime deadline clock.
        elapsed = (budget_at-self._started if _diagnostic_time(budget_at) and _diagnostic_time(self._started)
                   and budget_at >= self._started else None)
        if outcome not in ('accepted', 'timeout', 'exception', 'cancelled', 'unavailable'):
            outcome = 'unavailable'
        if error_code not in ('', 'timeout', 'cancelled_or_deadline', 'http_status', 'http_protocol',
                              'encoding', 'process_query', 'os_error', 'invalid_data', 'unexpected_error'):
            error_code = 'unexpected_error'
        rows = ()
        incomplete = self._incomplete or elapsed is None
        if self._lock.acquire(blocking=False):
            try:
                rows = tuple(GuardStageDiagnostic(stage, status,
                    min(3600., duration) if duration is not None else
                    min(3600., at-started) if _diagnostic_time(at) and at >= started else None)
                    for stage, status, started, duration in self._rows)
            finally:
                self._lock.release()
        else:
            incomplete = True
        return GuardSampleDiagnostic(outcome, min(3600., elapsed) if elapsed is not None else None,
            self._budget, rows, self._sequence, self._scope, incomplete, error_code)


def _new_guard_trace(started, budget, sequence, scope):
    try:
        return _GuardTrace(started, budget, sequence, scope)
    except Exception:
        return None


@contextmanager
def _guard_scope(trace):
    previous = getattr(_GUARD_SCOPE, 'current', None)
    _GUARD_SCOPE.current = trace if type(trace) is _GuardTrace else None
    try:
        yield
    finally:
        _GUARD_SCOPE.current = previous


@contextmanager
def _guard_stage(stage):
    trace = getattr(_GUARD_SCOPE, 'current', None)
    token = None
    if trace is not None:
        try:
            token = trace.begin(stage)
        except Exception:
            trace._incomplete = True
    status = 'returned'
    try:
        yield
    except BaseException:
        status = 'raised'
        raise
    finally:
        if trace is not None:
            try:
                trace.end(token, status)
            except Exception:
                trace._incomplete = True


@dataclass(frozen=True, repr=False)
class ClientProof:
    client_endpoint: tuple
    server_endpoint: tuple
    pid: int
    created: int
    executable: str
    root_pid: int
    root_created: int
    sampled_at: float


@dataclass(frozen=True, repr=False)
class ProxyProof:
    owner: tuple
    sampled_at: float
    client_endpoint: tuple | None = None
    server_endpoint: tuple | None = None


class BindingChanged(Exception):
    pass


class _TcpRow(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('state', 'local_addr', 'local_port', 'remote_addr', 'remote_port', 'pid')]


class _TcpTable(ctypes.Structure):
    _fields_ = [('count', ctypes.c_uint32), ('table', _TcpRow * 1)]


class _FileTime(ctypes.Structure):
    _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_uint32)]


@lru_cache(maxsize=1)
def _api():
    if os.name != 'nt':
        raise OSError('Windows ownership unavailable')
    ip = ctypes.WinDLL('iphlpapi.dll', use_last_error=True, winmode=0x800)
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    dword, boolean, handle = ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
    signatures = (
        (ip.GetExtendedTcpTable, [handle, ctypes.POINTER(dword), boolean, dword, ctypes.c_int, dword], dword),
        (kernel.OpenProcess, [dword, boolean, dword], handle),
        (kernel.GetProcessTimes, [handle, *([ctypes.POINTER(_FileTime)] * 4)], boolean),
        (kernel.QueryFullProcessImageNameW, [handle, dword, ctypes.c_wchar_p, ctypes.POINTER(dword)], boolean),
        (kernel.WaitForSingleObject, [handle, dword], dword),
        (kernel.CloseHandle, [handle], boolean),
    )
    for function, arguments, result in signatures:
        function.argtypes, function.restype = arguments, result
    return ip, kernel


def _decode_table(data):
    offset, stride = _TcpTable.table.offset, ctypes.sizeof(_TcpRow)
    if len(data) < offset:
        raise ValueError('invalid TCP table size')
    count = ctypes.c_uint32.from_buffer_copy(data).value
    if offset + count * stride > len(data):
        raise ValueError('invalid TCP table count')
    result = []
    for index in range(count):
        row = _TcpRow.from_buffer_copy(data, offset + index * stride)
        local = (socket.inet_ntoa(row.local_addr.to_bytes(4, 'little')), socket.ntohs(row.local_port & 0xffff))
        remote = (socket.inet_ntoa(row.remote_addr.to_bytes(4, 'little')), socket.ntohs(row.remote_port & 0xffff))
        result.append((row.state, local, remote, row.pid))
    return tuple(result)


def _tcp_rows():
    ip, _ = _api()
    size = ctypes.c_uint32()
    status = ip.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    if status not in (0, 122):
        raise OSError(status, 'TCP ownership unavailable')
    for _ in range(3):
        if not 4 <= size.value <= 4 * 1024 * 1024:
            raise ValueError('TCP table outside size limit')
        buffer = ctypes.create_string_buffer(size.value)
        status = ip.GetExtendedTcpTable(buffer, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if status == 0:
            return _decode_table(buffer.raw[:size.value])
        if status != 122:
            raise OSError(status, 'TCP ownership unavailable')
    raise OSError('TCP table changed repeatedly')


@contextmanager
def _process(pid):
    if type(pid) is not int or not 0 < pid <= 0xffffffff:
        raise ValueError('invalid process identity')
    _, kernel = _api()
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.WaitForSingleObject(handle, 0) != 258:
            raise ValueError('process not running')
        created, exited, system, user = (_FileTime() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(system), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        path = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_uint32(len(path))
        if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Existing CIM bindings use .NET UTC ticks at WMI's microsecond precision.
        ticks = ((created.high << 32) | created.low) + 504911232000000000
        yield {'pid': pid, 'created': str(ticks // 10 * 10), 'path': path.value}
        if kernel.WaitForSingleObject(handle, 0) != 258:
            raise ValueError('process exited during observation')
    finally:
        kernel.CloseHandle(handle)


def _endpoint_pid(rows, local, remote):
    matches = [pid for state, left, right, pid in rows if state == 5 and left == local and right == remote]
    if len(matches) != 1 or matches[0] <= 0:
        raise ValueError('ambiguous connection')
    return matches[0]


def _listener_pid(rows, port):
    matches = [pid for state, local, _, pid in rows
               if state == 2 and local[1] == port and local[0] in ('127.0.0.1', '0.0.0.0')]
    if len(matches) != 1 or matches[0] <= 0:
        raise ValueError('ambiguous listener')
    return matches[0]


def _path(value):
    return ntpath.normcase(ntpath.normpath(value))


def _capture_endpoint(local, remote, root_pid):
    if (os.name != 'nt' or local[0] != '127.0.0.1' or remote[0] != '127.0.0.1'
            or type(root_pid) is not int or root_pid <= 0
            or any(type(port) is not int or not 0 < port <= 65535 for port in (local[1], remote[1]))):
        raise ValueError('unsupported endpoint')
    pid = _endpoint_pid(_tcp_rows(), local, remote)
    with _process(pid) as process, _process(root_pid) as root:
        if _endpoint_pid(_tcp_rows(), local, remote) != pid:
            raise ValueError('connection owner changed')
        row = {**process, 'rootPid': root_pid, 'rootCreated': root['created'], 'rootPath': root['path']}
    return row


_HASH_CACHE = {}
_HASH_CACHE_LOCK = threading.Lock()


def _file_identity(path):
    stat = os.stat(path)
    return stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino, stat.st_dev


def _cached_file_sha256(path):
    # R32: the guard runs several times a second; the manager sample in backend still rehashes every time.
    key = _path(path)
    before = _file_identity(path)
    with _HASH_CACHE_LOCK:
        cached = _HASH_CACHE.get(key)
    if cached is not None and cached[0] == before:
        return cached[1]
    digest = _file_sha256(path)
    if _file_identity(path) != before:
        raise ValueError('manager executable changed while hashing')
    with _HASH_CACHE_LOCK:
        _HASH_CACHE[key] = (before, digest)
    return digest


def _native_proxy_owner(config):
    try:
        if (not isinstance(config.manager_executable, str) or not ntpath.isabs(config.manager_executable)
                or not isinstance(config.manager_sha256, str)
                or not re.fullmatch('[0-9a-fA-F]{64}', config.manager_sha256)
                or any(type(port) is not int or not 0 < port <= 65535
                       for port in (config.manager_port, config.proxy_port))):
            return None
        rows = _tcp_rows()
        pid = _listener_pid(rows, config.proxy_port)
        if _listener_pid(rows, config.manager_port) != pid:
            return None
        with _process(pid) as process:
            path = _path(os.path.realpath(process['path']))
            if (path != _path(os.path.realpath(config.manager_executable))
                    or _cached_file_sha256(config.manager_executable).lower() != config.manager_sha256.lower()):
                return None
            after = _tcp_rows()
            if any(_listener_pid(after, port) != pid for port in (config.manager_port, config.proxy_port)):
                return None
            owner = (config.manager_port, config.proxy_port, pid, process['created'], path, config.manager_sha256.lower())
        return owner
    except (OSError, ValueError, TypeError):
        return None


class WindowsRelayVerifier:
    def listener(self, config):
        sampled = time.monotonic()
        owner = _native_proxy_owner(config)
        return ProxyProof(owner, sampled) if owner is not None else None

    def client(self, binding, accepted):
        sampled = time.monotonic()
        client, server = accepted.getpeername(), accepted.getsockname()
        first = _capture_endpoint(client, server, binding.root_pid)
        second = _capture_endpoint(client, server, binding.root_pid)
        if first != second:
            return None
        if (first['rootPid'] != binding.root_pid or int(first['rootCreated']) != binding.root_created
                or _path(first['rootPath']) != _path(binding.executable)):
            raise BindingChanged('browser binding changed')
        return ClientProof(client, server, first['pid'], int(first['created']), first['path'],
                           first['rootPid'], int(first['rootCreated']), sampled)

    def upstream(self, config, connected):
        sampled = time.monotonic()
        owner = _native_proxy_owner(config)
        if owner is None:
            return None
        client, server = connected.getsockname(), connected.getpeername()
        first = _capture_endpoint(server, client, owner[2])
        second = _capture_endpoint(server, client, owner[2])
        if (first != second or first['pid'] != owner[2] or first['created'] != owner[3]
                or _path(first['path']) != _path(owner[4]) or _native_proxy_owner(config) != owner):
            return None
        return ProxyProof(owner, sampled, client, server)


class WindowsSessionGuard:
    """Fresh metadata and policy receipts for one fixed browser/relay generation."""
    def __init__(self, config, binding, fingerprint, relay, reader, *, budget_seconds=0.5, lease_seconds=2.0,
                 cancelled=None, clock=time.monotonic):
        from collections import deque
        import threading
        self.config, self.binding, self.fingerprint = config, binding, fingerprint
        self.relay, self.reader = relay, reader
        self.budget, self.clock = budget_seconds, clock
        self.lease_seconds = lease_seconds
        self.cancelled = cancelled or threading.Event()
        self._sequence = 0
        self._proofs = deque(maxlen=64)
        self._lock = threading.Lock()

    def read(self):
        from src.browser.session_binding import validate_bound_processes
        from src.core.monitoring import LocalGuardEvidence
        started = self.clock()
        deadline = started + self.budget
        def check_time():
            if self.cancelled.is_set() or self.clock() >= deadline:
                raise ValueError('guard_timeout_or_cancelled')
        check_time()
        with _guard_stage('bound_before'):
            validate_bound_processes(self.binding, self.fingerprint)
        with _guard_stage('proxy_before'):
            owner = _native_proxy_owner(self.config)
        if owner is None:
            raise ValueError('proxy_owner_unconfirmed')
        endpoint = self.relay.endpoint
        if endpoint is None:
            raise ValueError('relay_unavailable')
        selected = {self.binding.root_pid, *(pid for pid, _ in self.binding.network_processes)}
        with _guard_stage('routes'):
            for rows in (_tcp_rows(), _tcp_rows()):
                if any(pid in selected and state not in (1, 2, 12) and remote != endpoint
                       for state, local, remote, pid in rows):
                    raise ValueError('browser_route_changed')
        check_time()
        with _guard_stage('policy_read'):
            native = self.reader.read()
        check_time()
        with _guard_stage('relay_policy'):
            policy = self.relay.read_policy(self.reader, proof=native)
        with _guard_stage('bound_after'):
            validate_bound_processes(self.binding, self.fingerprint)
        with _guard_stage('proxy_after'):
            if _native_proxy_owner(self.config) != owner:
                raise ValueError('proxy_owner_changed')
        check_time()
        completed = self.clock()
        with self._lock:
            self._sequence += 1
            proof = LocalGuardEvidence(self.binding, owner, self._sequence, started, completed,
                                       min(started+self.lease_seconds, policy.expires_at), policy)
            self._proofs.append(proof)
            return proof

    def accepts(self, proof):
        with self._lock:
            return (not self.cancelled.is_set() and any(item is proof for item in self._proofs)
                    and proof.completed_at <= self.clock() < proof.expires_at
                    and not proof.policy.revoked.is_set())

    @property
    def latest(self):
        with self._lock:
            proof = self._proofs[-1] if self._proofs else None
        return proof if proof is not None and self.accepts(proof) else None
