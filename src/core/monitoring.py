"""Continuous independent checks; this module does not enforce network isolation."""
from __future__ import annotations

import math
import ipaddress
import ntpath
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .backend import Check, Config, Detection, detect


@dataclass(frozen=True, repr=False)
class BrowserBinding:
    executable: str
    user_data_dir: str
    profile_directory: str  # User selection, not observed request-profile identity.
    session_id: str
    root_pid: int
    root_created: int
    network_processes: tuple[tuple[int, int], ...]

    def __post_init__(self):
        def identity(pid, created):
            return type(pid) is int and pid > 0 and type(created) is int and created > 0
        if (not all(isinstance(path, str) and ntpath.isabs(path)
                    for path in (self.executable, self.user_data_dir))
                or not isinstance(self.profile_directory, str) or not self.profile_directory
                or self.profile_directory in ('.', '..')
                or any(c in self.profile_directory for c in '\\/:')
                or not isinstance(self.session_id, str) or not self.session_id
                or not identity(self.root_pid, self.root_created)
                or not isinstance(self.network_processes, tuple) or not self.network_processes
                or any(not isinstance(node, tuple) or len(node) != 2 or not identity(*node)
                       for node in self.network_processes)):
            raise ValueError('专用浏览器绑定不完整')
        pids = [node[0] for node in self.network_processes]
        if pids != sorted(set(pids)) or self.root_pid in pids:
            raise ValueError('专用浏览器网络进程身份不完整')

    def __repr__(self):
        return 'BrowserBinding(<redacted>)'


@dataclass(frozen=True, repr=False)
class BrowserBindingEvidence:
    binding: BrowserBinding
    sample_id: str
    sampled_at: float
    identity_status: str = 'unknown'
    request_status: str = 'unknown'
    proxy_status: str = 'unknown'
    proxy_port: int | None = None
    proxy_owner: tuple | None = None
    observed_ip: str | None = None
    target_origin: str = 'https://claude.ai'
    source: str = 'unknown'
    expires_at: float | None = None
    request_profile_status: str = 'unknown'
    request_profile_directory: str | None = None
    request_profile_source: str = 'unknown'

    def __repr__(self):
        return 'BrowserBindingEvidence(<redacted>)'


def binding_from_session(selection, evidence, *, now):
    """Adapt process identity; selected profile, request and proxy remain unproven."""
    from src.browser.inspection import BrowserSelection
    from src.browser.session_binding import SessionEvidence
    try:
        if (not isinstance(selection, BrowserSelection) or not isinstance(evidence, SessionEvidence)
                or evidence.source != 'windows_cim' or not evidence.is_fresh(now) or evidence.root is None
                or ntpath.normcase(ntpath.normpath(selection.chrome_executable)) !=
                   ntpath.normcase(ntpath.normpath(evidence.root.executable))
                or ntpath.normcase(ntpath.normpath(selection.user_data_dir)) !=
                   ntpath.normcase(ntpath.normpath(evidence.root.user_data_dir))
                or any(ntpath.normcase(ntpath.normpath(node.executable)) !=
                       ntpath.normcase(ntpath.normpath(selection.chrome_executable))
                       for node in evidence.network_processes)):
            raise ValueError('identity unavailable')
        return BrowserBinding(selection.chrome_executable, selection.user_data_dir,
                              selection.profile_directory, evidence.binding_id,
                              evidence.root.pid, evidence.root.created,
                              tuple(sorted((node.pid, node.created) for node in evidence.network_processes)))
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValueError('浏览器当前身份未确认') from None


@dataclass(frozen=True)
class MonitorEvent:
    occurred_at: datetime
    reason_code: str
    action_code: str
    sequence: int


@dataclass(frozen=True)
class MonitorSnapshot:
    state: str
    protection: str
    checked_at: datetime | None
    last_success_at: datetime | None
    reason_codes: tuple[str, ...]
    sequence: int
    events: tuple[MonitorEvent, ...]
    message: str
    scope: str = 'independent_proxy'
    browser_status: str = 'unknown'


@dataclass(frozen=True, repr=False)
class RelayLease:
    binding: BrowserBinding
    config: Config
    proxy_owner: tuple
    sequence: int
    accepted_at: float
    expires_at: float
    sample_id: str = ''
    revoked: threading.Event = field(default_factory=threading.Event, compare=False)

    def __repr__(self):
        return 'RelayLease(<redacted>)'


@dataclass(frozen=True, repr=False)
class SamplingTiming:
    sample_id: str
    detector_seconds: float
    provider_seconds: float
    total_seconds: float


class MonitorSession:
    """One bounded, explicitly started detector; alerts never claim a network block."""

    def __init__(self, config: Config, *, interval_seconds=30.0, max_age_seconds=60.0,
                 detector=None, clock=None, browser_binding=None, binding_provider=None, binding_key=None,
                 max_samples=None):
        if not isinstance(config, Config):
            raise ValueError('监测配置无效')
        if max_samples is not None and (type(max_samples) is not int or not 1 <= max_samples <= 3):
            raise ValueError('受控试验采样额度无效')
        for value in (interval_seconds, max_age_seconds):
            try:
                valid = (not isinstance(value, bool) and isinstance(value, (int, float))
                         and math.isfinite(value) and value > 0)
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError('监测周期和有效期必须是有限正数')
        if detector is not None and not callable(detector):
            raise ValueError('检测器不可调用')
        if clock is not None and not callable(clock):
            raise ValueError('时钟不可调用')
        if browser_binding is not None and not isinstance(browser_binding, BrowserBinding):
            raise ValueError('专用浏览器绑定无效')
        if binding_provider is not None and (not callable(binding_provider) or browser_binding is None):
            raise ValueError('浏览器证据提供者或绑定无效')
        if binding_key is not None:
            if (browser_binding is None or type(binding_key) is not tuple or len(binding_key) != 4
                    or not isinstance(binding_key[0], str) or len(binding_key[0]) != 64
                    or any(c not in '0123456789abcdef' for c in binding_key[0])
                    or type(binding_key[1]) is not int or type(binding_key[2]) is not int
                    or binding_key[1:] != (browser_binding.root_pid, browser_binding.root_created,
                                           browser_binding.session_id)):
                raise ValueError('界面绑定与浏览器会话不一致')
        self._binding_key = binding_key
        self._browser_binding = browser_binding
        self._binding_provider = binding_provider
        self._binding_invalidated = False
        self._browser_deadline = None
        self._config = config
        self._interval = float(interval_seconds)
        self._max_age = float(max_age_seconds)
        self._detector = detector if detector is not None else detect
        self._clock = clock if clock is not None else time.monotonic
        self._cv = threading.Condition()
        self._state = 'stopped'
        self._active = False
        self._latched = False
        self._reasons = ()
        self._checked_at = None
        self._last_success_at = None
        self._last_success_tick = None
        self._last_tick = None
        self._next_check = None
        self._owner = None
        self._generation = 0
        self._sequence = 0
        self._events = deque(maxlen=128)
        self._coordinator = None
        self._worker = None
        self._relay_leases = deque()
        self._lease_sequence = 0
        self._sample_limit = max_samples
        self._sample_attempts = 0
        self._last_timing = None
        self._relay_revocation = threading.Event()
        self._relay_revocation.set()

    @property
    def binding_key(self):
        return self._binding_key

    @property
    def relay_interval_seconds(self):
        return self._interval

    @property
    def relay_sample_limit(self):
        return self._sample_limit

    @property
    def relay_binding(self):
        return self._browser_binding

    @property
    def relay_config(self):
        return self._config

    @property
    def relay_revocation(self):
        return self._relay_revocation

    def last_sample_timing(self):
        with self._cv:
            return self._last_timing

    def _budget_exhausted(self):
        return self._sample_limit is not None and self._sample_attempts >= self._sample_limit

    def relay_lease(self):
        with self._cv:
            self.snapshot()
            if self._active and not self._latched and self._state == 'monitoring' and self._relay_leases:
                return self._relay_leases[-1]
            return None

    def accepts_relay_lease(self, lease):
        with self._cv:
            self.snapshot()
            return (isinstance(lease, RelayLease) and any(item is lease for item in self._relay_leases)
                    and self._active and not self._latched and self._state == 'monitoring'
                    and not lease.revoked.is_set() and self._last_tick < lease.expires_at)

    def _revoke_relay_leases_locked(self):
        self._relay_revocation.set()
        for lease in self._relay_leases:
            lease.revoked.set()
        self._relay_leases.clear()

    @staticmethod
    def _wall_time():
        return datetime.now(timezone.utc)

    def _tick_locked(self):
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('时钟不可用')
        value = float(value)
        if self._last_tick is not None and value < self._last_tick:
            raise ValueError('时钟倒退')
        self._last_tick = value
        return value

    def _event_locked(self, reason, action):
        self._sequence += 1
        self._events.append(MonitorEvent(self._wall_time(), reason, action, self._sequence))

    def _alarm_locked(self, reason):
        self._revoke_relay_leases_locked()
        if reason == 'browser_binding_changed':
            self._binding_invalidated = True
        if self._state == 'alarm' and self._reasons == (reason,):
            return
        self._state = 'alarm'
        self._latched = True
        self._reasons = (reason,)
        self._event_locked(reason, 'alert_only')
        self._cv.notify_all()

    def _expire_locked(self, now):
        if not self._active or self._latched:
            return
        if self._browser_deadline is not None and now >= self._browser_deadline:
            self._alarm_locked('browser_evidence_expired')
        elif self._last_success_tick is not None and now - self._last_success_tick >= self._max_age:
            self._alarm_locked('evidence_expired')
        elif self._worker is not None and now - self._worker[2] >= self._max_age:
            self._alarm_locked('check_timeout')

    def _ensure_coordinator_locked(self):
        if self._browser_binding is not None and self._binding_provider is None:
            self._alarm_locked('browser_provider_missing')
            return
        if self._coordinator is None:
            self._coordinator = threading.Thread(target=self._run, name='claude-monitor', daemon=True)
            try:
                self._coordinator.start()
            except Exception:
                self._coordinator = None
                self._alarm_locked('detector_error')
        self._cv.notify_all()

    def start(self):
        with self._cv:
            if self._active:
                return self._snapshot_locked()
            if self._budget_exhausted():
                self._alarm_locked('sample_budget_exhausted')
                return self._snapshot_locked()
            if self._latched:
                self._state = 'alarm'
                return self._snapshot_locked()
            self._active = True
            self._relay_revocation = threading.Event()
            self._generation += 1
            self._state = 'checking'
            self._reasons = ()
            self._last_success_tick = None
            self._browser_deadline = None
            self._next_check = None
            self._event_locked('started', 'monitor_only')
            if self._worker is not None:
                self._alarm_locked('previous_check_running')
            else:
                self._ensure_coordinator_locked()
            return self._snapshot_locked()

    def stop(self):
        with self._cv:
            self._revoke_relay_leases_locked()
            if self._state == 'stopped' and not self._active:
                return self._snapshot_locked()
            self._active = False
            self._generation += 1
            self._state = 'stopped'
            self._event_locked('stopped', 'monitor_only')
            self._cv.notify_all()
            return self._snapshot_locked()

    def resume(self):
        with self._cv:
            if self._binding_invalidated:
                self._alarm_locked('browser_binding_changed')
                return self._snapshot_locked()
            if not self._latched:
                return self._snapshot_locked()
            if self._budget_exhausted():
                self._alarm_locked('sample_budget_exhausted')
                return self._snapshot_locked()
            if self._worker is not None:
                self._alarm_locked('previous_check_running')
                return self._snapshot_locked()
            self._generation += 1
            self._active = True
            self._relay_revocation = threading.Event()
            self._latched = False
            self._state = 'checking'
            self._reasons = ()
            self._last_success_tick = None
            self._browser_deadline = None
            self._next_check = None
            self._owner = None
            self._event_locked('manual_resume', 'monitor_only')
            self._ensure_coordinator_locked()
            return self._snapshot_locked()

    def invalidate_binding(self):
        with self._cv:
            if self._browser_binding is None:
                raise ValueError('独立检测会话没有浏览器绑定')
            self._binding_invalidated = True
            self._active = False
            self._generation += 1
            self._alarm_locked('browser_binding_changed')
            return self._snapshot_locked()

    def snapshot(self):
        with self._cv:
            if self._active and not self._latched:
                try:
                    self._expire_locked(self._tick_locked())
                except Exception:
                    self._alarm_locked('clock_unavailable')
            return self._snapshot_locked()

    def _snapshot_locked(self):
        message = ('发现异常，阻断未启用' if self._state == 'alarm' else
                   '独立检测通过，阻断未启用；桌面及网页实际出口未确认' if self._state == 'monitoring' else
                   '正在独立检测，阻断未启用' if self._state == 'checking' else '监测已停止，阻断未启用')
        scope = 'dedicated_browser' if self._browser_binding is not None else 'independent_proxy'
        browser_status = 'pass' if scope == 'dedicated_browser' and self._state == 'monitoring' else 'unknown'
        if browser_status == 'pass':
            message = '专用浏览器本次身份、请求及代理绑定通过，阻断未启用；不证明全部连接'
        return MonitorSnapshot(self._state, 'not_enabled', self._checked_at, self._last_success_at,
                               self._reasons, self._sequence, tuple(self._events), message, scope, browser_status)

    def _browser_reason(self, evidence, sample_id, started, now, owner):
        if not isinstance(evidence, BrowserBindingEvidence):
            return 'browser_evidence_invalid'
        if evidence.binding != self._browser_binding:
            return 'browser_binding_changed'
        if evidence.sample_id != sample_id:
            return 'browser_sample_mismatch'
        sampled = evidence.sampled_at
        if type(sampled) not in (int, float) or not math.isfinite(sampled) or sampled > now:
            return 'browser_evidence_invalid'
        if sampled < started or now - sampled >= self._max_age:
            return 'browser_evidence_expired'
        deadline = evidence.expires_at
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= sampled:
            return 'browser_evidence_invalid'
        if now >= deadline:
            return 'browser_evidence_expired'
        statuses = (evidence.identity_status, evidence.request_status, evidence.proxy_status)
        if any(status not in ('pass', 'fail', 'unknown') for status in statuses):
            return 'browser_evidence_invalid'
        if evidence.source != 'runtime' or 'unknown' in statuses:
            return 'browser_evidence_unconfirmed'
        for status, reason in zip(statuses, ('browser_identity_unconfirmed',
                                            'browser_request_unconfirmed', 'browser_proxy_mismatch')):
            if status != 'pass':
                return reason
        if evidence.target_origin != 'https://claude.ai':
            return 'browser_request_unconfirmed'
        if evidence.request_profile_status not in ('pass', 'fail', 'unknown'):
            return 'browser_evidence_invalid'
        if evidence.request_profile_status == 'fail':
            return 'browser_profile_mismatch'
        if (evidence.request_profile_status != 'pass'
                or evidence.request_profile_source != 'selected_profile_context'
                or not isinstance(evidence.request_profile_directory, str)
                or not evidence.request_profile_directory):
            return 'browser_profile_unconfirmed'
        if evidence.request_profile_directory != self._browser_binding.profile_directory:
            return 'browser_profile_mismatch'
        if (type(evidence.proxy_port) is not int or evidence.proxy_port != self._config.proxy_port
                or not isinstance(evidence.proxy_owner, tuple) or evidence.proxy_owner != owner):
            return 'browser_proxy_mismatch'
        try:
            if (not isinstance(evidence.observed_ip, str)
                    or ipaddress.ip_address(evidence.observed_ip) != ipaddress.ip_address(self._config.expected_ip)):
                return 'browser_exit_mismatch'
        except ValueError:
            return 'browser_exit_mismatch'
        return None

    def _run(self):
        with self._cv:
            while self._active and not self._latched:
                try:
                    now = self._tick_locked()
                except Exception:
                    self._alarm_locked('clock_unavailable')
                    break
                self._expire_locked(now)
                if self._latched:
                    break
                if (not self._budget_exhausted() and self._worker is None
                        and (self._next_check is None or now >= self._next_check)):
                    generation = self._generation
                    worker = threading.Thread(target=self._perform, args=(generation,), name='claude-monitor-check', daemon=True)
                    self._worker = (worker, generation, now)
                    self._sample_attempts += 1
                    try:
                        worker.start()
                    except Exception:
                        self._worker = None
                        self._alarm_locked('detector_error')
                        break
                self._cv.wait(min(0.1, self._max_age / 4))
            self._coordinator = None

    def _perform(self, generation):
        measured_start = time.monotonic()
        provider_seconds = 0.0
        evidence = None
        browser_error = False
        sample_id = uuid.uuid4().hex
        try:
            result = self._detector(self._config)
            if not isinstance(result, Detection):
                raise ValueError('invalid detector result')
            checks = (result.manager, result.port, result.exit_ip, result.claude,
                      result.target_trace, result.mapping, result.desktop_egress)
            if any(not isinstance(check, Check) or check.status not in ('pass', 'fail', 'unknown') for check in checks):
                raise ValueError('invalid detector check')
            if result._owner_evidence is not None and not isinstance(result._owner_evidence, tuple):
                raise ValueError('invalid owner evidence')
            error = False
        except BaseException:
            result = None
            error = True
        detector_seconds = time.monotonic() - measured_start
        if not error and result.ready is True and self._browser_binding is not None:
            with self._cv:
                current = (generation == self._generation and self._active and not self._latched
                           and (self._owner is None or self._owner == result._owner_evidence))
                if current:
                    try:
                        self._expire_locked(self._tick_locked())
                    except Exception:
                        self._alarm_locked('clock_unavailable')
                    current = not self._latched
            if current:
                provider_started = time.monotonic()
                try:
                    evidence = self._binding_provider(self._config, self._browser_binding, sample_id)
                except BaseException:
                    browser_error = True
                finally:
                    provider_seconds = time.monotonic() - provider_started
        with self._cv:
            if generation == self._generation:
                self._last_timing = SamplingTiming(sample_id, detector_seconds, provider_seconds,
                                                   time.monotonic() - measured_start)
            started = None
            if self._worker is not None and self._worker[1] == generation:
                started = self._worker[2]
                self._worker = None
            if generation != self._generation or not self._active or self._latched:
                self._cv.notify_all()
                return
            try:
                now = self._tick_locked()
            except Exception:
                self._alarm_locked('clock_unavailable')
                return
            self._expire_locked(now)
            if self._latched:
                return
            if started is None or now - started >= self._max_age:
                self._alarm_locked('check_timeout')
                return
            self._checked_at = self._wall_time()
            if error:
                self._alarm_locked('detector_error')
                return
            if result._owner_evidence is None:
                self._alarm_locked('owner_unconfirmed')
                return
            if self._owner is not None and result._owner_evidence != self._owner:
                self._alarm_locked('owner_changed')
                return
            for check, code in ((result.port, 'proxy_unavailable'), (result.manager, 'manager_unavailable'),
                                (result.exit_ip, 'exit_ip_mismatch'), (result.target_trace, 'target_exit_mismatch'),
                                (result.mapping, 'mapping_unconfirmed')):
                if check.status != 'pass':
                    self._alarm_locked(code if check.status == 'fail' else 'evidence_unconfirmed')
                    return
            if result.ready is not True:
                self._alarm_locked('evidence_unconfirmed')
                return
            if self._browser_binding is not None:
                try:
                    reason = ('browser_provider_error' if browser_error else
                              self._browser_reason(evidence, sample_id, started, now, result._owner_evidence))
                except Exception:
                    reason = 'browser_evidence_invalid'
                if reason:
                    self._alarm_locked(reason)
                    return
                self._browser_deadline = evidence.expires_at
            self._owner = result._owner_evidence
            self._last_success_at = self._checked_at
            # The result contains no per-check timestamps; age starts at the earliest possible collection time.
            self._last_success_tick = started
            self._next_check = now + self._interval
            if self._state != 'monitoring':
                self._state = 'monitoring'
                self._reasons = ()
                self._event_locked('browser_check_pass' if self._browser_binding is not None else 'check_pass', 'monitor_only')
            else:
                self._sequence += 1
            if self._browser_binding is not None:
                while self._relay_leases and (self._relay_leases[0].expires_at <= now or len(self._relay_leases) >= 64):
                    self._relay_leases.popleft().revoked.set()
                self._lease_sequence += 1
                self._relay_leases.append(RelayLease(
                    self._browser_binding, self._config, self._owner, self._lease_sequence,
                    now, min(self._browser_deadline, started + self._max_age), sample_id=sample_id))
            self._cv.notify_all()


@dataclass(frozen=True, repr=False)
class LocalGuardEvidence:
    binding: BrowserBinding
    proxy_owner: tuple
    sequence: int
    started_at: float
    completed_at: float
    expires_at: float
    policy: object = field(repr=False)


@dataclass(frozen=True, repr=False)
class ForwardLeaseV2(RelayLease):
    manager_sequence: int = 0
    exit_sequence: int = 0
    guard_sequence: int = 0


class LayeredMonitorSession(MonitorSession):
    """Production issuer: new guard leases cannot renew stored exit observations."""
    def __init__(self, config, *, browser_binding, binding_key, exit_validator, guard_validator,
                 clock=None, manager_max_age=60.0, exit_max_age=30.0, lease_seconds=2.0):
        if (not callable(exit_validator) or not callable(guard_validator)
                or not 0 < manager_max_age <= 60 or not 0 < exit_max_age <= 30
                or not 0 < lease_seconds <= 2):
            raise ValueError('生产证据签发参数无效')
        super().__init__(config, browser_binding=browser_binding, binding_key=binding_key,
                         interval_seconds=0.25, max_age_seconds=manager_max_age, clock=clock)
        self._exit_validator, self._guard_validator = exit_validator, guard_validator
        self._exit_max_age, self._lease_seconds = exit_max_age, lease_seconds
        self._manager_expiry = self._exit = self._guard = None
        self._manager_sequence = self._exit_sequence = self._guard_sequence = 0
        self._exit_ids = set()
        self._manager_completed = None
        self._manager_receipts = deque(maxlen=64)
        self._started_once = False

    def start(self):
        with self._cv:
            if not self._started_once:
                self._started_once = self._active = True
                self._relay_revocation = threading.Event()
                self._generation += 1
                self._state = 'checking'
                self._event_locked('started', 'monitor_only')
            return self._snapshot_locked()

    def resume(self):
        # The runtime must create a new generation after explicit cleanup/restart.
        return self.snapshot()

    def _expire_locked(self, now):
        if not self._active or self._latched:
            return
        for deadline, reason in (
            (self._manager_expiry, 'evidence_expired'),
            (None if self._exit is None else self._exit.expires_at, 'browser_evidence_expired'),
            (None if self._guard is None else self._guard.expires_at, 'guard_expired'),
        ):
            if deadline is not None and now >= deadline:
                self._alarm_locked(reason)
                return
        if self._guard is not None and self._guard.policy.revoked.is_set():
            self._alarm_locked('policy_revoked')

    def fail(self, reason):
        with self._cv:
            if self._active:
                self._alarm_locked(reason)
            return self._snapshot_locked()

    def _ready_to_accept(self):
        now = self._tick_locked()
        self._expire_locked(now)
        return now if self._active and not self._latched else None

    def accept_manager_sample(self, result, *, started_at, completed_at):
        with self._cv:
            now = self._ready_to_accept()
            if now is None:
                return False
            valid = (isinstance(result, Detection) and result.ready is True
                     and isinstance(result._owner_evidence, tuple)
                     and all(type(v) in (int, float) and math.isfinite(v)
                             for v in (started_at, completed_at))
                     and 0 <= started_at <= completed_at <= now < started_at + self._max_age
                     and not any(value is result for value in self._manager_receipts)
                     and (self._manager_completed is None or started_at >= self._manager_completed)
                     and (self._owner is None or self._owner == result._owner_evidence))
            if not valid:
                self._alarm_locked('manager_sample_invalid')
                return False
            self._owner = result._owner_evidence
            self._manager_expiry = started_at + self._max_age
            self._manager_completed = completed_at
            self._manager_receipts.append(result)
            self._manager_sequence += 1
            return True

    def accept_exit_sample(self, evidence):
        try:
            valid = self._exit_validator(evidence) is True
        except Exception:
            valid = False
        with self._cv:
            now = self._ready_to_accept()
            if now is None:
                return False
            try:
                valid = (valid and isinstance(evidence, BrowserBindingEvidence)
                    and self._owner is not None and evidence.sample_id not in self._exit_ids
                    and 0 < evidence.expires_at - evidence.sampled_at <= self._exit_max_age
                    and self._browser_reason(evidence, evidence.sample_id, evidence.sampled_at,
                                             now, self._owner) is None)
            except (TypeError, ValueError, AttributeError):
                valid = False
            if not valid:
                self._alarm_locked('browser_evidence_invalid')
                return False
            self._exit = evidence
            self._exit_ids.add(evidence.sample_id)
            self._exit_sequence += 1
            self._checked_at = self._last_success_at = self._wall_time()
            self._sequence += 1
            return True

    def issue_forward_lease(self, guard):
        try:
            valid = self._guard_validator(guard) is True
        except Exception:
            valid = False
        with self._cv:
            now = self._ready_to_accept()
            if now is None:
                return None
            try:
                valid = (valid and isinstance(guard, LocalGuardEvidence)
                    and self._exit is not None and self._manager_expiry is not None
                    and guard.binding == self._browser_binding and guard.proxy_owner == self._owner
                    and type(guard.sequence) is int and guard.sequence > 0
                    and all(type(v) in (int, float) and math.isfinite(v) for v in
                            (guard.started_at, guard.completed_at, guard.expires_at))
                    and 0 <= guard.started_at <= guard.completed_at <= now < guard.expires_at
                    and guard.expires_at <= guard.started_at + self._lease_seconds
                    and not guard.policy.revoked.is_set() and now < guard.policy.expires_at)
            except (TypeError, ValueError, AttributeError):
                valid = False
            if not valid:
                self._alarm_locked('guard_unconfirmed')
                return None
            if guard.sequence <= self._guard_sequence:
                return None
            self._guard, self._guard_sequence = guard, guard.sequence
            self._lease_sequence += 1
            lease = ForwardLeaseV2(self._browser_binding, self._config, self._owner,
                self._lease_sequence, now, min(now+self._lease_seconds, self._manager_expiry,
                    self._exit.expires_at, guard.expires_at, guard.policy.expires_at),
                self._exit.sample_id, manager_sequence=self._manager_sequence,
                exit_sequence=self._exit_sequence, guard_sequence=guard.sequence)
            while self._relay_leases and (self._relay_leases[0].expires_at <= now or len(self._relay_leases) >= 64):
                self._relay_leases.popleft().revoked.set()
            self._relay_leases.append(lease)
            if self._state != 'monitoring':
                self._state = 'monitoring'
                self._event_locked('browser_check_pass', 'monitor_only')
            return lease

    def accepts_relay_lease(self, lease):
        return type(lease) is ForwardLeaseV2 and super().accepts_relay_lease(lease)

    @property
    def production_evidence(self):
        with self._cv:
            return dict(browser_evidence=self._exit, manager_sequence=self._manager_sequence,
                exit_sequence=self._exit_sequence, guard_sequence=self._guard_sequence,
                manager_expires_at=self._manager_expiry,
                exit_expires_at=None if self._exit is None else self._exit.expires_at,
                guard_expires_at=None if self._guard is None else self._guard.expires_at)
