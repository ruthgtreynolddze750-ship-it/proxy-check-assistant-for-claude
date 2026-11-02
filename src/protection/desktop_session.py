"""Protected desktop launch (R33): only the assistant's relay, fuse on any unconfirmed evidence.

Started only by an explicit UI action. A fuse pauses the relay and keeps the rules, so the
desktop loses the network but is never ended (R3). Rules are removed only after every
protected executable has exited.
"""
from dataclasses import dataclass, field, replace
from datetime import datetime
import json
import os
from pathlib import Path
import re
import threading
import time


@dataclass(frozen=True)
class DesktopBudget:
    guard_interval_seconds: float = 0.25
    guard_budget_seconds: float = 0.5
    lease_seconds: float = 2.0
    manager_interval_seconds: float = 5.0
    manager_budget_seconds: float = 25.0
    exit_ttl_seconds: float = 30.0
    exit_check_interval_seconds: float = 5.0
    exit_check_budget_seconds: float = 10.0
    manager_max_age_seconds: float = 60.0
    policy_max_age_seconds: float = 5.0
    exit_wait_poll_seconds: float = 1.0

    def __post_init__(self):
        # Same split as the dedicated Chrome: fast exit checks carry the 30 s evidence, full samples 60 s.
        if (any(type(value) not in (int, float) or not value > 0 for value in vars(self).values())
                or self.lease_seconds > 2 or self.exit_ttl_seconds > 30 or self.policy_max_age_seconds > 5
                or self.manager_max_age_seconds > 60
                or self.guard_interval_seconds + 2*self.guard_budget_seconds >= self.lease_seconds
                or 2*self.exit_check_budget_seconds + self.exit_check_interval_seconds >= self.exit_ttl_seconds
                or 2*self.manager_budget_seconds + self.manager_interval_seconds >= self.manager_max_age_seconds):
            raise ValueError('桌面端保护时限超出批准范围')


@dataclass(frozen=True)
class DesktopView:
    request_id: str = ''
    phase: str = 'idle'     # idle preparing running fused desktop_exited stopping waiting_exit failed blocked abandoned
    reason_code: str = 'not_started'
    cleanup_status: str = 'not_applicable'
    relay_state: str = ''
    relay_reason: str = ''
    relay_port: int | None = None
    active_connections: int = 0
    rejected_connections: int = 0
    guard_sequence: int = 0
    manager_sequence: int = 0
    exit_sequence: int = 0
    guard_expires_at: float | None = None
    exit_expires_at: float | None = None
    protected_processes: int = 0
    other_children: int = 0
    executables: int = 0
    resumable: bool = False
    events: tuple = field(default=(), repr=False)

    @property
    def active(self):
        return self.phase not in ('idle', 'failed')


class _Stage(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


_GUARD_REASONS = frozenset(('desktop_exited', 'unknown_desktop_executable', 'proxy_owner_unconfirmed',
                            'proxy_owner_changed', 'desktop_route_changed', 'guard_timeout'))


class DesktopGuard:
    """One fast check: tree, Proxy Manager owner, routes and rule readback, within the budget."""
    def __init__(self, config, tree, relay_port, verifier, owner, backend, *, budget, lease, clock):
        self.config, self.tree, self.relay_port = config, tree, relay_port
        self.verifier, self.owner, self.backend = verifier, owner, backend
        self.budget, self.lease, self.clock = budget, lease, clock

    def read(self):
        started = self.clock()
        deadline = started + self.budget
        def check_time():
            if self.clock() >= deadline:
                raise ValueError('guard_timeout')
        observation = self.tree.read()
        if observation.unknown_claude:
            raise ValueError('unknown_desktop_executable')
        if self.backend.proxy_owner(self.config) != self.owner:
            raise ValueError('proxy_owner_changed')
        pids = {pid for pid, _ in observation.allowed}
        relay = ('127.0.0.1', self.relay_port)
        for _ in range(2):
            rows = self.backend.tcp_rows()
            listening = {(pid, local[1]) for state, local, _, pid in rows if state == 2}
            for state, local, remote, pid in rows:
                # Accepted inbound connections are not routes; outbound must go to the relay.
                if (pid in pids and state not in (1, 2, 12) and remote != relay
                        and (pid, local[1]) not in listening):
                    raise ValueError('desktop_route_changed')
        check_time()
        policy = self.verifier.read()
        check_time()
        if not self.tree.root_alive():
            raise ValueError('desktop_exited')
        if self.backend.proxy_owner(self.config) != self.owner:
            raise ValueError('proxy_owner_changed')
        completed = self.clock()
        check_time()
        return started, completed, min(started + self.lease, policy.expires_at), observation


def _manager_reason(result):
    if getattr(result, '_owner_evidence', None) is None:
        return 'manager_owner_unconfirmed'
    for name, code in (('exit_ip', 'exit_ip_mismatch'), ('target_trace', 'target_exit_mismatch'),
                       ('manager', 'manager_unavailable'), ('port', 'proxy_unavailable'),
                       ('mapping', 'mapping_unconfirmed')):
        check = getattr(result, name, None)
        if getattr(check, 'status', 'unknown') == 'fail':
            return code
    return 'manager_unconfirmed'


class DesktopProtectionRuntime:
    def __init__(self, *, journal_path=None, budget=None, backend=None, clock=time.monotonic):
        self.budget = budget or DesktopBudget()
        if not isinstance(self.budget, DesktopBudget):
            raise ValueError('桌面端保护时限无效')
        self.journal_path = Path(journal_path) if journal_path is not None else (
            Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'ClaudeLaunchCenter' / 'desktop-recovery.json')
        self._backend_override = backend
        self._backend = None
        self.clock = clock
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._resume = threading.Event()
        self._abandoned = threading.Event()
        self._generation = threading.Event()
        self._thread = None
        self._requests = set()
        self._events = []
        self._pending = {}
        self._config = self._plan = self._relay = self._tree = self._guard = None
        self._verifier = self._owner = None
        self._exit_expires = self._manager_expires = None
        self._view = DesktopView()
        if self.journal_path.exists():
            self._view = DesktopView(phase='blocked', reason_code='cleanup_pending', cleanup_status='pending')

    # ---- read side -------------------------------------------------------------------------
    def current(self):
        with self._lock:
            relay = self._relay.snapshot() if self._relay is not None else None
            view = self._view
            if relay is not None:
                view = replace(view, relay_state=relay.state, relay_reason=relay.reason_code,
                               relay_port=relay.port, active_connections=relay.active_connections,
                               rejected_connections=relay.rejected_connections)
            return replace(view, events=tuple(self._events), exit_expires_at=self._exit_expires)

    def _event(self, text):
        self._events.append((datetime.now().astimezone(), text))
        del self._events[:-100]

    def _set(self, **changes):
        with self._lock:
            before = self._view
            self._view = replace(self._view, **changes)
            if 'phase' in changes and changes['phase'] != before.phase or (
                    'reason_code' in changes and changes['reason_code'] != before.reason_code):
                self._event(self._view.phase + ':' + self._view.reason_code)

    # ---- commands --------------------------------------------------------------------------
    def request_start(self, core_config, app_id, request_id):
        from src.core.backend import Config
        if (not isinstance(core_config, Config) or not isinstance(app_id, str)
                or not re.fullmatch(r'[A-Za-z0-9._!+-]{1,256}', app_id)
                or not isinstance(request_id, str) or not 0 < len(request_id) <= 128):
            raise ValueError('桌面端保护请求无效')
        with self._lock:
            if request_id in self._requests or self._view.active or (
                    self._thread is not None and self._thread.is_alive()):
                return False
            if self.journal_path.exists():
                self._view = DesktopView(phase='blocked', reason_code='cleanup_pending', cleanup_status='pending')
                return False
            self._requests.add(request_id)
            for flag in (self._stop, self._resume, self._abandoned, self._wake):
                flag.clear()
            self._events = []
            self._config, self._plan = core_config, None
            self._relay = self._tree = self._guard = self._verifier = self._owner = None
            self._exit_expires = self._manager_expires = None
            self._view = DesktopView(request_id=request_id, phase='preparing', reason_code='preparing',
                                     cleanup_status='pending')
            self._event('preparing:preparing')
            self._thread = threading.Thread(target=self._main, args=(core_config, app_id),
                                            name='desktop-protection', daemon=True)
            self._thread.start()
            return True

    def request_stop(self):
        with self._lock:
            phase = self._view.phase
            if phase == 'blocked' and (self._thread is None or not self._thread.is_alive()):
                self._stop.set()
                self._view = replace(self._view, phase='stopping', reason_code='recovering_rules')
                self._event('stopping:recovering_rules')
                self._thread = threading.Thread(target=self._recover, name='desktop-recovery', daemon=True)
                self._thread.start()
                return True
            if phase not in ('preparing', 'running', 'fused', 'desktop_exited'):
                return False
            self._stop.set()
            self._generation.set()
            relay = self._relay
            if phase != 'preparing':
                self._view = replace(self._view, phase='stopping', reason_code='user_stopped')
                self._event('stopping:user_stopped')
        if relay is not None:
            relay.pause('user_stopped')
        self._wake.set()
        return True

    def request_resume(self):
        with self._lock:
            if self._view.phase != 'fused' or not self._view.resumable or self._stop.is_set():
                return False
            self._resume.set()
        self._wake.set()
        return True

    def abandon(self):
        """D2: the assistant is closing anyway; the rules stay and the desktop stays offline."""
        with self._lock:
            self._abandoned.set()
            self._stop.set()
            self._generation.set()
            relay = self._relay
            if self._view.active:
                self._view = replace(self._view, phase='abandoned', reason_code='assistant_closed')
        if relay is not None:
            relay.close('assistant_closed')
        self._wake.set()

    # ---- preparation -----------------------------------------------------------------------
    def _backend_instance(self):
        if self._backend is None:
            self._backend = self._backend_override or NativeDesktopBackend()
        return self._backend

    def _check_stop(self):
        if self._stop.is_set():
            raise _Stage('user_stopped')

    def _sample_manager(self, cancelled):
        started = self.clock()
        result = self._backend.detect(self._config, deadline=started + self.budget.manager_budget_seconds,
                                      cancelled=cancelled)
        if self.clock() >= started + self.budget.manager_budget_seconds:
            raise _Stage('manager_sample_timeout')
        return started, result

    def _write_journal(self):
        from .desktop_wfp import journal_record
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open('x', encoding='utf-8') as handle:
            json.dump(journal_record(self._plan), handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())

    def _prepare(self, app_id):
        backend = self._backend_instance()
        self._stage = 'desktop_running'
        if backend.desktop_check(self._config) != 'pass':
            raise _Stage('desktop_running')
        self._check_stop()
        self._stage = 'desktop_executables_unconfirmed'
        executables = backend.discover(app_id)
        self._check_stop()
        self._stage = 'manager_sample_failed'
        _, first = self._sample_manager(self._stop)
        if first.ready is not True:
            raise _Stage(_manager_reason(first))
        self._owner = first._owner_evidence
        self._check_stop()
        relay = backend.make_relay(self._config, self._admit, self.budget.lease_seconds)
        with self._lock:
            self._relay = relay
        port = relay.reserve()
        self._stage = 'system_policy_unconfirmed'
        self._plan = backend.prepare_plan(executables, port)
        self._check_stop()
        self._write_journal()
        try:
            backend.apply(self._plan)
        except BaseException as error:
            if isinstance(error, PermissionError) or str(error).endswith(':5'):
                raise _Stage('system_permission_denied') from error
            raise
        self._verifier = backend.verifier(self._plan, self.clock, self.budget.policy_max_age_seconds)
        self._verifier.read()
        self._check_stop()
        self._stage = 'desktop_running'
        if backend.desktop_check(self._config) != 'pass':
            raise _Stage('desktop_running')
        # Fresh exit evidence, then only the activation, so forwarding opens inside the evidence window.
        self._stage = 'manager_sample_failed'
        started, second = self._sample_manager(self._stop)
        if second.ready is not True or second._owner_evidence != self._owner:
            raise _Stage(_manager_reason(second) if second.ready is not True else 'proxy_owner_changed')
        self._exit_expires = started + self.budget.exit_ttl_seconds
        self._manager_expires = started + self.budget.manager_max_age_seconds
        self._check_stop()
        self._stage = 'desktop_launch_failed'
        self._set(reason_code='launching')
        pid = backend.launch(self._config, app_id, port)
        if type(pid) is not int or pid <= 0:
            raise _Stage('desktop_launch_failed')
        self._stage = 'desktop_binding_unconfirmed'
        root = backend.process_info(pid)
        if root is None or backend.path_key(root[1]) != backend.path_key(self._plan.apps[0].executable):
            raise _Stage('desktop_binding_unconfirmed')
        self._tree = backend.make_tree(pid, root[0], self._plan.apps[0].executable, self._plan.executables)
        self._guard = DesktopGuard(self._config, self._tree, port, self._verifier, self._owner, backend,
                                   budget=self.budget.guard_budget_seconds, lease=self.budget.lease_seconds,
                                   clock=self.clock)
        self._stage = 'initial_guard_failed'
        self._open_forwarding()

    def _open_forwarding(self, *, new_owner=False):
        _, _, expires, observation = self._guard.read()
        if not self._relay.authorize(min(expires, self._exit_expires), self._owner, new_owner=new_owner):
            raise _Stage('relay_not_authorized')
        with self._lock:
            self._view = replace(self._view, guard_sequence=self._view.guard_sequence + 1, guard_expires_at=expires,
                                 protected_processes=len(observation.allowed),
                                 other_children=observation.other_children,
                                 executables=len(self._plan.apps))

    def _admit(self, client_endpoint, server_endpoint):
        try:
            tree = self._tree
            return tree is not None and tree.admits(self._backend.connection_pid(client_endpoint, server_endpoint))
        except Exception:
            return False

    # ---- running ---------------------------------------------------------------------------
    def _fuse(self, reason):
        with self._lock:
            if self._view.phase != 'running' or self._stop.is_set():
                return
            self._generation.set()
            phase = 'desktop_exited' if reason == 'desktop_exited' else 'fused'
            self._set(phase=phase, reason_code=reason, resumable=phase == 'fused')
            relay = self._relay
        if relay is not None:
            relay.pause(reason)
        self._wake.set()

    def _guard_loop(self, generation):
        while not generation.is_set():
            started = self.clock()
            with self._lock:
                self._pending['guard'] = started + self.budget.guard_budget_seconds
            try:
                _, _, expires, observation = self._guard.read()
                if generation.is_set():
                    return
                if not self._relay.authorize(min(expires, self._exit_expires), self._owner):
                    raise ValueError('relay_not_authorized')
                if self.clock() >= started + self.budget.guard_budget_seconds:
                    raise ValueError('guard_timeout')
                with self._lock:
                    self._view = replace(self._view, guard_sequence=self._view.guard_sequence + 1,
                                         guard_expires_at=expires, protected_processes=len(observation.allowed),
                                         other_children=observation.other_children)
            except ValueError as error:
                reason = str(error)
                self._fuse(reason if reason in _GUARD_REASONS or reason == 'relay_not_authorized'
                           else 'guard_failed')
                return
            except BaseException:
                self._fuse('guard_failed')
                return
            finally:
                with self._lock:
                    self._pending.pop('guard', None)
            if generation.wait(self.budget.guard_interval_seconds):
                return

    def _manager_loop(self, generation):
        while not generation.is_set():
            started = self.clock()
            with self._lock:
                self._pending['manager'] = started + self.budget.manager_budget_seconds
            try:
                started, result = self._sample_manager(generation)
                if generation.is_set():
                    return
                if result.ready is not True:
                    self._fuse(_manager_reason(result))
                    return
                if result._owner_evidence != self._owner:
                    self._fuse('proxy_owner_changed')
                    return
                with self._lock:
                    self._exit_expires = max(self._exit_expires or 0, started + self.budget.exit_ttl_seconds)
                    self._manager_expires = max(self._manager_expires or 0,
                                                started + self.budget.manager_max_age_seconds)
                    self._view = replace(self._view, manager_sequence=self._view.manager_sequence + 1)
            except _Stage as error:
                self._fuse(error.reason)
                return
            except BaseException:
                if not generation.is_set():
                    self._fuse('manager_sample_failed')
                return
            finally:
                with self._lock:
                    self._pending.pop('manager', None)
            if generation.wait(self.budget.manager_interval_seconds):
                return

    def _exit_loop(self, generation):
        while not generation.is_set():
            started = self.clock()
            with self._lock:
                self._pending['exit'] = started + self.budget.exit_check_budget_seconds
            try:
                check = self._backend.exit_check(self._config)
                if generation.is_set():
                    return
                status = getattr(check, 'status', 'unknown')
                if status == 'fail':
                    self._fuse('target_exit_mismatch')
                    return
                # An unconfirmed check does not refresh; the evidence expiry decides.
                if status == 'pass':
                    if self._backend.proxy_owner(self._config) != self._owner:
                        self._fuse('proxy_owner_changed')
                        return
                    with self._lock:
                        self._exit_expires = max(self._exit_expires or 0, started + self.budget.exit_ttl_seconds)
                        self._view = replace(self._view, exit_sequence=self._view.exit_sequence + 1)
            except BaseException:
                if not generation.is_set():
                    self._fuse('exit_check_failed')
                return
            finally:
                with self._lock:
                    self._pending.pop('exit', None)
            if generation.wait(self.budget.exit_check_interval_seconds):
                return

    def _sampling_round(self):
        generation = threading.Event()
        with self._lock:
            self._generation = generation
            self._pending = {}
        workers = [threading.Thread(target=loop, args=(generation,), name='desktop-' + name, daemon=True)
                   for name, loop in (('guard', self._guard_loop), ('manager', self._manager_loop),
                                      ('exit', self._exit_loop))]
        for worker in workers:
            worker.start()
        while not generation.wait(0.02):
            now = self.clock()
            with self._lock:
                overdue = next((kind for kind, deadline in self._pending.items() if now >= deadline), None)
                expired = self._exit_expires is None or now >= self._exit_expires
                manager_expired = self._manager_expires is None or now >= self._manager_expires
                relay = self._relay.snapshot()
            if overdue is not None:
                self._fuse(overdue + '_timeout')
            elif expired:
                self._fuse('exit_evidence_expired')
            elif manager_expired:
                self._fuse('manager_evidence_expired')
            elif relay.state != 'forwarding':
                self._fuse('relay_' + relay.reason_code)
        generation.set()
        deadline = time.monotonic() + self.budget.manager_budget_seconds + 1
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))

    def _try_resume(self):
        if self._tree is None or not self._tree.root_alive():
            self._set(phase='desktop_exited', reason_code='desktop_exited', resumable=False)
            return
        self._set(reason_code='resume_checking')
        try:
            started, result = self._sample_manager(self._stop)
            if result.ready is not True:
                raise _Stage(_manager_reason(result))
            # A restarted Proxy Manager passes the full trusted-program check again before adoption.
            new_owner = result._owner_evidence != self._owner
            with self._lock:
                self._owner = result._owner_evidence
                self._guard.owner = self._owner
                self._exit_expires = started + self.budget.exit_ttl_seconds
                self._manager_expires = started + self.budget.manager_max_age_seconds
            self._open_forwarding(new_owner=new_owner)
        except _Stage as error:
            self._set(phase='fused', reason_code='resume_rejected_' + error.reason)
            return
        except ValueError as error:
            reason = str(error)
            self._set(phase='desktop_exited' if reason == 'desktop_exited' else 'fused',
                      reason_code=reason if reason == 'desktop_exited' else 'resume_rejected_' +
                      (reason if reason in _GUARD_REASONS else 'guard_failed'))
            return
        except BaseException:
            self._set(phase='fused', reason_code='resume_rejected_guard_failed')
            return
        self._set(phase='running', reason_code='protecting', resumable=False)

    def _main(self, config, app_id):
        self._stage = 'preparation_failed'
        try:
            self._prepare(app_id)
            self._set(phase='running', reason_code='protecting', cleanup_status='not_applicable')
        except BaseException as error:
            reason = error.reason if isinstance(error, _Stage) else self._stage
            self._prepare_failed(reason)
            return
        while not self._stop.is_set():
            if self._view.phase == 'running':
                self._sampling_round()
                continue
            self._wake.wait(0.5)
            self._wake.clear()
            if self._stop.is_set():
                break
            if self._resume.is_set():
                self._resume.clear()
                self._try_resume()
            elif self._view.phase == 'fused' and not self._tree.root_alive():
                self._set(phase='desktop_exited', reason_code='desktop_exited', resumable=False)
        self._finish()

    def _prepare_failed(self, reason):
        relay = self._relay
        if relay is not None:
            relay.pause(reason)
        if self._plan is None or not self.journal_path.exists():
            if relay is not None:
                relay.close(reason)
            self._set(phase='failed', reason_code=reason, cleanup_status='not_applicable')
            return
        # Rules exist. Launched (or unknown): keep them and let the user quit the desktop first.
        launched = self._backend.running(self._plan.executables)
        if launched is False:
            self._remove_rules(phase_after='idle' if reason == 'user_stopped' else 'failed', reason_after=reason)
            return
        self._set(phase='fused', reason_code=reason, cleanup_status='pending')
        while not self._stop.is_set():
            self._wake.wait(0.5)
            self._wake.clear()
        self._finish()

    # ---- removal ---------------------------------------------------------------------------
    def _wait_for_exit(self):
        while not self._abandoned.is_set():
            running = self._backend.running(self._plan.executables)
            if running is False:
                return True
            self._set(phase='waiting_exit',
                      reason_code='desktop_still_running' if running else 'desktop_state_unknown')
            self._wake.wait(self.budget.exit_wait_poll_seconds)
            self._wake.clear()
        return False

    def _remove_rules(self, *, phase_after='idle', reason_after='user_stopped'):
        try:
            if not self._wait_for_exit():
                return
            self._set(phase='stopping', reason_code='removing_rules')
            if self._verifier is not None:
                self._verifier.close()
            self._backend.rollback(self._plan)
            if not self._backend.objects_absent(self._plan):
                raise ValueError('objects_still_present')
            from .desktop_wfp import journal_record
            if json.loads(self.journal_path.read_text(encoding='utf-8')) != json.loads(json.dumps(
                    journal_record(self._plan))):
                raise ValueError('journal_changed')
            self.journal_path.unlink()
            if self._relay is not None:
                self._relay.close('stopped')
            self._set(phase=phase_after, reason_code=reason_after, cleanup_status='confirmed')
        except BaseException:
            if not self._abandoned.is_set():
                self._set(phase='blocked', reason_code='cleanup_unconfirmed', cleanup_status='unknown')

    def _finish(self):
        self._generation.set()
        if self._relay is not None:
            self._relay.pause('user_stopped')
        if self._abandoned.is_set():
            return
        self._remove_rules()

    def _recover(self):
        from .desktop_wfp import plan_from_journal
        try:
            self._backend_instance()
            self._plan = plan_from_journal(json.loads(self.journal_path.read_text(encoding='utf-8')))
        except BaseException:
            self._set(phase='blocked', reason_code='cleanup_unconfirmed', cleanup_status='unknown')
            return
        self._remove_rules()


class NativeDesktopBackend:
    """System calls are reached only through an explicitly requested protection start."""
    def desktop_check(self, config):
        from src.core.backend import desktop_status
        return desktop_status().status

    def discover(self, app_id):
        from src.core.backend import _desktop_snapshot
        packages, _ = _desktop_snapshot()
        desktop = next((item['executable'] for item in packages if item.get('aumid') == app_id), None)
        match = re.fullmatch(r'Claude_([a-z0-9]{13})!Claude', app_id)
        if not desktop or match is None:
            raise ValueError('desktop_executables_unconfirmed')
        base = Path(os.environ['LOCALAPPDATA']) / 'Claude-Data' / ('claude_' + match.group(1)) / 'claude-code'
        bundled = sorted((path for path in base.glob('*/*/claude.exe') if path.is_file()),
                         key=lambda path: path.stat().st_mtime_ns, reverse=True)[:7]
        return (('desktop', desktop), *(('claude_code', str(path)) for path in bundled))

    def detect(self, config, *, deadline, cancelled):
        from src.core.backend import detect
        return detect(config, deadline=deadline, cancelled=cancelled, reference_home=False, retry_exit_ip=True,
                      retry_target_trace=True)

    def exit_check(self, config):
        from src.core.backend import inspect_claude_trace
        return inspect_claude_trace(config)

    def make_relay(self, config, admit, lease_seconds):
        from .desktop_relay import DesktopRelay
        return DesktopRelay(config, admit=admit, max_lease_seconds=lease_seconds)

    def prepare_plan(self, executables, port):
        from .desktop_wfp import prepare_plan
        return prepare_plan(executables, port)

    def _absent(self, plan):
        return self.running(plan.executables) is False

    def apply(self, plan):
        from .desktop_wfp import PlanApproval, apply_plan
        return apply_plan(plan, approval=PlanApproval(plan.digest, 'apply'), processes_absent=self._absent)

    def rollback(self, plan):
        from .desktop_wfp import PlanApproval, rollback_plan
        return rollback_plan(plan, approval=PlanApproval(plan.digest, 'rollback'), processes_absent=self._absent)

    def objects_absent(self, plan):
        from .desktop_wfp import objects_absent
        return objects_absent(plan)

    def verifier(self, plan, clock, max_age):
        from .desktop_wfp import DesktopPolicyVerifier
        return DesktopPolicyVerifier(plan, clock=clock, max_age_seconds=max_age)

    def launch(self, config, app_id, port):
        from src.core.backend import _activate_application
        if type(port) is not int or not 1 <= port <= 65535:
            return None
        try:
            return _activate_application(app_id, f'--proxy-server=http://127.0.0.1:{port}')
        except OSError:
            return None

    def process_info(self, pid):
        from .desktop_process import process_info
        return process_info(pid)

    def path_key(self, path):
        from .desktop_wfp import path_key
        return path_key(path)

    def make_tree(self, pid, created, desktop, executables):
        from .desktop_process import DesktopTree
        return DesktopTree(pid, created, desktop, executables)

    def running(self, executables):
        from .desktop_process import running_executables
        try:
            return running_executables(executables)
        except OSError:
            return None

    def connection_pid(self, client_endpoint, server_endpoint):
        from .desktop_process import connection_pid
        return connection_pid(client_endpoint, server_endpoint)

    def proxy_owner(self, config):
        from .relay_identity import _native_proxy_owner
        return _native_proxy_owner(config)

    def tcp_rows(self):
        from .relay_identity import _tcp_rows
        return _tcp_rows()
