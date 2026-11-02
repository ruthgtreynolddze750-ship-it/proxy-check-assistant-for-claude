"""Explicitly started, application-owned dedicated browser session."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
import json
import os
import re
import uuid
from pathlib import Path
import threading
import time

from src.core.backend import Config, Detection, DetectionStep, detection_error_code
from src.core.monitoring import BrowserBindingEvidence, MonitorSession, LayeredMonitorSession
from src.browser.inspection import BrowserSelection, _valid_url
from .session_relay import RelaySnapshot, WorkerFailureDiagnostic
from .relay_identity import (GuardSampleDiagnostic, _GuardTrace, _new_guard_trace,
                             _guard_scope, _guard_stage)


@dataclass(frozen=True)
class SamplingBudget:
    interval_seconds: float = 5.0
    max_age_seconds: float = 60.0
    identity_refresh_seconds: float = 0.25
    request_budget_seconds: float = 10.0
    request_evidence_ttl_seconds: float = 30.0
    relay_max_lease_seconds: float = 2.0
    policy_max_age_seconds: float = 5.0
    manager_interval_seconds: float = 5.0
    manager_budget_seconds: float = 25.0
    guard_budget_seconds: float = 0.5

    def __post_init__(self):
        if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
               for value in vars(self).values()):
            raise ValueError('生产采样预算无效')
        if (self.interval_seconds > 5 or self.request_budget_seconds > 10
                or self.request_evidence_ttl_seconds > 30 or self.relay_max_lease_seconds > 2
                or self.max_age_seconds > 60 or self.policy_max_age_seconds > 5
                or 2*self.request_budget_seconds+self.interval_seconds >= self.request_evidence_ttl_seconds
                or 2*self.manager_budget_seconds+self.manager_interval_seconds >= self.max_age_seconds
                or self.identity_refresh_seconds+2*self.guard_budget_seconds >= self.relay_max_lease_seconds):
            raise ValueError('生产采样预算超出批准期限或无法及时刷新')


@dataclass(frozen=True)
class ManagerSampleDiagnostic:
    outcome: str
    elapsed_seconds: float
    budget_seconds: float
    checks: tuple[tuple[str, str], ...] = ()
    steps: tuple[DetectionStep, ...] = ()
    error_code: str = ''
    rejection_reason: str = ''


@dataclass(frozen=True)
class RuntimeView:
    request_id: str = ''
    phase: str = 'idle'
    session: MonitorSession | None = field(default=None, repr=False, compare=False)
    browser_evidence: BrowserBindingEvidence | None = field(default=None, repr=False)
    relay_snapshot: RelaySnapshot | None = None
    reason_code: str = 'not_started'
    cleanup_status: str = 'not_applicable'
    sampling_budget: SamplingBudget = field(default_factory=SamplingBudget)
    evidence_mode: str = 'layered_v1'
    binding_key: tuple | None = field(default=None, repr=False)
    manager_sequence: int = 0
    exit_sequence: int = 0
    guard_sequence: int = 0
    manager_expires_at: float | None = None
    exit_expires_at: float | None = None
    guard_expires_at: float | None = None
    manager_diagnostic: ManagerSampleDiagnostic | None = None
    guard_diagnostic: GuardSampleDiagnostic | None = None
    worker_diagnostic: WorkerFailureDiagnostic | None = None


class ManagedSessionRuntime:
    """Construction/current are read-only; commands require an explicit UI action."""
    def __init__(self, *, journal_path=None, budget=None, backend_factory=None):
        self.budget = budget or SamplingBudget()
        if not isinstance(self.budget, SamplingBudget):
            raise ValueError('生产采样预算无效')
        self.journal_path = Path(journal_path) if journal_path is not None else (
            Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'ClaudeLaunchCenter' / 'session-recovery.json')
        self._factory = backend_factory
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._view = RuntimeView(sampling_budget=self.budget)
        self._thread = self._backend = self._session = None
        self._selection = self._config = self._fingerprint = None
        self._requests = set()
        self._pending = {}
        self._guard_trace = self._guard_terminal = None
        self._guard_sample_sequence = 0
        self._user_stopped = False
        if self.journal_path.exists():
            self._view = replace(self._view, phase='blocked', reason_code='cleanup_unconfirmed',
                                 cleanup_status='unknown')

    def current(self):
        with self._lock:
            return self._view

    def request_start(self, core_config, selection, *, config_fingerprint, request_id):
        return self._request_start(core_config, selection, config_fingerprint, request_id)

    def request_stop(self, binding_key=None, request_id=''):
        # Cancellation never waits behind the detector or a command queue.
        with self._lock:
            if binding_key is not None and self._view.binding_key != binding_key:
                return
            self._cancel.set()
            self._user_stopped = True
            session, backend = self._session, self._backend
            trace = self._guard_trace or getattr(backend, '_guard_trace', None)
            generation = self._cancel
            token = object() if self._guard_terminal is None else None
            if token is not None:
                self._guard_terminal = token
            if self._view.phase in ('preparing', 'running', 'alarm'):
                self._view = replace(self._view, request_id=request_id or self._view.request_id,
                                     phase='stopping', reason_code='user_stopped', cleanup_status='pending')
        if session is not None:
            session.stop()
        if backend is not None:
            backend.revoke()
        if token is not None:
            self._record_guard_diagnostic(backend, trace, generation, 'cancelled', terminal=token)

    def request_resume(self, binding_key, request_id):
        with self._lock:
            if (self._view.phase != 'alarm' or self._view.cleanup_status != 'confirmed'
                    or self._view.binding_key != binding_key):
                return
            config, selection, fingerprint = self._config, self._selection, self._fingerprint
        self._request_start(config, selection, fingerprint, request_id)

    def _request_start(self, config, selection, fingerprint, request_id):
        if (not isinstance(config, Config) or not isinstance(selection, BrowserSelection)
                or not _valid_url(selection.url)
                or not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint)
                or not isinstance(request_id, str) or not 0 < len(request_id) <= 128):
            raise ValueError('生产会话请求无效')
        with self._lock:
            if request_id in self._requests or (self._thread is not None and self._thread.is_alive()):
                return
            if self.journal_path.exists() or self._view.cleanup_status == 'unknown':
                self._view = replace(self._view, phase='blocked', reason_code='cleanup_unconfirmed',
                                     cleanup_status='unknown')
                return
            self._requests.add(request_id)
            self._config, self._selection, self._fingerprint = config, selection, fingerprint
            self._cancel = threading.Event()
            self._user_stopped = False
            self._pending = {}
            self._guard_trace = self._guard_terminal = None
            self._guard_sample_sequence = 0
            self._session = self._backend = None
            self._view = RuntimeView(request_id=request_id, phase='preparing', reason_code='preparing',
                                     cleanup_status='pending', sampling_budget=self.budget)
            self._thread = threading.Thread(target=self._run, name='dedicated-session-runtime', daemon=True)
            self._thread.start()

    def _trip(self, reason, *, guard_error=None):
        with self._lock:
            if self._user_stopped or self._view.phase in ('alarm', 'stopping', 'blocked'):
                return
            session, backend = self._session, self._backend
            trace = self._guard_trace or getattr(backend, '_guard_trace', None)
            generation = self._cancel
            token = object() if self._guard_terminal is None else None
            if token is not None:
                self._guard_terminal = token
            self._cancel.set()
            self._view = replace(self._view, phase='alarm', reason_code=reason, cleanup_status='pending')
        if session is not None:
            session.fail(reason)
        if backend is not None:
            backend.revoke()
            self._record_worker_diagnostic(backend, generation)
        if token is not None:
            outcome = ('timeout' if reason == 'guard_sample_timeout' else
                       'exception' if reason in ('guard_sample_failed', 'initial_guard_failed') else 'cancelled')
            self._record_guard_diagnostic(backend, trace, generation, outcome, terminal=token,
                error=guard_error if outcome in ('timeout', 'exception') else None)

    def _record_worker_diagnostic(self, backend, generation):
        try:
            reader = getattr(backend, 'worker_diagnostic', None)
            detail = reader() if callable(reader) else None
            if type(detail) is not WorkerFailureDiagnostic or not self._lock.acquire(blocking=False):
                return
            try:
                if backend is self._backend and generation is self._cancel:
                    self._view = replace(self._view, worker_diagnostic=detail)
            finally:
                self._lock.release()
        except BaseException:
            pass

    def _record_guard_diagnostic(self, backend, trace, generation, outcome, *, terminal=None, error=None):
        if type(trace) is not _GuardTrace:
            return
        try:
            if not self._lock.acquire(blocking=False):
                return
            try:
                if backend is not self._backend or generation is not self._cancel:
                    return
                if terminal is not None:
                    if terminal is not self._guard_terminal:
                        return
                elif self._guard_terminal is not None or generation.is_set():
                    return
            finally:
                self._lock.release()
            if outcome == 'cancelled' and trace._completed:
                return
            if outcome == 'accepted':
                trace._completed = True
            try:
                detail = trace.snapshot(outcome, freeze=terminal is not None,
                    error_code='' if error is None else detection_error_code(error))
                if type(detail) is not GuardSampleDiagnostic:
                    raise ValueError('diagnostic_unavailable')
            except Exception:
                detail = GuardSampleDiagnostic(outcome, None, self.budget.guard_budget_seconds,
                    incomplete=True)
            # Diagnostics cannot hold up the watchdog or wait for a UI reader.
            if not self._lock.acquire(blocking=False):
                return
            try:
                if backend is not self._backend or generation is not self._cancel:
                    return
                if terminal is not None:
                    if terminal is not self._guard_terminal:
                        return
                elif self._guard_terminal is not None or generation.is_set():
                    return
                self._view = replace(self._view, guard_diagnostic=detail)
            finally:
                self._lock.release()
        except Exception:
            pass

    def _record_manager_diagnostic(self, started, budget, *, result=None, outcome, error=None,
                                   rejection_reason=''):
        checks = ()
        if isinstance(result, Detection):
            checks = tuple((name, getattr(result, name).status
                            if getattr(result, name).status in ('pass','fail','unknown') else 'unknown')
                           for name in ('manager','port','exit_ip','claude','target_trace','mapping'))
            checks += (('owner', 'pass' if result._owner_evidence is not None else 'unknown'),)
        detail = ManagerSampleDiagnostic(outcome, max(0.0,time.monotonic()-started), budget, checks,
            tuple(getattr(self._backend, 'manager_steps', ())),
            '' if error is None else detection_error_code(error), rejection_reason)
        with self._lock:
            # A late worker may supply context, but cannot replace the watchdog's timeout.
            previous = self._view.manager_diagnostic
            if previous is None or previous.outcome != 'timeout':
                self._view = replace(self._view, manager_diagnostic=detail)

    def _publish(self):
        session, backend = self._session, self._backend
        evidence = session.production_evidence
        snapshot = backend.snapshot()
        monitor_snapshot = session.snapshot()
        with self._lock:
            phase, cleanup = self._view.phase, self._view.cleanup_status
            if phase == 'preparing' and not self._cancel.is_set():
                browser = evidence['browser_evidence']
                if (monitor_snapshot.state != 'monitoring' or snapshot.state != 'listening'
                        or session.binding_key is None or browser is None
                        or time.monotonic() >= browser.expires_at):
                    raise ValueError('initial_runtime_evidence_unconfirmed')
                phase, cleanup = 'running', 'not_applicable'
            self._view = replace(self._view, session=session, binding_key=session.binding_key,
                                 relay_snapshot=snapshot, phase=phase, cleanup_status=cleanup,
                                  worker_diagnostic=getattr(snapshot, 'worker_diagnostic', None),
                                 reason_code='monitoring' if phase == 'running' else self._view.reason_code,
                                 **evidence)

    def _sample_loop(self, kind, delay, interval, budget):
        navigate = kind == 'exit'
        if self._cancel.wait(delay):
            return
        while not self._cancel.is_set():
            started = time.monotonic()
            result = None
            manager_recorded = False
            trace = None
            backend, generation = self._backend, self._cancel
            with self._lock:
                self._pending[kind] = started + budget
                if kind == 'guard':
                    self._guard_sample_sequence = min(self._guard_sample_sequence+1, 2147483647)
                    trace = _new_guard_trace(started, budget, self._guard_sample_sequence, 'sample')
                    self._guard_trace = trace
            try:
                if kind == 'manager':
                    result = self._backend.check_manager(self._config, started+budget)
                    accepted = self._session.accept_manager_sample(result, started_at=started,
                                                                   completed_at=time.monotonic())
                    reasons = self._session.snapshot().reason_codes if not accepted else ()
                    self._record_manager_diagnostic(started, budget, result=result,
                        outcome='accepted' if accepted else 'rejected',
                        rejection_reason=reasons[0] if reasons else '')
                    manager_recorded = True
                elif kind == 'exit':
                    if navigate:
                        self._backend.open_selected_url(self._selection.url)
                        navigate, accepted = False, True
                    else:
                        result = self._backend.collect_exit(uuid.uuid4().hex)
                        accepted = self._session.accept_exit_sample(result)
                else:
                    with _guard_scope(trace):
                        with _guard_stage('guard_read'):
                            result = self._backend.read_guard()
                        with _guard_stage('lease_issue'):
                            lease = self._session.issue_forward_lease(result)
                        accepted = False
                        if lease is not None:
                            with _guard_stage('relay_renew'):
                                accepted = self._backend.renew(lease, result)
                if time.monotonic() >= started+budget or not accepted:
                    raise ValueError('sample_unconfirmed_or_expired')
                if kind == 'guard':
                    self._record_guard_diagnostic(backend, trace, generation, 'accepted')
            except BaseException as error:
                timed_out = time.monotonic() >= started+budget
                if kind == 'manager' and (not manager_recorded or timed_out):
                    self._record_manager_diagnostic(started, budget, result=result,
                        outcome='timeout' if timed_out else 'cancelled' if self._cancel.is_set() else 'exception',
                        error=error)
                if not self._cancel.is_set():
                    self._trip(kind+('_sample_timeout' if timed_out else '_sample_failed'),
                               guard_error=error if kind == 'guard' else None)
                return
            finally:
                with self._lock:
                    self._pending.pop(kind, None)
            if self._cancel.wait(interval):
                return

    def _run(self):
        workers = []
        try:
            backend = (self._factory or NativeManagedBackend)()
            with self._lock:
                self._backend = backend
            if self._cancel.is_set():
                return
            session = backend.initialize(self._config, self._selection, self._fingerprint, self.budget,
                                         self._cancel, self.journal_path)
            with self._lock:
                self._session = session
            if self._cancel.is_set():
                session.stop()
                return
            self._record_guard_diagnostic(backend, getattr(backend, '_guard_trace', None),
                                          self._cancel, 'accepted')
            for kind, delay, interval, budget in (
                ('guard', self.budget.identity_refresh_seconds, self.budget.identity_refresh_seconds,
                 self.budget.guard_budget_seconds),
                ('manager', 0.0, self.budget.manager_interval_seconds, self.budget.manager_budget_seconds),
                ('exit', 0.0, self.budget.interval_seconds, self.budget.request_budget_seconds),
            ):
                worker = threading.Thread(target=self._sample_loop, args=(kind, delay, interval, budget),
                                          name='dedicated-'+kind, daemon=True)
                workers.append(worker)
                worker.start()
            self._publish()
            while not self._cancel.wait(0.02):
                now = time.monotonic()
                with self._lock:
                    overdue = next(((kind, deadline) for kind, deadline in self._pending.items() if now >= deadline), None)
                snapshot = session.snapshot()
                if overdue is not None:
                    kind, deadline = overdue
                    if kind == 'manager':
                        self._record_manager_diagnostic(deadline-self.budget.manager_budget_seconds,
                            self.budget.manager_budget_seconds, outcome='timeout')
                    self._trip(kind+'_sample_timeout')
                elif snapshot.state == 'alarm':
                    self._trip(snapshot.reason_codes[0] if snapshot.reason_codes else 'evidence_unconfirmed')
                elif backend.snapshot().state != 'listening':
                    self._trip('relay_closed')
                self._publish()
        except BaseException as error:
            if not self._user_stopped:
                self._trip(getattr(self._backend, 'failure_reason', 'preparation_failed'), guard_error=error)
        finally:
            self._cancel.set()
            backend = self._backend
            if backend is not None:
                backend.revoke()
            deadline = time.monotonic()+max(self.budget.manager_budget_seconds,
                                             self.budget.request_budget_seconds)+1
            for worker in workers:
                if worker.ident is not None:
                    worker.join(max(0, deadline-time.monotonic()))
            quiescent = all(not worker.is_alive() for worker in workers)
            try:
                cleaned = (backend is None or backend.cleanup(quiescent=quiescent) is True)
                cleaned = cleaned and not self.journal_path.exists()
            except BaseException:
                cleaned = False
            if self._session is not None and backend is not None:
                self._publish()
            elif backend is not None:
                self._record_worker_diagnostic(backend, self._cancel)
            with self._lock:
                self._view = replace(self._view, cleanup_status='confirmed' if cleaned else 'unknown',
                    phase=('idle' if self._user_stopped else 'alarm') if cleaned else 'blocked',
                    reason_code=('user_stopped' if self._user_stopped else self._view.reason_code)
                        if cleaned else 'cleanup_unconfirmed')


class NativeManagedBackend:
    """System calls are reached only through an explicitly requested runtime start."""
    def __init__(self):
        self.relay = self.probe = self.plan = self.grant = self.monitor = self.guard = None
        self.reader = self.guard_reader = self.cancel = None
        self.journal = None
        self._owns_journal = False
        self.failure_reason = 'preparation_failed'
        self._manager_steps = []
        self._guard_trace = None

    def _check(self):
        if self.cancel.is_set():
            raise ValueError('session_cancelled')

    def _manifest(self):
        from .dedicated_wfp import plan_objects
        return {'schema': 1, 'state': 'pending', 'deployment_id': self.plan.deployment_id,
                'plan_digest': self.plan.digest,
                'target': {'executable': self.plan.target.executable,
                           'user_data_dir': self.plan.target.user_data_dir},
                'relay_port': self.plan.relay_port,
                'objects': plan_objects(self.plan)}

    def initialize(self, config, selection, fingerprint, budget, cancelled, journal):
        from src.core.backend import detect
        from src.browser import request_probe as browser
        from src.browser.session_binding import DedicatedTarget
        from . import dedicated_wfp as wfp
        from .session_relay import SessionRelay, ProductionBootstrapBridge
        from .relay_identity import WindowsRelayVerifier, WindowsSessionGuard
        self.config, self.budget, self.cancel, self.journal = config, budget, cancelled, journal
        self.failure_reason = 'dedicated_target_unconfirmed'
        self._check()
        target = DedicatedTarget(selection.chrome_executable, selection.user_data_dir)
        excluded = browser.inspect_production_target(target)
        self._check()
        self.failure_reason = 'manager_sample_failed'
        started = time.monotonic()
        manager = detect(config, deadline=started+budget.manager_budget_seconds, cancelled=cancelled,
                         reference_home=False, retry_exit_ip=True, retry_target_trace=True)
        completed = time.monotonic()
        if manager.ready is not True:
            raise ValueError('manager_sample_failed')
        self._check()
        self.relay = SessionRelay(None, config, max_lease_seconds=budget.relay_max_lease_seconds)
        reservation = self.relay.reserve()
        self.failure_reason = 'system_policy_unconfirmed'
        self.plan = wfp.prepare_plan(target, reservation.endpoint[1], excluded_executables=excluded)
        self._check()
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        with self.journal.open('x', encoding='utf-8') as handle:
            self._owns_journal = True
            json.dump(self._manifest(), handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        self._check()
        try:
            wfp.apply_plan(self.plan, approval=wfp.PlanApproval(self.plan.digest, 'apply'))
        except BaseException as error:
            if isinstance(error, PermissionError) or str(error).endswith(':5'):
                self.failure_reason = 'system_permission_denied'
            raise
        self._check()
        self.reader = wfp.PolicyReadbackVerifier(self.plan, max_age_seconds=budget.policy_max_age_seconds)
        plan = browser.prepare_production_launch(target, reservation.endpoint[1], self.plan.digest,
            selection.profile_directory, request_seconds=budget.request_budget_seconds,
            evidence_seconds=budget.request_evidence_ttl_seconds)
        self.grant = browser.ProductionSessionGrant(plan, cancelled)
        bridge = ProductionBootstrapBridge(self.relay, self.reader)
        self.failure_reason = 'browser_start_unconfirmed'
        expected_owner = manager._owner_evidence
        def preflight(unused):
            self._check()
            proof = WindowsRelayVerifier().listener(config)
            return proof is not None and proof.owner == expected_owner
        try:
            self.probe = browser.launch_production_probe(plan, grant=self.grant,
                policy_verifier=self.reader, proxy_preflight=preflight, diagnostic_gate=bridge.gate)
        except BaseException as error:
            self.probe = getattr(error, 'owned_probe', None)
            raise
        self._check()
        binding = self.probe.binding()
        self.relay.bind(binding)
        key = (fingerprint, binding.root_pid, binding.root_created, binding.session_id)
        self.monitor = LayeredMonitorSession(config, browser_binding=binding, binding_key=key,
            exit_validator=self.probe.accepts_exit_evidence,
            guard_validator=lambda proof: self.guard is not None and self.guard.accepts(proof),
            manager_max_age=budget.max_age_seconds, exit_max_age=budget.request_evidence_ttl_seconds,
            lease_seconds=budget.relay_max_lease_seconds)
        self.monitor.start()
        if not self.monitor.accept_manager_sample(manager, started_at=started, completed_at=completed):
            raise ValueError('manager_evidence_expired')
        self.relay.attach_monitor(self.monitor)
        bridge.attach_probe(self.probe)
        self.failure_reason = 'initial_request_failed'
        self._check()
        bridge(config, binding, uuid.uuid4().hex)
        self._check()
        evidence = self.probe.seal_first_exit(bridge.last_route)
        if not self.monitor.accept_exit_sample(evidence):
            raise ValueError('initial_exit_unconfirmed')
        self.guard_reader = wfp.PolicyReadbackVerifier(self.plan, max_age_seconds=budget.policy_max_age_seconds)
        self.guard = WindowsSessionGuard(config, binding, plan.launch.fingerprint, self.relay, self.guard_reader,
            budget_seconds=budget.guard_budget_seconds, lease_seconds=budget.relay_max_lease_seconds,
            cancelled=cancelled)
        self.failure_reason = 'initial_guard_failed'
        self._guard_trace = _new_guard_trace(time.monotonic(), budget.guard_budget_seconds, 0, 'initialization')
        with _guard_scope(self._guard_trace):
            with _guard_stage('guard_read'):
                guard = self.guard.read()
            with _guard_stage('lease_issue'):
                lease = self.monitor.issue_forward_lease(guard)
                if lease is None:
                    raise ValueError('initial_lease_unconfirmed')
            with _guard_stage('relay_promote'):
                self.relay.promote(lease, bridge.last_route, policy=guard.policy)
        self.probe.route_provider = lambda: self.guard.latest
        self._check()
        return self.monitor

    def check_manager(self, config, deadline):
        from src.core.backend import detect
        self._manager_steps = []
        return detect(config, deadline=deadline, cancelled=self.cancel, diagnostics=self._manager_steps,
                      reference_home=False, retry_exit_ip=True, retry_target_trace=True)

    @property
    def manager_steps(self):
        return tuple(self._manager_steps)

    def collect_exit(self, sample_id):
        return self.probe.collect_exit(self.config, self.monitor.relay_binding, sample_id)

    def open_selected_url(self, url):
        self._check()
        if self.relay.snapshot().state != 'listening' or not self.relay._live():
            raise ValueError('relay_not_ready')
        return self.probe.open_selected_url(url)

    def read_guard(self):
        return self.guard.read()

    def renew(self, lease, guard):
        return self.relay.renew_production(lease, policy=guard.policy)

    def snapshot(self):
        return self.relay.snapshot()

    def worker_diagnostic(self):
        return None if self.relay is None else self.relay._worker_diagnostic_snapshot()

    def revoke(self):
        if self.cancel is not None:
            self.cancel.set()
        if self.grant is not None:
            self.grant.close()
        if self.relay is not None:
            self.relay.stop()

    def cleanup(self, *, quiescent):
        from . import dedicated_wfp as wfp
        from src.browser.session_binding import capture_process_snapshot
        self.revoke()
        if not quiescent:
            return False
        if self.probe is not None:
            try:
                self.probe.normal_close()
            except Exception:
                pass
            deadline = time.monotonic()+10
            while self.probe._process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if self.probe.exit_status().status != 'exited':
                return False
        elif self.plan is not None:
            snapshot = capture_process_snapshot(self.plan.target)
            if not snapshot.complete or snapshot.processes:
                return False
        for reader in (self.reader, self.guard_reader):
            if reader is not None:
                reader.close()
        if self.plan is not None and self._owns_journal:
            wfp.rollback_plan(self.plan, approval=wfp.PlanApproval(self.plan.digest, 'rollback'))
            engine = wfp.NativeWfp()
            try:
                absent = all(engine.get(item['kind'], item['key']) is None for item in wfp.plan_objects(self.plan))
            finally:
                engine.close()
            if not absent:
                return False
            current = json.loads(self.journal.read_text(encoding='utf-8'))
            if current != json.loads(json.dumps(self._manifest())):
                return False
            self.journal.unlink()
            self._owns_journal = False
        return True
