"""Guard diagnostics: injected OS boundaries; no browser, WFP or network."""
from dataclasses import asdict
from contextlib import ExitStack
from pathlib import Path
import json
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.protection import relay_identity as ri, dedicated_wfp as wfp
from src.protection.managed_session import ManagedSessionRuntime, NativeManagedBackend, RuntimeView, SamplingBudget
from test_managed_session import SyntheticSessionBackend
import test_production_guard as guard_fixture
import test_wfp_readback as policy_fixture
from src.core.backend import Config
from src.browser.inspection import BrowserSelection


class GuardDiagnosticTests(unittest.TestCase):
    def trace(self, now=None, **kwargs):
        self.assertTrue(hasattr(ri, '_GuardTrace'), 'missing bounded guard diagnostic recorder')
        clock = (lambda: now[0]) if now is not None else time.monotonic
        return ri._GuardTrace(clock(), .5, 1, 'sample', clock=clock, **kwargs)

    def runtime(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        runtime = ManagedSessionRuntime(journal_path=Path(folder.name)/'absent.json')
        backend = SyntheticSessionBackend()
        config = Config(25001, 25002, '203.0.113.1', 'https://example.test')
        selection = BrowserSelection('https://claude.ai/', r'C:\owned\chrome.exe', r'C:\data', 'Default')
        session = backend.initialize(config, selection, 'a'*64, SamplingBudget(), runtime._cancel, runtime.journal_path)
        self.addCleanup(session.stop)
        runtime._backend, runtime._session, runtime._config = backend, session, config
        runtime._view = RuntimeView(phase='running', reason_code='monitoring')
        return runtime, backend

    def test_fixed_primitive_contract_inflight_and_cap(self):
        now = [100.]
        trace = self.trace(now)
        token = trace.begin('policy_objects_before')
        self.assertIsNone(trace.begin('SECRET 198.51.100.8 C:/private'))
        now[0] = 100.5
        detail = trace.snapshot('timeout', freeze=True)
        self.assertIsInstance(detail, ri.GuardSampleDiagnostic)
        self.assertEqual((detail.steps[0].status, detail.steps[0].elapsed_seconds), ('running', .5))
        now[0] = 110.
        trace.end(token, 'returned')
        self.assertEqual(trace.snapshot('timeout').steps, detail.steps)
        other = self.trace(now)
        for _ in range(1000):
            other.end(other.begin('proxy_before'), 'returned')
        capped = other.snapshot('accepted')
        self.assertEqual(len(capped.steps), 24)
        self.assertTrue(capped.incomplete)
        self.assertNotIn('SECRET', json.dumps(asdict(detail)))

    def test_broken_diagnostics_preserve_original_error_and_scope(self):
        trace = self.trace()
        original = ValueError('SECRET path C:/private')
        called = []
        with patch.object(ri._GuardTrace, 'begin', side_effect=RuntimeError('diagnostic')), \
             patch.object(ri._GuardTrace, 'end', side_effect=RuntimeError('diagnostic')):
            with self.assertRaises(ValueError) as caught:
                with ri._guard_scope(trace), ri._guard_stage('proxy_before'):
                    called.append(True)
                    raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(called, [True])
        with ri._guard_stage('proxy_before'):
            pass
        self.assertEqual(trace.snapshot('exception').steps, ())

    def test_stage_precision_does_not_replace_original_budget_clock(self):
        phase = [1000.]
        with patch('time.monotonic',return_value=100.), patch('time.perf_counter',side_effect=lambda:phase[0]):
            trace = ri._GuardTrace(100.,.5,1,'sample')
            token = trace.begin('proxy_before')
            phase[0] += .0001
            trace.end(token,'returned')
            detail = trace.snapshot('accepted')
        self.assertAlmostEqual(detail.steps[0].elapsed_seconds,.0001,places=8)
        self.assertEqual(detail.elapsed_seconds,0.)
        self.assertEqual(detail.budget_seconds,.5)

    def test_thread_scopes_do_not_mix_records(self):
        barrier = threading.Barrier(2)
        records, errors = {}, []
        def run(stage):
            try:
                trace = self.trace()
                with ri._guard_scope(trace), ri._guard_stage(stage):
                    barrier.wait(1)
                records[stage] = trace.snapshot('accepted')
            except BaseException as error:
                errors.append(type(error).__name__)
        workers = [threading.Thread(target=run,args=(stage,)) for stage in ('proxy_before','policy_capabilities')]
        for worker in workers: worker.start()
        for worker in workers: worker.join(2)
        self.assertFalse(errors)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        for stage,detail in records.items():
            self.assertEqual(tuple(step.stage for step in detail.steps),(stage,))

    def test_actual_guard_boundaries_and_budget_unchanged(self):
        for delay in (.49, .5, .51):
            fixture = guard_fixture.ProductionGuardTests()
            fixture.setUp()
            try:
                trace = self.trace(fixture.now)
                def policy_read():
                    fixture.now[0] += delay
                    return fixture.policy
                fixture.reader.read.side_effect = policy_read
                with ri._guard_scope(trace):
                    if delay < .5:
                        proof = fixture.guard.read()
                        self.assertTrue(fixture.guard.accepts(proof))
                        self.assertEqual(fixture.owner_check.call_count, 2)
                    else:
                        with self.assertRaisesRegex(ValueError, 'guard_timeout_or_cancelled'):
                            fixture.guard.read()
                        self.assertIsNone(fixture.guard.latest)
                stages = [x.stage for x in trace.snapshot('accepted').steps]
                self.assertIn('bound_before', stages)
                self.assertIn('proxy_before', stages)
                self.assertIn('policy_read', stages)
                self.assertEqual(fixture.guard.budget, .5)
                self.assertEqual(fixture.guard.lease_seconds, 2.)
            finally:
                fixture.doCleanups()

    def test_policy_substages_keep_all_reads_and_close_failure(self):
        fixture = policy_fixture.ReadbackTests(); fixture.setUp()
        trace = self.trace()
        with ri._guard_scope(trace):
            proof = fixture.reader().read()
        stages = [x.stage for x in trace.snapshot('accepted').steps]
        self.assertEqual(stages, ['policy_engine_open', 'policy_capabilities', 'policy_identity_before',
            'policy_objects_before', 'policy_objects_after', 'policy_identity_after', 'policy_engine_close'])
        self.assertEqual(len(fixture.engine.reads), 12)
        self.assertEqual(fixture.engine.closed, 1)
        fixture.engine.objects.clear(); fixture.engine.close_error = True
        with ri._guard_scope(self.trace()), self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch') as caught:
            fixture.reader().read()
        self.assertTrue(any('close_failed' in x for x in caught.exception.__notes__))

    def test_runtime_timeout_lease_stage_after_revoke_preserves_first(self):
        runtime, backend = self.runtime()
        clock = [time.monotonic()]
        def fail_renew(*args):
            clock[0] += .51
            raise TimeoutError('SECRET 198.51.100.8')
        backend.renew = fail_renew
        events = []
        revoke = backend.revoke
        backend.revoke = lambda: (events.append('revoke'), revoke())[-1]
        self.trace()
        snapshot = ri._GuardTrace.snapshot
        def observed(trace, *args, **kwargs):
            events.append('snapshot')
            self.assertTrue(backend.closed)
            return snapshot(trace, *args, **kwargs)
        with patch('time.monotonic', side_effect=lambda: clock[0]), patch.object(ri._GuardTrace, 'snapshot', observed):
            runtime._sample_loop('guard', 0, .25, .5)
        detail = runtime.current().guard_diagnostic
        self.assertEqual(detail.outcome, 'timeout')
        self.assertEqual(detail.error_code, 'timeout')
        self.assertEqual(detail.steps[-1].stage, 'relay_renew')
        self.assertEqual(detail.steps[-1].status, 'raised')
        self.assertEqual(events, ['revoke', 'snapshot'])
        runtime._trip('relay_closed')
        self.assertIs(runtime.current().guard_diagnostic, detail)
        self.assertEqual(runtime.current().reason_code, 'guard_sample_timeout')
        self.assertNotIn('SECRET', repr(detail))

    def test_busy_trace_lock_does_not_delay_revoke(self):
        runtime, backend = self.runtime()
        runtime._guard_trace = trace = self.trace()
        trace._lock.acquire()
        done = threading.Event()
        def trip():
            runtime._trip('guard_sample_timeout')
            done.set()
        worker = threading.Thread(target=trip, daemon=True)
        worker.start()
        try:
            self.assertTrue(done.wait(.5))
            self.assertTrue(backend.closed)
            self.assertTrue(runtime.current().guard_diagnostic.incomplete)
        finally:
            trace._lock.release(); worker.join(1)

    def test_explicit_stop_freezes_cancelled_and_rejects_late_accepted(self):
        runtime, backend = self.runtime()
        runtime._guard_trace = self.trace()
        runtime._guard_trace.begin('policy_objects_before')
        runtime.request_stop()
        detail = runtime.current().guard_diagnostic
        self.assertEqual(detail.outcome, 'cancelled')
        self.assertEqual(detail.steps[0].status, 'running')
        self.assertEqual(runtime.current().reason_code, 'user_stopped')
        runtime._record_guard_diagnostic(backend, runtime._guard_trace, runtime._cancel, 'accepted')
        self.assertIs(runtime.current().guard_diagnostic, detail)

    def test_old_backend_or_cancel_generation_cannot_publish(self):
        runtime, backend = self.runtime()
        trace = self.trace()
        runtime._record_guard_diagnostic(object(), trace, runtime._cancel, 'accepted')
        runtime._record_guard_diagnostic(backend, trace, threading.Event(), 'accepted')
        self.assertIsNone(runtime.current().guard_diagnostic)
        self.assertFalse(trace._frozen, 'stale generation must not touch the current trace')

    def test_actual_watchdog_captures_blocked_stage_before_worker_returns(self):
        entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
        class Backend(SyntheticSessionBackend):
            initialized = False
            def initialize(self, *args):
                session = super().initialize(*args)
                self.initialized = True
                return session
            def read_guard(self):
                if self.initialized:
                    with ri._guard_stage('policy_objects_before'):
                        entered.set()
                        release.wait(3)
                return super().read_guard()
            def revoke(self):
                super().revoke()
                revoked.set()
        backend = Backend()
        with tempfile.TemporaryDirectory() as folder:
            runtime = ManagedSessionRuntime(journal_path=Path(folder)/'absent.json', backend_factory=lambda: backend)
            try:
                runtime.request_start(Config(25001,25002,'203.0.113.1','https://example.test'),
                    BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\data','Default'),
                    config_fingerprint='a'*64,request_id='watchdog')
                self.assertTrue(entered.wait(1))
                self.assertTrue(revoked.wait(1.5))
                deadline = time.monotonic()+.5
                while runtime.current().guard_diagnostic is None and time.monotonic()<deadline:
                    threading.Event().wait(.001)
                detail = runtime.current().guard_diagnostic
                self.assertIsNotNone(detail)
                self.assertEqual(detail.outcome, 'timeout')
                stage = next(x for x in detail.steps if x.stage=='policy_objects_before')
                self.assertEqual(stage.status, 'running')
                self.assertFalse(release.is_set())
            finally:
                release.set()
                if runtime._thread:
                    runtime._thread.join(3)
            self.assertFalse(runtime._thread.is_alive())
            self.assertIs(runtime.current().guard_diagnostic, detail)
            self.assertEqual(runtime.current().reason_code, 'guard_sample_timeout')

    def test_non_guard_fault_cancels_guard_without_claiming_guard_timeout(self):
        runtime, backend = self.runtime()
        runtime._guard_trace = self.trace()
        runtime._guard_trace.begin('policy_capabilities')
        runtime._trip('manager_sample_failed')
        self.assertEqual(runtime.current().guard_diagnostic.outcome, 'cancelled')
        self.assertEqual(runtime.current().reason_code, 'manager_sample_failed')

    def test_other_fault_does_not_relabel_a_completed_guard_as_cancelled(self):
        runtime, backend = self.runtime()
        runtime._guard_trace = trace = self.trace()
        trace.end(trace.begin('guard_read'), 'returned')
        runtime._record_guard_diagnostic(backend,trace,runtime._cancel,'accepted')
        accepted = runtime.current().guard_diagnostic
        runtime._trip('manager_sample_failed')
        self.assertIs(runtime.current().guard_diagnostic,accepted)
        self.assertEqual(runtime.current().reason_code,'manager_sample_failed')

    def test_snapshot_exception_does_not_escape_trip(self):
        runtime, backend = self.runtime()
        runtime._guard_trace = self.trace()
        with patch.object(ri._GuardTrace, 'snapshot', side_effect=RuntimeError('SECRET')):
            runtime._trip('guard_sample_failed')
        self.assertTrue(backend.closed)
        self.assertTrue(runtime.current().guard_diagnostic.incomplete)
        self.assertNotIn('SECRET', repr(runtime.current().guard_diagnostic))

    def test_native_initialization_records_existing_promote_and_failures(self):
        from src.browser import request_probe as browser, session_binding
        from src.protection import session_relay, managed_session
        from src.core import backend as core
        from src.core.monitoring import BrowserBinding
        for case in ('success', 'guard_error', 'lease_rejected', 'promote_error'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                runtime = ManagedSessionRuntime(journal_path=Path(folder)/'journal.json')
                native = NativeManagedBackend()
                runtime._backend = native
                runtime._view = RuntimeView(phase='preparing')
                config = Config(25001,25002,'203.0.113.1','https://example.test')
                selection = BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\data','Default')
                binding = BrowserBinding(selection.chrome_executable,selection.user_data_dir,'Default','fixture',101,1000,((102,1001),))
                plan = SimpleNamespace(target=session_binding.DedicatedTarget(binding.executable,binding.user_data_dir),
                                       digest='a'*64,deployment_id='fixture',relay_port=45678)
                relay, monitor, probe, guard, bridge = (Mock() for _ in range(5))
                relay.reserve.return_value = SimpleNamespace(endpoint=('127.0.0.1',45678))
                probe.binding.return_value = binding
                monitor.accept_manager_sample.return_value = True
                monitor.accept_exit_sample.return_value = True
                monitor.issue_forward_lease.return_value = None if case=='lease_rejected' else object()
                original = OSError('SECRET original initialization failure')
                if case=='guard_error':
                    guard.read.side_effect = original
                else:
                    guard.read.return_value = SimpleNamespace(policy=object())
                if case=='promote_error':
                    relay.promote.side_effect = original
                replacements = (
                    (browser,'inspect_production_target',()), (core,'detect',SimpleNamespace(ready=True,_owner_evidence=('fixture',))),
                    (session_relay,'SessionRelay',relay), (wfp,'prepare_plan',plan), (wfp,'apply_plan',None),
                    (wfp,'plan_objects',[]), (wfp,'PolicyReadbackVerifier',Mock()),
                    (browser,'prepare_production_launch',SimpleNamespace(launch=SimpleNamespace(fingerprint=('fixture',)))),
                    (browser,'ProductionSessionGrant',Mock()), (session_relay,'ProductionBootstrapBridge',bridge),
                    (browser,'launch_production_probe',probe), (managed_session,'LayeredMonitorSession',monitor),
                    (ri,'WindowsSessionGuard',guard))
                mocks = {}
                for module,name,value in replacements:
                    mocks[name] = stack.enter_context(patch.object(module,name,return_value=value))
                if case=='success':
                    self.assertIs(native.initialize(config,selection,'a'*64,runtime.budget,runtime._cancel,runtime.journal_path), monitor)
                    runtime._record_guard_diagnostic(native,native._guard_trace,runtime._cancel,'accepted')
                else:
                    with self.assertRaises((OSError,ValueError)) as caught:
                        native.initialize(config,selection,'a'*64,runtime.budget,runtime._cancel,runtime.journal_path)
                    if case != 'lease_rejected':
                        self.assertIs(caught.exception,original)
                    runtime._trip(native.failure_reason,guard_error=caught.exception)
                    relay.stop.assert_called_once()
                detail = runtime.current().guard_diagnostic
                self.assertEqual(detail.scope,'initialization')
                self.assertEqual(detail.sample_sequence,0)
                stages = [step.stage for step in detail.steps]
                self.assertEqual(stages[0],'guard_read')
                self.assertEqual('relay_promote' in stages,case in ('success','promote_error'))
                if case=='promote_error':
                    self.assertEqual(detail.steps[-1].status,'raised')
                if case=='lease_rejected':
                    relay.promote.assert_not_called()
                self.assertEqual(mocks['WindowsSessionGuard'].call_args.kwargs['budget_seconds'],.5)
                self.assertEqual(mocks['WindowsSessionGuard'].call_args.kwargs['lease_seconds'],2.)
                self.assertNotIn('SECRET',repr(detail))

    def test_initialization_exception_and_cancel_use_original_runtime_cleanup(self):
        for cancelled in (False,True):
            with self.subTest(cancelled=cancelled), tempfile.TemporaryDirectory() as folder:
                runtime = ManagedSessionRuntime(journal_path=Path(folder)/'absent.json')
                class Backend:
                    failure_reason = 'initial_guard_failed'
                    def initialize(inner,*args):
                        inner._guard_trace = ri._new_guard_trace(time.monotonic(),.5,0,'initialization')
                        with ri._guard_scope(inner._guard_trace), ri._guard_stage('guard_read'):
                            if cancelled:
                                runtime.request_stop()
                            raise ValueError('SECRET preparation exception')
                    def revoke(inner):
                        pass
                    def cleanup(inner,*,quiescent):
                        return quiescent
                runtime._factory = Backend
                runtime._view = RuntimeView(phase='preparing')
                runtime._run()
                detail = runtime.current().guard_diagnostic
                self.assertEqual(detail.scope,'initialization')
                self.assertEqual(detail.outcome,'cancelled' if cancelled else 'exception')
                self.assertEqual(runtime.current().reason_code,'user_stopped' if cancelled else 'initial_guard_failed')
                self.assertEqual(runtime.current().cleanup_status,'confirmed')


if __name__ == '__main__':
    unittest.main()
