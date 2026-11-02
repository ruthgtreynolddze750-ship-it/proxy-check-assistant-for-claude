"""Manager failure provenance; all OS/network boundaries are injected."""
from dataclasses import replace
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import backend
from src.browser.inspection import BrowserSelection
from src.protection.managed_session import ManagedSessionRuntime, RuntimeView, SamplingBudget, NativeManagedBackend
from test_managed_session import SyntheticSessionBackend


class ManagerDiagnosticsTests(unittest.TestCase):
    def runtime(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        runtime = ManagedSessionRuntime(journal_path=Path(folder.name)/'absent.json')
        config = backend.Config(25001,25002,'203.0.113.1','https://example.test/ip')
        selection = BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\owned-data','Default')
        adapter = SyntheticSessionBackend()
        session = adapter.initialize(config,selection,'a'*64,SamplingBudget(),runtime._cancel,runtime.journal_path)
        self.addCleanup(session.stop)
        runtime._backend,runtime._session,runtime._config = adapter,session,config
        runtime._view = RuntimeView(phase='running',reason_code='monitoring')
        return runtime,adapter

    def test_failed_subcheck_and_rejection_survive_runtime_alarm_without_sensitive_text(self):
        for field in ('manager','port','exit_ip','target_trace','mapping'):
            with self.subTest(field=field):
                runtime,adapter = self.runtime()
                good = adapter.check_manager(runtime._config,time.monotonic()+25)
                bad = replace(good,**{field:backend.Check('unknown','SECRET 198.51.100.2 password=hidden')})
                adapter.check_manager = lambda *a:bad
                runtime._sample_loop('manager',0,5,25)
                detail = getattr(runtime.current(),'manager_diagnostic',None)
                self.assertIsNotNone(detail,'failed detector detail must be retained')
                self.assertEqual(dict(detail.checks)[field],'unknown')
                self.assertEqual(detail.outcome,'rejected')
                self.assertEqual(detail.rejection_reason,'manager_sample_invalid')
                self.assertLess(detail.elapsed_seconds,detail.budget_seconds)
                self.assertNotIn('SECRET',repr(detail))
                self.assertNotIn('198.51.100.2',repr(detail))
                self.assertTrue(adapter.closed)

    def test_first_failure_is_not_overwritten_by_another_worker(self):
        runtime,adapter = self.runtime()
        runtime._trip('manager_sample_failed')
        runtime._trip('relay_closed')
        self.assertEqual(runtime.current().reason_code,'manager_sample_failed')
        self.assertEqual(runtime._session.snapshot().reason_codes,('manager_sample_failed',))

    def test_detect_retains_swallowed_timeout_phase_and_thread_scope_is_restored(self):
        self.assertIn('diagnostics',__import__('inspect').signature(backend.detect).parameters)
        good = backend.Check('pass','synthetic')
        config = backend.Config(25001,25002,'203.0.113.1','https://example.test/ip')
        owner = (25002,25001,501,'900',r'C:\pm.exe','a'*64)
        steps = []
        with patch.object(backend,'_proxy_owner_snapshot',return_value=owner), \
             patch.object(backend,'_process_present',side_effect=TimeoutError('SECRET /private/path')), \
             patch.object(backend,'_port',return_value=good), \
             patch.object(backend,'_request_via_proxy',return_value=b'203.0.113.1'), \
             patch.object(backend,'_inspect_claude_trace_request',return_value=good):
            result = backend.detect(config,deadline=time.monotonic()+25,cancelled=threading.Event(),diagnostics=steps)
        self.assertFalse(result.ready)
        manager = next(step for step in steps if step.stage=='manager')
        self.assertEqual(manager.status,'unknown')
        self.assertEqual(manager.error_code,'timeout')
        self.assertGreaterEqual(manager.elapsed_seconds,0)
        self.assertNotIn('SECRET',repr(steps))
        self.assertIsNone(getattr(backend._REQUEST_SCOPE,'steps',None))

    def test_native_adapter_preserves_progress_if_detect_raises(self):
        self.assertIn('diagnostics',__import__('inspect').signature(backend.detect).parameters)
        adapter = NativeManagedBackend()
        adapter.cancel = threading.Event()
        def detect(config,**kwargs):
            kwargs['diagnostics'].append(backend.DetectionStep('owner_before','running',0,''))
            raise backend.DetectionCancelled('secret raw message')
        with patch.object(backend,'detect',side_effect=detect),self.assertRaises(backend.DetectionCancelled):
            adapter.check_manager(object(),time.monotonic()+25)
        self.assertEqual(adapter.manager_steps[0].stage,'owner_before')

    def test_expired_budget_records_timeout_without_changing_stop_behavior(self):
        runtime,adapter = self.runtime()
        clock = [time.monotonic()]
        def expired(*args):
            clock[0] += 26
            raise TimeoutError('SECRET upstream token')
        adapter.check_manager = expired
        with patch('src.protection.managed_session.time.monotonic',side_effect=lambda:clock[0]):
            runtime._sample_loop('manager',0,5,25)
        detail = runtime.current().manager_diagnostic
        self.assertEqual(detail.outcome,'timeout')
        self.assertGreaterEqual(detail.elapsed_seconds,detail.budget_seconds)
        self.assertEqual(detail.error_code,'timeout')
        self.assertEqual(runtime.current().reason_code,'manager_sample_timeout')
        self.assertTrue(adapter.closed)
        self.assertNotIn('SECRET',repr(detail))

    def test_diagnostic_scopes_are_independent_between_detector_threads(self):
        barrier = threading.Barrier(2)
        records, failures = {}, []
        def fake_detect(config, reference_home=True, retry_exit_ip=False, retry_target_trace=False):
            def sample():
                barrier.wait(1)
                if config.proxy_port == 25001:
                    backend._note_detection_error(TimeoutError('SECRET'))
                    return backend.Check('unknown','synthetic')
                return backend.Check('pass','synthetic')
            return backend._detection_step('manager',sample)
        def run(port):
            try:
                steps=[]
                backend.detect(backend.Config(port,25002,'203.0.113.1','https://example.test'),
                    deadline=time.monotonic()+25,cancelled=threading.Event(),diagnostics=steps)
                records[port]=(tuple(steps),getattr(backend._REQUEST_SCOPE,'steps',None))
            except BaseException as error:
                failures.append(type(error).__name__)
        with patch.object(backend,'_detect',side_effect=fake_detect):
            workers=[threading.Thread(target=run,args=(port,)) for port in (25001,25003)]
            for worker in workers:worker.start()
            for worker in workers:worker.join(2)
        self.assertFalse(failures)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(records[25001][0][0].error_code,'timeout')
        self.assertEqual(records[25003][0][0].error_code,'')
        self.assertIsNone(records[25001][1])
        self.assertIsNone(records[25003][1])


if __name__ == '__main__':
    unittest.main()
