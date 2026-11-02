"""Production lifecycle checks with injected local adapters; never a real browser or WFP."""
import importlib.util
import tempfile
import unittest
import threading
import time
import json
from pathlib import Path
from unittest.mock import Mock, patch
from src.core.backend import Config, Check, Detection
from src.core.monitoring import BrowserBinding, BrowserBindingEvidence, LayeredMonitorSession, LocalGuardEvidence
from src.protection.session_relay import RelaySnapshot
from types import SimpleNamespace
from src.browser.inspection import BrowserSelection


class SyntheticSessionBackend:
    def __init__(self):
        self.closed = False
        self.sequence = 0
        self.exits, self.guards = [], []

    def initialize(self, config, selection, fingerprint, budget, cancel, journal):
        self.config, self.cancel = config, cancel
        self.binding = BrowserBinding(selection.chrome_executable, selection.user_data_dir,
            selection.profile_directory, 'synthetic-generation', 101, 1000, ((102, 1001),))
        self.owner = (config.manager_port, config.proxy_port, 501, '900', r'C:\pm.exe', 'a'*64)
        self.monitor = LayeredMonitorSession(config, browser_binding=self.binding,
            binding_key=(fingerprint,101,1000,'synthetic-generation'),
            exit_validator=lambda value: any(value is item for item in self.exits),
            guard_validator=lambda value: any(value is item for item in self.guards))
        self.monitor.start()
        started = time.monotonic()
        self.monitor.accept_manager_sample(self.check_manager(config, started+1),
                                           started_at=started, completed_at=time.monotonic())
        self.monitor.accept_exit_sample(self.collect_exit('first-exit'))
        self.monitor.issue_forward_lease(self.read_guard())
        return self.monitor

    def check_manager(self, config, deadline):
        ok = Check('pass', 'synthetic')
        return Detection(ok,ok,ok,ok,Check('unknown','unverified'),mapping=ok,target_trace=ok,
                         _owner_evidence=self.owner)

    def collect_exit(self, sample_id):
        now = time.monotonic()
        evidence = BrowserBindingEvidence(self.binding,sample_id,now,'pass','pass','pass',
            self.config.proxy_port,self.owner,self.config.expected_ip,source='runtime',expires_at=now+30,
            request_profile_status='pass',request_profile_directory='Default',
            request_profile_source='selected_profile_context')
        self.exits.append(evidence)
        return evidence

    def open_selected_url(self, url):
        self.opened_url = url

    def read_guard(self):
        now = time.monotonic()
        self.sequence += 1
        policy = SimpleNamespace(sampled_at=now,expires_at=now+5,revoked=threading.Event())
        guard = LocalGuardEvidence(self.binding,self.owner,self.sequence,now,now,now+2,policy)
        self.guards.append(guard)
        return guard

    def renew(self, lease, guard):
        return not self.closed and self.monitor.accepts_relay_lease(lease)

    def snapshot(self):
        return RelaySnapshot('closed' if self.closed else 'listening', 'synthetic',0,'local_test')

    def revoke(self):
        self.closed = True

    def cleanup(self, *, quiescent):
        return quiescent


class ManagedRuntimeTests(unittest.TestCase):
    def runtime_module(self):
        self.assertIsNotNone(importlib.util.find_spec('src.protection.managed_session'),
                             '正式生产会话运行时缺失')
        from src.protection import managed_session
        return managed_session

    def test_initialization_and_snapshot_do_not_start_external_or_system_operations(self):
        module = self.runtime_module()
        with tempfile.TemporaryDirectory() as folder:
            def forbidden(*args, **kwargs):
                self.fail('初始化或快照触发了系统/网络操作')
            with patch('ctypes.WinDLL', forbidden), patch('subprocess.Popen', forbidden), \
                    patch('socket.socket.connect', forbidden), patch('os.startfile', forbidden):
                runtime = module.ManagedSessionRuntime(journal_path=Path(folder) / 'recovery.json')
                view = runtime.current()
                self.assertEqual(view.phase, 'idle')
                self.assertIsNone(view.session)
                self.assertIsNone(view.browser_evidence)
                self.assertIsNone(view.relay_snapshot)
                self.assertEqual(view.cleanup_status, 'not_applicable')
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_approved_timing_limits_are_not_silently_relaxed(self):
        module = self.runtime_module()
        budget = module.SamplingBudget()
        self.assertEqual(budget.relay_max_lease_seconds, 2)
        self.assertEqual(budget.request_evidence_ttl_seconds, 30)
        self.assertLessEqual(budget.request_budget_seconds, 10)
        self.assertLessEqual(budget.interval_seconds, 5)
        self.assertEqual(budget.policy_max_age_seconds, 5)
        self.assertEqual(budget.max_age_seconds, 60)
        self.assertLess(2*budget.guard_budget_seconds+budget.identity_refresh_seconds,
                        budget.relay_max_lease_seconds)
        with self.assertRaises(ValueError):
            module.SamplingBudget(guard_budget_seconds=1)
        with self.assertRaises(ValueError):
            module.SamplingBudget(request_evidence_ttl_seconds=31)
        with self.assertRaises(ValueError):
            module.SamplingBudget(relay_max_lease_seconds=3)

    def test_stop_is_immediate_while_preparation_worker_is_blocked(self):
        module = self.runtime_module()
        entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
        class Backend:
            def initialize(self, *args):
                entered.set()
                release.wait(2)
                raise ValueError('cancelled preparation')
            def revoke(self):
                revoked.set()
            def cleanup(self, *, quiescent):
                return True
        with tempfile.TemporaryDirectory() as folder:
            runtime = module.ManagedSessionRuntime(journal_path=Path(folder)/'recovery.json',
                                                   backend_factory=Backend)
            config = Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
            selection = BrowserSelection('https://claude.ai/', r'C:\owned\chrome.exe', r'C:\owned-data', 'Default')
            try:
                runtime.request_start(config, selection, config_fingerprint='a'*64, request_id='start-1')
                self.assertTrue(entered.wait(1))
                before = time.monotonic()
                runtime.request_stop(None, 'stop-1')
                self.assertLess(time.monotonic()-before, 0.2)
                self.assertTrue(revoked.is_set())
                self.assertEqual(runtime.current().phase, 'stopping')
            finally:
                runtime.request_stop(None, 'cleanup-stop')
                release.set()
                if runtime._thread:
                    runtime._thread.join(2)
            self.assertEqual(runtime.current().cleanup_status, 'confirmed')
            self.assertEqual(runtime.current().phase, 'idle')

    def test_unresolved_receipt_blocks_start_without_loading_native_backend(self):
        module = self.runtime_module()
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder)/'recovery.json'
            receipt.write_text('{"state":"pending"}', encoding='utf-8')
            runtime = module.ManagedSessionRuntime(journal_path=receipt,
                backend_factory=lambda: self.fail('残留回执下不应启动系统能力'))
            runtime.request_start(Config(1,2,'203.0.113.1','https://example.test/ip'),
                BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\data','Default'),
                config_fingerprint='a'*64, request_id='start')
            self.assertEqual(runtime.current().phase, 'blocked')
            self.assertEqual(receipt.read_text(encoding='utf-8'), '{"state":"pending"}')

    def test_running_is_published_with_complete_evidence_and_stop_cannot_be_overwritten(self):
        module = self.runtime_module()
        entered, release = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory() as folder:
            runtime = module.ManagedSessionRuntime(journal_path=Path(folder)/'recovery.json',
                                                   backend_factory=SyntheticSessionBackend)
            publish = runtime._publish
            def paused():
                entered.set()
                release.wait(2)
                publish()
            runtime._publish = paused
            try:
                runtime.request_start(Config(25001,25002,'203.0.113.1','https://example.test/ip'),
                    BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\data','Default'),
                    config_fingerprint='a'*64,request_id='start')
                self.assertTrue(entered.wait(1))
                self.assertEqual(runtime.current().phase, 'preparing')
                runtime.request_stop(None, 'stop')
                self.assertEqual(runtime.current().phase, 'stopping')
            finally:
                release.set()
                if runtime._thread:
                    runtime._thread.join(2)
            self.assertEqual(runtime.current().phase, 'idle')
            self.assertEqual(runtime.current().cleanup_status, 'confirmed')


class NativeCleanupTests(unittest.TestCase):
    def test_rollback_requires_quiescent_workers_and_confirmed_browser_exit(self):
        from src.protection.managed_session import NativeManagedBackend
        from src.protection import dedicated_wfp as wfp
        backend = NativeManagedBackend()
        backend.cancel = threading.Event()
        backend.probe = Mock()
        backend.probe._process.poll.return_value = 0
        backend.probe.exit_status.return_value = SimpleNamespace(status='unknown')
        backend.plan = SimpleNamespace(digest='a'*64)
        backend._owns_journal = True
        with patch.object(wfp,'rollback_plan') as rollback:
            self.assertFalse(backend.cleanup(quiescent=False))
            backend.probe.normal_close.assert_not_called()
            self.assertFalse(backend.cleanup(quiescent=True))
            backend.probe.normal_close.assert_called_once()
            rollback.assert_not_called()

    def test_confirmed_cleanup_rechecks_exact_objects_then_removes_only_own_journal(self):
        from src.protection.managed_session import NativeManagedBackend
        from src.protection import dedicated_wfp as wfp
        with tempfile.TemporaryDirectory() as folder:
            backend = NativeManagedBackend()
            backend.cancel = threading.Event()
            backend.probe, backend.relay = Mock(), Mock()
            backend.probe._process.poll.return_value = 0
            backend.probe.exit_status.return_value = SimpleNamespace(status='exited')
            backend.plan = SimpleNamespace(digest='a'*64)
            backend._owns_journal = True
            backend.journal = Path(folder)/'recovery.json'
            manifest = {'objects':({'kind':'filter','key':'owned-key'},)}
            backend.journal.write_text(json.dumps(manifest), encoding='utf-8')
            backend._manifest = lambda:manifest
            engine = Mock()
            engine.get.return_value = None
            events = []
            backend.relay.stop.side_effect = lambda:events.append('relay_closed')
            backend.probe.normal_close.side_effect = lambda:events.append('browser_closed')
            with patch.object(wfp,'rollback_plan',side_effect=lambda *a,**kw:events.append('rollback')), \
                    patch.object(wfp,'NativeWfp',return_value=engine), \
                    patch.object(wfp,'plan_objects',return_value=manifest['objects']):
                self.assertTrue(backend.cleanup(quiescent=True))
            self.assertEqual(events, ['relay_closed','browser_closed','rollback'])
            engine.get.assert_called_once_with('filter','owned-key')
            engine.close.assert_called_once()
            self.assertFalse(backend.journal.exists())


if __name__ == '__main__':
    unittest.main()
