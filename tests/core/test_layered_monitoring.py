import unittest
import threading
from dataclasses import replace
from types import SimpleNamespace
from src.core.backend import Config, Check, Detection
from src.core import monitoring as m


class LayeredEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(m, 'LayeredMonitorSession'), '缺少明确的生产分层证据签发器')
        self.now = 100.0
        self.config = Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        self.binding = m.BrowserBinding(r'C:\owned\chrome.exe', r'C:\owned-data', 'Default',
                                        'owned-generation', 101, 1000, ((102, 1001),))
        self.owner = (25002, 25001, 501, '900', r'c:\pm.exe', 'a'*64)
        self.exits, self.guards = [], []
        self.monitor = m.LayeredMonitorSession(self.config, browser_binding=self.binding,
            binding_key=('a'*64, 101, 1000, 'owned-generation'), clock=lambda: self.now,
            exit_validator=lambda value: any(value is v for v in self.exits),
            guard_validator=lambda value: any(value is v for v in self.guards))
        self.monitor.start()
        ok = Check('pass', '合成证据')
        self.detection = Detection(ok, ok, ok, ok, Check('unknown', '未验'), mapping=ok,
                                   target_trace=ok, _owner_evidence=self.owner)
        self.monitor.accept_manager_sample(self.detection, started_at=99, completed_at=100)
        self.exit = m.BrowserBindingEvidence(self.binding, 'exit-1', 100, 'pass', 'pass', 'pass',
            25001, self.owner, '203.0.113.1', source='runtime', expires_at=130,
            request_profile_status='pass', request_profile_directory='Default',
            request_profile_source='selected_profile_context')
        self.exits.append(self.exit)
        self.assertTrue(self.monitor.accept_exit_sample(self.exit))

    def guard(self, sequence):
        policy = SimpleNamespace(sampled_at=self.now, expires_at=self.now+5, revoked=threading.Event())
        item = m.LocalGuardEvidence(self.binding, self.owner, sequence, self.now, self.now,
                                    self.now+2, policy)
        self.guards.append(item)
        return item

    def test_fresh_local_guard_never_extends_original_exit_deadline(self):
        first = self.monitor.issue_forward_lease(self.guard(1))
        self.assertEqual(first.expires_at, 102)
        self.assertFalse(self.monitor.accepts_relay_lease(replace(first)))
        for tick in range(101, 130):
            self.now = float(tick)
            self.assertIsNotNone(self.monitor.issue_forward_lease(self.guard(tick)))
        self.now = 129.5
        latest = self.monitor.issue_forward_lease(self.guard(130))
        self.assertEqual(latest.expires_at, 130)
        self.assertEqual(latest.sample_id, first.sample_id)
        self.assertGreater(latest.sequence, first.sequence)
        self.now = 130
        self.assertIsNone(self.monitor.issue_forward_lease(self.guard(131)))
        self.assertEqual(self.monitor.snapshot().state, 'alarm')
        self.assertFalse(self.monitor.accepts_relay_lease(latest))

    def test_copied_exit_result_and_repeated_guard_do_not_create_new_evidence(self):
        self.assertFalse(self.monitor.accept_exit_sample(replace(self.exit)))
        self.assertEqual(self.monitor.snapshot().state, 'alarm')

    def test_guard_replay_is_rejected_without_updating_lease_sequence(self):
        guard = self.guard(1)
        first = self.monitor.issue_forward_lease(guard)
        self.assertIsNone(self.monitor.issue_forward_lease(guard))
        self.assertTrue(self.monitor.accepts_relay_lease(first))

    def test_manager_failure_revokes_live_lease_without_waiting_for_exit_expiry(self):
        lease = self.monitor.issue_forward_lease(self.guard(1))
        bad = replace(self.detection, mapping=Check('unknown', '未确认'))
        self.assertFalse(self.monitor.accept_manager_sample(bad, started_at=100, completed_at=100))
        self.assertTrue(lease.revoked.is_set())
        self.assertEqual(self.monitor.snapshot().state, 'alarm')

    def test_stop_cannot_be_undone_by_late_worker_or_direct_resume(self):
        self.monitor.stop()
        self.assertFalse(self.monitor.accept_exit_sample(self.exit))
        self.assertIsNone(self.monitor.issue_forward_lease(self.guard(1)))
        self.monitor.resume()
        self.assertNotEqual(self.monitor.snapshot().state, 'monitoring')


if __name__ == '__main__':
    unittest.main()
