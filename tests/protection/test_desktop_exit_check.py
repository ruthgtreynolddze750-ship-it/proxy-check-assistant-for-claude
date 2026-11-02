"""Desktop protection: a fast exit check every 5 s keeps the 30 s exit evidence; full samples keep 60 s."""
import tempfile
import time
import unittest
from pathlib import Path

from src.protection.desktop_session import DesktopBudget, DesktopProtectionRuntime, DesktopView
from src.ui.desktop_presentation import desktop_report_lines, reason_label
from test_desktop_protection import CFG, FakeBackend, wait_for

APP_ID = 'Claude_pzs8sxrjxfjjc!Claude'

# Scaled from the real run: a full sample (1.3 s) is far longer than ttl/2, as 13 s is against 30 s.
SLOW = DesktopBudget(guard_interval_seconds=0.02, guard_budget_seconds=0.2, lease_seconds=0.5,
                     manager_interval_seconds=0.5, manager_budget_seconds=1.4, exit_ttl_seconds=3.0,
                     exit_check_interval_seconds=0.05, exit_check_budget_seconds=1.0, manager_max_age_seconds=6.0,
                     exit_wait_poll_seconds=0.02)


class ExitCheckRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.backend = FakeBackend()
        self.runtime = DesktopProtectionRuntime(journal_path=Path(self.temp.name) / 'desktop-recovery.json',
                                                budget=SLOW, backend=self.backend)

    def tearDown(self):
        self.runtime.abandon()
        self.temp.cleanup()

    def start_slow(self):
        self.assertTrue(self.runtime.request_start(CFG, APP_ID, 'r1'))
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'running'), self.runtime.current())
        self.backend.detect_delay = 1.3

    def fused(self, reason):
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'fused', 10), self.runtime.current())
        self.assertEqual(self.runtime.current().reason_code, reason)
        self.assertEqual(self.backend.relay.state, 'paused')
        self.assertEqual(self.backend.rolled_back, 0)

    def test_slow_full_samples_no_longer_expire_the_exit_evidence(self):
        self.start_slow()
        time.sleep(4.5)
        view = self.runtime.current()
        self.assertEqual(view.phase, 'running', view)
        self.assertEqual(self.backend.relay.state, 'forwarding')
        self.assertGreater(view.exit_sequence, 10)
        self.assertGreaterEqual(view.manager_sequence, 2)

    def test_exit_mismatch_in_the_fast_check_fuses_at_once(self):
        self.start_slow()
        self.backend.exit_status = 'fail'
        self.fused('target_exit_mismatch')

    def test_unconfirmed_fast_checks_until_expiry_fuse(self):
        self.start_slow()
        self.backend.exit_status = 'unknown'
        self.fused('exit_evidence_expired')

    def test_full_sample_evidence_has_its_own_expiry(self):
        self.start_slow()
        time.sleep(0.2)
        with self.runtime._lock:
            self.runtime._manager_expires = time.monotonic() - 1
        self.fused('manager_evidence_expired')

    def test_slow_fast_check_is_a_timeout(self):
        self.start_slow()
        original = self.backend.exit_check

        def slow(config):
            time.sleep(1.5)
            return original(config)
        self.backend.exit_check = slow
        self.fused('exit_timeout')


class BudgetTests(unittest.TestCase):
    def test_defaults_are_the_approved_limits(self):
        budget = DesktopBudget()
        self.assertEqual((budget.exit_check_interval_seconds, budget.exit_check_budget_seconds,
                          budget.exit_ttl_seconds, budget.manager_max_age_seconds), (5.0, 10.0, 30.0, 60.0))

    def test_limits_that_cannot_refresh_in_time_are_refused(self):
        for changes in ({'exit_check_budget_seconds': 12.5}, {'exit_check_interval_seconds': 10.0},
                        {'manager_budget_seconds': 28.0}, {'manager_max_age_seconds': 61.0},
                        {'exit_ttl_seconds': 31.0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DesktopBudget(**changes)


class ExitCheckTextTests(unittest.TestCase):
    def test_report_counts_exit_checks(self):
        view = DesktopView(phase='running', reason_code='protecting', manager_sequence=3, exit_sequence=17,
                           exit_expires_at=100.0)
        lines = desktop_report_lines(view, 90.0, lambda when: when.isoformat())
        self.assertIn('出口证据：剩余 10.0 秒 · 出口核验 17 次 · 管理器采样 3 次', lines)

    def test_new_reasons_have_labels(self):
        self.assertEqual(reason_label('exit_timeout'), '快速出口核验超时')
        self.assertEqual(reason_label('manager_evidence_expired'), '完整检测证据已过期')
        self.assertEqual(reason_label('exit_check_failed'), '快速出口核验异常')


if __name__ == '__main__':
    unittest.main()
