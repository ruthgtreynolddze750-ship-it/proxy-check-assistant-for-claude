"""R31: a manager sample cancelled by a stop is reported as interrupted, not as the first manager failure."""
from dataclasses import replace
import unittest

import test_manager_diagnostic_ui as md
from ui import monitoring_presentation as presentation

INTERRUPTED = '管理器采样被停止打断（界面记录时间，不是故障）：'
INTERRUPTED_NOTE = '监测停止后中断的采样，本身不代表故障'
FAILED = '管理器首次异常（界面记录时间）：'
FAILED_NOTE = '诊断记录；断连效果待真实验收'


def cancelled():
    return md.diagnostic(outcome='cancelled', checks=(), rejection_reason='', error_code='cancelled_or_deadline',
                         steps=(md.DetectionStep('manager', 'unknown', 2.33, 'cancelled_or_deadline'),))


class InterruptedPresentationTests(unittest.TestCase):
    def test_only_cancelled_outcome_is_interrupted_and_still_retained_as_failed(self):
        for outcome, interrupted in (('cancelled', True), ('rejected', False), ('exception', False),
                                     ('timeout', False), ('accepted', False), (md.PRIVATE, False)):
            with self.subTest(outcome=outcome[:9]):
                view = presentation.present_manager_diagnostic(md.diagnostic(outcome=outcome))
                self.assertIs(view.interrupted, interrupted)
                self.assertIs(view.failed, outcome != 'accepted')


class InterruptedEventTkTests(unittest.TestCase):
    make_app = md.ManagerDiagnosticTkTests.make_app
    setUp = md.ManagerDiagnosticTkTests.setUp
    tearDown = md.ManagerDiagnosticTkTests.tearDown
    start = md.ManagerDiagnosticTkTests.start
    history_text = md.ManagerDiagnosticTkTests.history_text

    def finish(self, detail, phase='idle', reason='user_stopped'):
        self.start()
        self.app.stop_monitor()
        self.runtime.view = replace(self.runtime.view, phase=phase, reason_code=reason,
                                    cleanup_status='confirmed', manager_diagnostic=detail)
        self.app._poll_monitor()
        self.app.refresh()
        return [event for event in self.app._monitor_events if '管理器' in event[1]]

    def test_stop_interrupted_sample_is_not_labelled_a_failure(self):
        events = self.finish(cancelled())
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0][1].startswith(INTERRUPTED))
        self.assertEqual(events[0][2], INTERRUPTED_NOTE)
        history = self.history_text()
        self.assertIn('不是故障', history)
        self.assertNotIn('首次异常', history)
        report = self.app._render_report()
        self.assertIn('管理器采样诊断：采样已取消', report)
        self.assertIn('取消或截止期限', report)
        self.assertNotIn('SECRET', report + history)

    def test_alarm_cancelled_sample_uses_same_wording(self):
        events = self.finish(cancelled(), phase='alarm', reason='relay_closed')
        self.assertTrue(events[0][1].startswith(INTERRUPTED))

    def assert_failure_wording(self, outcome):
        events = self.finish(md.diagnostic(outcome=outcome), phase='alarm', reason='manager_sample_failed')
        self.assertTrue(events[0][1].startswith(FAILED))
        self.assertEqual(events[0][2], FAILED_NOTE)

    def test_rejected_sample_keeps_first_failure_wording(self):
        self.assert_failure_wording('rejected')

    def test_exception_sample_keeps_first_failure_wording(self):
        self.assert_failure_wording('exception')

    def test_timeout_sample_keeps_first_failure_wording(self):
        self.assert_failure_wording('timeout')


if __name__ == '__main__':
    unittest.main()
