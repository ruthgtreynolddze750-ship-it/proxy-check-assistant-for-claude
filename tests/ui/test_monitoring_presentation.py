import sys
import time
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from src.core.monitoring import MonitorEvent, MonitorSnapshot
from ui.monitoring_presentation import present_snapshot


class MonitorPresentationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.snapshot = MonitorSnapshot('monitoring', 'not_enabled', self.now, self.now, (), 2, (), 'PRIVATE_RAW_MESSAGE')

    def test_core_snapshot_is_rendered_without_claiming_protection(self):
        view = present_snapshot(self.snapshot)
        self.assertEqual(view.state_label, '正在监测')
        self.assertEqual(view.protection_label, '未启用')
        self.assertTrue(view.evidence_current)
        self.assertNotIn('PRIVATE_RAW_MESSAGE', repr(view))

    def test_alarm_and_unverified_protection_are_never_promoted(self):
        alarm = replace(self.snapshot, state='alarm', protection='protected', reason_codes=('exit_ip_mismatch',))
        view = present_snapshot(alarm)
        self.assertEqual(view.state_label, '发现异常')
        self.assertEqual(view.protection_label, '未确认')
        self.assertFalse(view.evidence_current)
        self.assertIn('独立出口与预期不一致', view.reason_labels)

    def test_browser_scope_and_current_status_are_distinct(self):
        independent = present_snapshot(self.snapshot)
        self.assertIn('独立代理请求', '\n'.join(independent.report_lines()))
        self.assertIn('浏览器本次绑定：未确认', '\n'.join(independent.report_lines()))
        bound = replace(self.snapshot, scope='dedicated_browser', browser_status='pass')
        view = present_snapshot(bound)
        self.assertTrue(view.evidence_current)
        self.assertIn('浏览器本次绑定：通过', '\n'.join(view.report_lines()))
        self.assertFalse(present_snapshot(replace(bound, browser_status='unknown')).evidence_current)
        with self.assertRaises(ValueError):
            present_snapshot(replace(self.snapshot, browser_status='pass'))
        with self.assertRaises(ValueError):
            present_snapshot(replace(bound, scope='PRIVATE_RAW_VALUE'))

    def test_browser_reason_codes_have_fixed_safe_labels(self):
        reasons = ('browser_binding_changed', 'browser_check_pass', 'browser_evidence_expired',
                   'browser_evidence_invalid', 'browser_evidence_unconfirmed', 'browser_exit_mismatch',
                   'browser_identity_unconfirmed', 'browser_provider_error', 'browser_provider_missing',
                   'browser_proxy_mismatch', 'browser_request_unconfirmed', 'browser_sample_mismatch',
                   'browser_profile_unconfirmed', 'browser_profile_mismatch')
        view = present_snapshot(replace(self.snapshot, state='alarm', reason_codes=reasons,
                                        scope='dedicated_browser'))
        self.assertEqual(len(set(view.reason_labels)), len(reasons))
        self.assertNotIn('监测异常，原因未确认', view.reason_labels)
        self.assertNotIn('browser_', '\n'.join(view.report_lines()))

    def test_unknown_reason_and_action_never_copy_raw_values(self):
        event = MonitorEvent(self.now, 'password=PRIVATE_TEST_VALUE', 'cookie=PRIVATE_TEST_VALUE', 1)
        snapshot = replace(self.snapshot, state='alarm', reason_codes=('PRIVATE_TEST_VALUE',), events=(event,))
        view = present_snapshot(snapshot)
        self.assertNotIn('PRIVATE_TEST_VALUE', repr(view))
        self.assertNotIn('PRIVATE_TEST_VALUE', '\n'.join(view.report_lines()))
        self.assertIn('发现异常，阻断未启用', '\n'.join(view.report_lines()))
        self.assertEqual(view.reason_labels, ('监测异常，原因未确认',))
        self.assertEqual(view.events[0].action_label, '处理结果未确认')

    def test_event_bound_and_required_fields_fail_closed(self):
        events = tuple(MonitorEvent(self.now, 'check_pass', 'monitor_only', i) for i in range(1, 130))
        with self.assertRaises(ValueError):
            present_snapshot(replace(self.snapshot, sequence=129, events=events))
        with self.assertRaises(ValueError):
            present_snapshot(SimpleNamespace(state='monitoring'))

    def test_regressing_or_reordered_sequences_fail_closed(self):
        with self.assertRaises(ValueError):
            present_snapshot(self.snapshot, previous_sequence=3)
        events = (MonitorEvent(self.now, 'started', 'monitor_only', 2),
                  MonitorEvent(self.now, 'check_pass', 'monitor_only', 1))
        with self.assertRaises(ValueError):
            present_snapshot(replace(self.snapshot, events=events))

    def test_monitoring_with_unconfirmed_last_success_is_not_healthy(self):
        view = present_snapshot(replace(self.snapshot, last_success_at=None))
        self.assertFalse(view.evidence_current)
        self.assertEqual(view.state_label, '监测状态未确认')

    def test_stopped_with_alarm_and_expired_evidence_remains_visible(self):
        snapshot = replace(self.snapshot, state='stopped', reason_codes=('evidence_expired',))
        view = present_snapshot(snapshot)
        self.assertEqual(view.state_label, '监测已停止，异常仍需手动复检')
        self.assertIn('监测证据：已过期', '\n'.join(view.report_lines()))
        self.assertFalse(view.evidence_current)

    def test_presentation_limits_retained_events_to_100(self):
        events = tuple(MonitorEvent(self.now, 'check_pass', 'monitor_only', i) for i in range(1, 129))
        view = present_snapshot(replace(self.snapshot, sequence=128, events=events))
        self.assertEqual(len(view.events), 100)
        self.assertEqual(view.events[0].sequence, 29)

    def test_real_core_session_with_simulated_detector_preserves_manual_recovery(self):
        from src.core import backend
        from src.core.monitoring import MonitorSession
        passed, failed = backend.Check('pass', ''), backend.Check('fail', 'PRIVATE_TEST_VALUE')
        state = {'fail': False}
        def detector(config):
            return backend.Detection(passed, passed, failed if state['fail'] else passed, passed,
                                     backend.Check('unknown', ''), mapping=passed,
                                     _owner_evidence=('synthetic',), target_trace=passed)
        config = backend.Config(proxy_port=12001, manager_port=12002, expected_ip='192.0.2.41',
                                ip_url='https://ip.example/check')
        session = MonitorSession(config, interval_seconds=.05, max_age_seconds=1, detector=detector)
        def wait_for(expected):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                snapshot = session.snapshot()
                if snapshot.state == expected:
                    return snapshot
                time.sleep(.01)
            self.fail('模拟会话未进入预期状态')
        try:
            with patch.object(backend, '_request_via_proxy') as request:
                session.start()
                successful = wait_for('monitoring')
                self.assertTrue(present_snapshot(successful).evidence_current)
                state['fail'] = True
                alarm = wait_for('alarm')
                view = present_snapshot(alarm)
                self.assertIn('独立出口与预期不一致', view.reason_labels)
                self.assertNotIn('PRIVATE_TEST_VALUE', '\n'.join(view.report_lines()))
                state['fail'] = False
                time.sleep(.12)
                self.assertEqual(session.snapshot().state, 'alarm')
                self.assertEqual(present_snapshot(session.stop()).state_label, '监测已停止，异常仍需手动复检')
                session.resume()
                self.assertTrue(present_snapshot(wait_for('monitoring')).evidence_current)
                request.assert_not_called()
        finally:
            session.stop()


if __name__ == '__main__':
    unittest.main()
