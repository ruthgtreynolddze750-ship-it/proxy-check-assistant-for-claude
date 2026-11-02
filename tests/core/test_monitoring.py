import math
import threading
import time
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from src.core import backend
from src.core.backend import Check, Config, Detection
from src.core.monitoring import MonitorSession


def detection(*, owner=('owner', 1), ip='pass', trace='pass', port='pass', mapping='pass'):
    ok = Check('pass', '通过')
    return Detection(ok, Check(port, '端口'), Check(ip, '出口'),
                     Check('unknown', '首页未确认'), Check('unknown', '桌面出口未确认'),
                     mapping=Check(mapping, '映射'), _owner_evidence=owner,
                     target_trace=Check(trace, '目标出口'))


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        self.sessions = []

    def session(self, detector, **kwargs):
        instance = MonitorSession(self.config, detector=detector, interval_seconds=kwargs.get('interval_seconds', 0.05),
                                  max_age_seconds=kwargs.get('max_age_seconds', 0.25))
        self.sessions.append(instance)
        return instance

    def tearDown(self):
        for instance in self.sessions:
            instance.stop()

    def await_state(self, instance, wanted, timeout=2):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = instance.snapshot()
            if result.state == wanted:
                return result
            threading.Event().wait(0.01)
        self.fail(f'未达到状态 {wanted}: {instance.snapshot().state}')

    def test_initialization_is_inert_and_snapshot_is_immutable(self):
        called = threading.Event()
        session = self.session(lambda config: called.set())
        result = session.snapshot()
        self.assertEqual((result.state, result.protection), ('stopped', 'not_enabled'))
        self.assertIsNone(result.checked_at)
        self.assertFalse(called.is_set())
        with self.assertRaises(FrozenInstanceError):
            result.state = 'monitoring'

    def test_periodic_success_is_not_protection_and_does_not_check_desktop_instance(self):
        calls = []
        session = self.session(lambda config: calls.append(config) or detection())
        session.start()
        result = self.await_state(session, 'monitoring')
        self.assertEqual(result.protection, 'not_enabled')
        self.assertIsNotNone(result.last_success_at)
        self.assertEqual(calls[0], self.config)
        self.assertTrue(all(e.action_code != 'blocked' for e in result.events))
        self.assertIn('阻断未启用', result.message)

    def test_default_detector_runs_common_checks_without_desktop_instance_check(self):
        passed = Check('pass', '通过')
        with patch.object(backend, '_proxy_owner_snapshot', return_value=('owner', 1)), \
             patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, 'desktop_status', side_effect=AssertionError('不应检查桌面实例')), \
             patch.object(backend, '_request_via_proxy', side_effect=[
                 b'203.0.113.1', backend.ProxyHTTPError(403), b'h=claude.ai\nip=203.0.113.1\n']):
            session = MonitorSession(self.config, interval_seconds=30, max_age_seconds=60)
            self.sessions.append(session)
            session.start()
            result = self.await_state(session, 'monitoring')
            session.stop()
        self.assertEqual(result.protection, 'not_enabled')

    def test_failure_latches_alarm_until_explicit_resume(self):
        calls = []
        mode = {'bad': False}
        def detect(config):
            calls.append(1)
            return detection(ip='fail' if mode['bad'] else 'pass')
        session = self.session(detect)
        session.start()
        self.await_state(session, 'monitoring')
        mode['bad'] = True
        result = self.await_state(session, 'alarm')
        self.assertIn('exit_ip_mismatch', result.reason_codes)
        self.assertEqual(result.protection, 'not_enabled')
        count = len(calls)
        mode['bad'] = False
        threading.Event().wait(0.15)
        self.assertEqual(len(calls), count)
        self.assertEqual(session.snapshot().state, 'alarm')
        session.resume()
        self.await_state(session, 'monitoring')

    def test_owner_change_latches_alarm(self):
        calls = []
        def detect(config):
            calls.append(1)
            return detection(owner=('owner', len(calls)))
        session = self.session(detect)
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('owner_changed', result.reason_codes)

    def test_manual_resume_can_adopt_freshly_verified_owner(self):
        owner = [('owner', 1)]
        session = self.session(lambda config: detection(owner=owner[0]))
        session.start()
        self.await_state(session, 'monitoring')
        owner[0] = ('owner', 2)
        result = self.await_state(session, 'alarm')
        self.assertIn('owner_changed', result.reason_codes)
        session.resume()
        self.await_state(session, 'monitoring')

    def test_target_exit_mismatch_or_unknown_never_claims_protection(self):
        for status, reason in [('fail', 'target_exit_mismatch'), ('unknown', 'evidence_unconfirmed')]:
            with self.subTest(status=status):
                session = self.session(lambda config: detection(trace=status))
                session.start()
                result = self.await_state(session, 'alarm')
                self.assertIn(reason, result.reason_codes)
                self.assertEqual(result.protection, 'not_enabled')
                self.assertIn('阻断未启用', result.message)

    def test_stop_and_start_do_not_clear_latched_alarm(self):
        mode, calls = {'bad': True}, []
        def detect(config):
            calls.append(1)
            return detection(ip='fail' if mode['bad'] else 'pass')
        session = self.session(detect)
        session.start()
        self.await_state(session, 'alarm')
        session.stop()
        before = len(calls)
        mode['bad'] = False
        self.assertEqual(session.start().state, 'alarm')
        self.assertEqual(len(calls), before)
        session.resume()
        self.await_state(session, 'monitoring')

    def test_backward_clock_is_latched_as_unknown(self):
        tick = [10.0]
        def detect(config):
            tick[0] = 9.0
            return detection()
        session = MonitorSession(self.config, detector=detect, clock=lambda: tick[0],
                                 interval_seconds=0.05, max_age_seconds=0.2)
        self.sessions.append(session)
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('clock_unavailable', result.reason_codes)
        self.assertEqual(result.protection, 'not_enabled')

    def test_malformed_detector_result_is_latched_without_retries(self):
        calls = []
        def malformed(config):
            calls.append(1)
            return Detection(None, Check('pass', 'x'), Check('pass', 'x'), Check('pass', 'x'),
                             Check('unknown', 'x'), _owner_evidence=('owner', 1))
        session = self.session(malformed)
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('detector_error', result.reason_codes)
        count = len(calls)
        threading.Event().wait(0.1)
        self.assertEqual(len(calls), count)

    def test_hung_detector_expires_without_spawning_more_workers(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        calls = []
        def detect(config):
            calls.append(1)
            entered.set()
            gate.wait(3)
            return detection()
        session = self.session(detect, max_age_seconds=0.12)
        session.start()
        self.assertTrue(entered.wait(1))
        result = self.await_state(session, 'alarm')
        self.assertIn('check_timeout', result.reason_codes)
        for _ in range(5):
            session.resume()
        self.assertEqual(len(calls), 1)
        before = time.monotonic()
        session.stop()
        self.assertLess(time.monotonic() - before, 0.2)
        gate.set()
        threading.Event().wait(0.05)
        self.assertEqual(session.snapshot().state, 'stopped')

    def test_late_first_result_cannot_succeed_when_clock_has_advanced(self):
        tick = [0.0]
        def detect(config):
            tick[0] = 10.0
            return detection()
        session = MonitorSession(self.config, detector=detect, clock=lambda: tick[0],
                                 interval_seconds=0.05, max_age_seconds=0.2)
        self.sessions.append(session)
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('check_timeout', result.reason_codes)
        self.assertIsNone(result.last_success_at)

    def test_slow_success_expires_from_start_not_completion(self):
        tick = [0.0]
        def detect(config):
            tick[0] = 9.0
            return detection()
        session = MonitorSession(self.config, detector=detect, clock=lambda: tick[0],
                                 interval_seconds=20, max_age_seconds=10)
        self.sessions.append(session)
        session.start()
        result = self.await_state(session, 'monitoring')
        self.assertIsNotNone(result.checked_at)
        self.assertEqual(result.checked_at, result.last_success_at)
        tick[0] = 9.9
        self.assertEqual(session.snapshot().state, 'monitoring')
        tick[0] = 10.0
        result = session.snapshot()
        self.assertEqual(result.state, 'alarm')
        self.assertIn('evidence_expired', result.reason_codes)
        self.assertEqual(result.protection, 'not_enabled')

    def test_restart_while_previous_detector_is_blocked_never_starts_a_second(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        calls = []
        def detect(config):
            calls.append(1)
            entered.set()
            gate.wait(2)
            return detection()
        session = self.session(detect)
        session.start()
        self.assertTrue(entered.wait(1))
        session.stop()
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('previous_check_running', result.reason_codes)
        self.assertEqual(len(calls), 1)
        gate.set()
        threading.Event().wait(0.05)
        self.assertEqual(session.snapshot().state, 'alarm')

    def test_fresh_success_expires_if_next_detection_hangs(self):
        gate, second_started = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        calls = []
        def detect(config):
            calls.append(1)
            if len(calls) > 1:
                second_started.set()
                gate.wait(2)
            return detection()
        session = self.session(detect, interval_seconds=0.04, max_age_seconds=0.15)
        session.start()
        self.await_state(session, 'monitoring')
        self.assertTrue(second_started.wait(1))
        result = self.await_state(session, 'alarm')
        self.assertIn('evidence_expired', result.reason_codes)
        self.assertIsNotNone(result.last_success_at)

    def test_events_are_bounded_and_never_expose_configuration(self):
        session = self.session(lambda config: detection())
        for _ in range(150):
            session.start()
            session.stop()
        snapshot = session.snapshot()
        self.assertLessEqual(len(snapshot.events), 128)
        self.assertEqual(list(e.sequence for e in snapshot.events), sorted(e.sequence for e in snapshot.events))
        self.assertNotIn(self.config.expected_ip, repr(snapshot))
        self.assertNotIn(self.config.ip_url, repr(snapshot))

    def test_stopped_stale_result_never_revives_new_session(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        def detect(config):
            entered.set()
            gate.wait(2)
            return detection()
        session = self.session(detect)
        session.start()
        self.assertTrue(entered.wait(1))
        session.stop()
        stopped = session.snapshot()
        gate.set()
        threading.Event().wait(0.08)
        self.assertEqual(session.snapshot(), stopped)
        self.assertEqual(session.snapshot().state, 'stopped')

    def test_detector_failure_is_redacted_and_latched(self):
        def detect(config):
            raise OSError('private_test_value')
        session = self.session(detect)
        session.start()
        result = self.await_state(session, 'alarm')
        self.assertIn('detector_error', result.reason_codes)
        self.assertNotIn('private_test_value', repr(result))

    def test_worker_creation_failure_alarms_without_retry_or_raw_error(self):
        session = self.session(lambda config: detection())
        real_start = threading.Thread.start
        def start(thread):
            if thread.name == 'claude-monitor-check':
                raise RuntimeError('private_test_value')
            return real_start(thread)
        with patch.object(threading.Thread, 'start', start):
            session.start()
            result = self.await_state(session, 'alarm')
        self.assertIn('detector_error', result.reason_codes)
        self.assertNotIn('private_test_value', repr(result))

    def test_invalid_periods_rejected_without_starting(self):
        for value in (0, -1, True, math.inf, math.nan, 10**1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MonitorSession(self.config, interval_seconds=value)
            with self.subTest(max_age=value), self.assertRaises(ValueError):
                MonitorSession(self.config, max_age_seconds=value)


if __name__ == '__main__':
    unittest.main()
