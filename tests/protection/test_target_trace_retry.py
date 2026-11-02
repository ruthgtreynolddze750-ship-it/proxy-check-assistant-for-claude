"""Continuous monitoring retries the target trace request once after a connection-class error or a timeout;
start-up detection keeps a single attempt. All OS/network boundaries are injected."""
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import backend
from src.browser import request_probe as browser
from src.browser.inspection import BrowserSelection
from src.protection.desktop_session import NativeDesktopBackend
from src.protection.managed_session import NativeManagedBackend, SamplingBudget

OWNER = (25002, 25001, 501, '900', r'C:\pm.exe', 'a'*64)
TRACE_URL = 'https://claude.ai/cdn-cgi/trace'
GOOD = b'fl=1\nh=claude.ai\nip=203.0.113.1\n'


class Stop(Exception):
    pass


class TargetTraceRetryTests(unittest.TestCase):
    def setUp(self):
        self.config = backend.Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        passed = backend.Check('pass', 'synthetic')
        self.answers = []
        self.urls = []

        def request(port, url, timeout, **kwargs):
            self.urls.append(url)
            if url == self.config.ip_url:
                return b'203.0.113.1'
            if url != TRACE_URL:
                return b''
            answer = self.answers.pop(0) if self.answers else GOOD
            if isinstance(answer, BaseException):
                raise answer
            return answer
        for name, kwargs in (('_proxy_owner_snapshot', dict(return_value=OWNER)),
                             ('_manager', dict(return_value=passed)), ('_port', dict(return_value=passed)),
                             ('_mapping', dict(return_value=passed)),
                             ('_request_via_proxy', dict(side_effect=request))):
            patcher = patch.object(backend, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def bounded(self, seconds=25, **kwargs):
        steps = []
        result = backend.detect(self.config, deadline=time.monotonic()+seconds, cancelled=threading.Event(),
                                diagnostics=steps, reference_home=False, retry_exit_ip=True, **kwargs)
        return result, steps

    def trace_requests(self):
        return self.urls.count(TRACE_URL)

    def test_default_detection_keeps_single_trace_attempt(self):
        for run in (lambda: backend.detect(self.config), lambda: self.bounded()[0]):
            with self.subTest():
                self.urls.clear()
                self.answers[:] = [ConnectionResetError('SECRET'), GOOD]
                result = run()
                self.assertEqual(self.trace_requests(), 1)
                self.assertEqual(result.target_trace.status, 'unknown')

    def test_connection_error_or_timeout_is_retried_once(self):
        for error, code in ((ConnectionResetError('SECRET'), 'os_error'), (TimeoutError('SECRET'), 'timeout')):
            with self.subTest(code=code):
                self.urls.clear()
                self.answers[:] = [error, GOOD]
                result, steps = self.bounded(retry_target_trace=True)
                self.assertEqual(self.trace_requests(), 2)
                self.assertEqual(result.target_trace.status, 'pass')
                self.assertTrue(result.ready)
                traces = [step for step in steps if step.stage == 'target_trace']
                self.assertEqual([step.error_code for step in traces], [code, ''])
                self.assertEqual([step.status for step in traces], ['unknown', 'pass'])
                self.assertNotIn('SECRET', repr(steps))

    def test_retry_cannot_mask_a_mismatch_on_the_second_answer(self):
        self.answers[:] = [ConnectionResetError(), b'h=claude.ai\nip=198.51.100.9\n']
        result, _ = self.bounded(retry_target_trace=True)
        self.assertEqual(self.trace_requests(), 2)
        self.assertEqual(result.target_trace.status, 'fail')
        self.assertFalse(result.ready)

    def test_second_failure_stays_unconfirmed(self):
        self.answers[:] = [ConnectionResetError(), TimeoutError(), GOOD]
        result, steps = self.bounded(retry_target_trace=True)
        self.assertEqual(self.trace_requests(), 2)
        self.assertEqual(result.target_trace.status, 'unknown')
        self.assertFalse(result.ready)
        self.assertEqual([s.error_code for s in steps if s.stage == 'target_trace'], ['os_error', 'timeout'])

    def test_non_connection_outcomes_are_not_retried(self):
        cases = {'mismatch': (b'h=claude.ai\nip=198.51.100.9\n', 'fail'),
                 'wrong_host': (b'h=example.test\nip=203.0.113.1\n', 'unknown'),
                 'http_status': (backend.ProxyHTTPError(503), 'unknown'),
                 'invalid_data': (b'h=claude.ai\nip=not-an-ip\n', 'unknown'),
                 'oversize': (b'x' * 5000, 'unknown'),
                 'cancelled': (backend.DetectionCancelled(), 'unknown')}
        for name, (answer, status) in cases.items():
            with self.subTest(case=name):
                self.urls.clear()
                self.answers[:] = [answer, GOOD]
                result, _ = self.bounded(retry_target_trace=True)
                self.assertEqual(self.trace_requests(), 1)
                self.assertEqual(result.target_trace.status, status)
                self.assertFalse(result.ready)

    def test_no_retry_when_less_than_ten_seconds_remain(self):
        self.answers[:] = [ConnectionResetError(), GOOD]
        result, _ = self.bounded(seconds=9.5, retry_target_trace=True)
        self.assertEqual(self.trace_requests(), 1)
        self.assertEqual(result.target_trace.status, 'unknown')

    def test_cancelled_scope_is_not_retried(self):
        cancelled = threading.Event()

        def fail_then_cancel(port, url, timeout, **kwargs):
            self.urls.append(url)
            if url == self.config.ip_url:
                return b'203.0.113.1'
            cancelled.set()
            raise ConnectionResetError()
        with patch.object(backend, '_request_via_proxy', side_effect=fail_then_cancel):
            with self.assertRaises(backend.DetectionCancelled):
                backend.detect(self.config, deadline=time.monotonic()+25, cancelled=cancelled,
                               reference_home=False, retry_exit_ip=True, retry_target_trace=True)
        self.assertEqual(self.trace_requests(), 1)

    def test_both_retries_stay_within_the_sample_deadline(self):
        clock = [0.0]

        def slow(port, url, timeout, **kwargs):
            self.urls.append(url)
            clock[0] += 5.0
            if url == self.config.ip_url:
                if self.urls.count(url) == 1:
                    raise ConnectionResetError()
                return b'203.0.113.1'
            if self.urls.count(url) == 1:
                raise TimeoutError()
            return GOOD
        with patch.object(backend, '_request_via_proxy', side_effect=slow), \
             patch.object(backend.time, 'monotonic', side_effect=lambda: clock[0]):
            result = backend.detect(self.config, deadline=25.0, cancelled=threading.Event(),
                                    reference_home=False, retry_exit_ip=True, retry_target_trace=True)
        # exit 5+5 s leaves 15 s; trace 5 s leaves 10 s, so one retry fits; the sample still ends by 25 s.
        self.assertEqual(self.trace_requests(), 2)
        self.assertTrue(result.ready)
        self.assertLessEqual(clock[0], 25.0)

    def test_monitoring_samples_request_trace_retry(self):
        adapter = NativeManagedBackend()
        adapter.cancel = threading.Event()
        self.answers[:] = [ConnectionResetError(), GOOD]
        with patch.object(backend, 'detect', wraps=backend.detect) as detect:
            result = adapter.check_manager(self.config, time.monotonic()+25)
        self.assertIs(detect.call_args.kwargs['retry_target_trace'], True)
        self.assertEqual(self.trace_requests(), 2)
        self.assertTrue(result.ready)

    def test_monitoring_start_sample_requests_trace_retry(self):
        calls = []

        def detect(config, **kwargs):
            calls.append(kwargs)
            raise Stop()
        selection = BrowserSelection('https://claude.ai/', r'C:\owned\chrome.exe', r'C:\owned-data', 'Default')
        with patch.object(browser, 'inspect_production_target', return_value=()), \
             patch.object(backend, 'detect', side_effect=detect), self.assertRaises(Stop):
            NativeManagedBackend().initialize(self.config, selection, 'a'*64, SamplingBudget(),
                                              threading.Event(), Path('unused-journal.json'))
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0]['retry_target_trace'], True)

    def test_desktop_samples_request_trace_retry(self):
        self.answers[:] = [TimeoutError(), GOOD]
        with patch.object(backend, 'detect', wraps=backend.detect) as detect:
            result = NativeDesktopBackend().detect(self.config, deadline=time.monotonic()+25,
                                                   cancelled=threading.Event())
        self.assertIs(detect.call_args.kwargs['retry_target_trace'], True)
        self.assertEqual(self.trace_requests(), 2)
        self.assertTrue(result.ready)


if __name__ == '__main__':
    unittest.main()
