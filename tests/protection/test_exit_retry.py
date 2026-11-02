"""R29: continuous monitoring retries the independent exit request once after a connection-class error;
start-up detection keeps a single attempt. All OS/network boundaries are injected."""
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import backend
from src.browser import request_probe as browser
from src.browser.inspection import BrowserSelection
from src.protection.managed_session import NativeManagedBackend, SamplingBudget

OWNER = (25002, 25001, 501, '900', r'C:\pm.exe', 'a'*64)
GOOD = b'203.0.113.1'


class Stop(Exception):
    pass


class ExitRetryTests(unittest.TestCase):
    def setUp(self):
        self.config = backend.Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        passed = backend.Check('pass', 'synthetic')
        self.answers = []
        self.urls = []

        def request(port, url, timeout, **kwargs):
            self.urls.append(url)
            if url != self.config.ip_url:
                return b''
            answer = self.answers.pop(0) if self.answers else GOOD
            if isinstance(answer, BaseException):
                raise answer
            return answer
        for name, kwargs in (('_proxy_owner_snapshot', dict(return_value=OWNER)),
                             ('_manager', dict(return_value=passed)), ('_port', dict(return_value=passed)),
                             ('_mapping', dict(return_value=passed)),
                             ('_inspect_claude_trace_request', dict(return_value=passed)),
                             ('_request_via_proxy', dict(side_effect=request))):
            patcher = patch.object(backend, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def bounded(self, seconds=25, **kwargs):
        steps = []
        result = backend.detect(self.config, deadline=time.monotonic()+seconds, cancelled=threading.Event(),
                                diagnostics=steps, reference_home=False, **kwargs)
        return result, steps

    def exit_requests(self):
        return self.urls.count(self.config.ip_url)

    def test_default_detection_keeps_single_exit_attempt(self):
        for run in (lambda: backend.detect(self.config), lambda: self.bounded()[0]):
            with self.subTest():
                self.urls.clear()
                self.answers[:] = [ConnectionResetError('SECRET'), GOOD]
                result = run()
                self.assertEqual(self.exit_requests(), 1)
                self.assertEqual(result.exit_ip.status, 'unknown')
                self.assertFalse(result.ready)

    def test_connection_error_is_retried_once_and_second_answer_is_compared(self):
        self.answers[:] = [ConnectionResetError('SECRET'), GOOD]
        result, steps = self.bounded(retry_exit_ip=True)
        self.assertEqual(self.exit_requests(), 2)
        self.assertEqual(result.exit_ip.status, 'pass')
        self.assertTrue(result.ready)
        exits = [step for step in steps if step.stage == 'exit_ip']
        self.assertEqual([step.error_code for step in exits], ['os_error', ''])
        self.assertEqual(exits[0].status, 'error')
        self.assertNotIn('SECRET', repr(steps))

    def test_retry_cannot_mask_a_mismatch_on_the_second_answer(self):
        self.answers[:] = [ConnectionResetError(), b'198.51.100.9']
        result, _ = self.bounded(retry_exit_ip=True)
        self.assertEqual(self.exit_requests(), 2)
        self.assertEqual(result.exit_ip.status, 'fail')
        self.assertFalse(result.ready)

    def test_second_connection_error_stays_unconfirmed(self):
        self.answers[:] = [ConnectionResetError(), ConnectionAbortedError(), GOOD]
        result, steps = self.bounded(retry_exit_ip=True)
        self.assertEqual(self.exit_requests(), 2)
        self.assertEqual(result.exit_ip.status, 'unknown')
        self.assertFalse(result.ready)
        self.assertEqual([s.error_code for s in steps if s.stage == 'exit_ip'], ['os_error', 'os_error'])

    def test_non_connection_outcomes_are_not_retried(self):
        cases = {'mismatch': (b'198.51.100.9', 'fail'), 'timeout': (TimeoutError(), 'unknown'),
                 'http_status': (backend.ProxyHTTPError(503), 'unknown'),
                 'invalid_data': (b'not-an-ip', 'unknown'),
                 'cancelled': (backend.DetectionCancelled(), 'unknown')}
        for name, (answer, status) in cases.items():
            with self.subTest(case=name):
                self.urls.clear()
                self.answers[:] = [answer, GOOD]
                result, _ = self.bounded(retry_exit_ip=True)
                self.assertEqual(self.exit_requests(), 1)
                self.assertEqual(result.exit_ip.status, status)
                self.assertFalse(result.ready)

    def test_no_retry_when_less_than_ten_seconds_remain(self):
        self.answers[:] = [ConnectionResetError(), GOOD]
        result, _ = self.bounded(seconds=9.5, retry_exit_ip=True)
        self.assertEqual(self.exit_requests(), 1)
        self.assertEqual(result.exit_ip.status, 'unknown')

    def test_monitoring_loop_sample_retries_connection_error(self):
        adapter = NativeManagedBackend()
        adapter.cancel = threading.Event()
        self.answers[:] = [ConnectionResetError(), GOOD]
        with patch.object(backend, 'detect', wraps=backend.detect) as detect:
            result = adapter.check_manager(self.config, time.monotonic()+25)
        self.assertIs(detect.call_args.kwargs['retry_exit_ip'], True)
        self.assertEqual(self.exit_requests(), 2)
        self.assertTrue(result.ready)

    def test_monitoring_start_sample_retries_connection_error(self):
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
        self.assertIs(calls[0]['retry_exit_ip'], True)


if __name__ == '__main__':
    unittest.main()
