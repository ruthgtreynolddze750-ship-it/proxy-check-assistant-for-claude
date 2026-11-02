"""R28: continuous monitoring skips the Claude home reference request; start-up detection keeps it.
All OS/network boundaries are injected."""
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import backend
from src.browser import request_probe as browser
from src.browser.inspection import BrowserSelection
from src.protection.managed_session import NativeManagedBackend, SamplingBudget

HOME = 'https://claude.ai/'
OWNER = (25002, 25001, 501, '900', r'C:\pm.exe', 'a'*64)


class Stop(Exception):
    pass


class HomeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.config = backend.Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        passed = backend.Check('pass', 'synthetic')
        self.urls = []

        def request(port, url, timeout, **kwargs):
            self.urls.append(url)
            return b'203.0.113.1'
        for name, kwargs in (('_proxy_owner_snapshot', dict(return_value=OWNER)),
                             ('_manager', dict(return_value=passed)), ('_port', dict(return_value=passed)),
                             ('_mapping', dict(return_value=passed)),
                             ('_inspect_claude_trace_request', dict(return_value=passed)),
                             ('_request_via_proxy', dict(side_effect=request))):
            patcher = patch.object(backend, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def bounded(self, **kwargs):
        steps = []
        result = backend.detect(self.config, deadline=time.monotonic()+25, cancelled=threading.Event(),
                                diagnostics=steps, **kwargs)
        return result, steps

    def test_default_detection_still_requests_home_reference(self):
        for run in (lambda: (backend.detect(self.config), None), self.bounded):
            with self.subTest(bounded=run is self.bounded):
                self.urls.clear()
                result, steps = run()
                self.assertEqual(self.urls.count(HOME), 1)
                self.assertEqual(result.claude.status, 'pass')
                if steps is not None:
                    self.assertIn('claude_home', [step.stage for step in steps])

    def test_skipped_home_reference_sends_no_request_and_keeps_sample_ready(self):
        for run in (lambda: (backend.detect(self.config, reference_home=False), None),
                    lambda: self.bounded(reference_home=False)):
            with self.subTest():
                self.urls.clear()
                result, steps = run()
                self.assertNotIn(HOME, self.urls)
                self.assertEqual(self.urls, [self.config.ip_url])
                self.assertEqual(result.claude.status, 'unknown')
                self.assertIn('参考项', result.claude.message)
                self.assertEqual(result.exit_ip.status, 'pass')
                self.assertEqual(result.target_trace.status, 'pass')
                self.assertTrue(result.ready)
                if steps is not None:
                    self.assertNotIn('claude_home', [step.stage for step in steps])

    def test_skipping_home_cannot_mask_a_failed_required_check(self):
        with patch.object(backend, '_inspect_claude_trace_request', return_value=backend.Check('fail', 'synthetic')):
            result, _ = self.bounded(reference_home=False)
        self.assertFalse(result.ready)

    def test_monitoring_loop_sample_skips_home_reference(self):
        adapter = NativeManagedBackend()
        adapter.cancel = threading.Event()
        with patch.object(backend, 'detect', wraps=backend.detect) as detect:
            result = adapter.check_manager(self.config, time.monotonic()+25)
        self.assertIs(detect.call_args.kwargs['reference_home'], False)
        self.assertNotIn(HOME, self.urls)
        self.assertTrue(result.ready)
        self.assertNotIn('claude_home', [step.stage for step in adapter.manager_steps])

    def test_monitoring_start_sample_skips_home_reference(self):
        calls = []

        def detect(config, **kwargs):
            calls.append(kwargs)
            raise Stop()
        selection = BrowserSelection(HOME, r'C:\owned\chrome.exe', r'C:\owned-data', 'Default')
        with patch.object(browser, 'inspect_production_target', return_value=()), \
             patch.object(backend, 'detect', side_effect=detect), self.assertRaises(Stop):
            NativeManagedBackend().initialize(self.config, selection, 'a'*64, SamplingBudget(),
                                              threading.Event(), Path('unused-journal.json'))
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0]['reference_home'], False)


if __name__ == '__main__':
    unittest.main()
