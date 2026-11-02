import unittest
from src.browser.offline_demo import run_demo


class OfflinePageFlowTests(unittest.TestCase):
    def test_valid_trace_through_page_and_parser_remains_unconfirmed(self):
        result = run_demo('fl=demo\nip=203.0.113.9\n', '203.0.113.9')
        self.assertEqual(result.diagnostic, 'candidate')
        self.assertEqual(result.identity_status, 'unconfirmed')
        self.assertEqual(result.proxy_status, 'unconfirmed')
        self.assertFalse(result.may_launch)
        self.assertNotIn('203.0.113.9', repr(result))

    def test_missing_duplicate_malformed_mismatched_and_wrong_target_fail_closed(self):
        cases = [('', '203.0.113.9', 'claude.ai'),
                 ('ip=203.0.113.9\nip=203.0.113.9\n', '203.0.113.9', 'claude.ai'),
                 ('ip=not-an-ip\n', '203.0.113.9', 'claude.ai'),
                 ('ip=203.0.113.10\n', '203.0.113.9', 'claude.ai'),
                 ('ip=203.0.113.9\n', '203.0.113.9', 'example.com')]
        for trace, expected, target in cases:
            with self.subTest(trace=trace, target=target):
                result = run_demo(trace, expected, target)
                self.assertEqual(result.diagnostic, 'rejected')
                self.assertFalse(result.may_launch)

    def test_no_browser_network_path_is_used(self):
        result = run_demo('ip=203.0.113.9\n', '203.0.113.9')
        self.assertEqual(result.network_calls, 0)
        self.assertFalse(result.may_launch)


if __name__ == '__main__':
    unittest.main()
