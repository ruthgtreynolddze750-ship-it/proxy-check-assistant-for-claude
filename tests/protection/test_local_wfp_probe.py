import subprocess
import sys
import unittest

from src.protection import local_wfp_probe


class LocalWfpProbeTests(unittest.TestCase):
    def test_fixture_limits_identity_and_endpoint_and_never_calls_windows(self):
        result = local_wfp_probe.run_fixture('success')
        self.assertEqual(result['scope']['app'], 'fixture-project-target-exe')
        self.assertEqual(result['scope']['layer'], 'ALE_AUTH_CONNECT_V4')
        self.assertEqual(result['scope']['protocol'], 'tcp')
        self.assertEqual(result['scope']['remote_address'], '127.0.0.1')
        self.assertEqual(result['scope']['remote_port'], 43123)
        self.assertEqual(result['result'], 'fixture_complete')
        self.assertEqual(result['events'], ['begin', 'add', 'commit', 'readback', 'delete', 'verify_absent'])
        self.assertEqual(result['system_action'], 'none')
        self.assertFalse(result['live_write_available'])

    def test_transaction_failure_aborts_without_delete(self):
        result = local_wfp_probe.run_fixture('add_failure')
        self.assertEqual(result['result'], 'aborted')
        self.assertEqual(result['events'], ['begin', 'add', 'abort'])
        self.assertIn('synthetic_add_failure', result['errors'])

    def test_readback_mismatch_refuses_cleanup_and_preserves_unknown(self):
        result = local_wfp_probe.run_fixture('readback_mismatch')
        self.assertEqual(result['result'], 'cleanup_refused')
        self.assertEqual(result['events'], ['begin', 'add', 'commit', 'readback'])
        self.assertEqual(result['remaining_object'], 'unknown')

    def test_commit_failure_does_not_assume_no_rule_was_installed(self):
        result = local_wfp_probe.run_fixture('commit_failure')
        self.assertEqual(result['result'], 'commit_unknown')
        self.assertEqual(result['events'], ['begin', 'add', 'commit', 'abort'])
        self.assertEqual(result['remaining_object'], 'unknown')

    def test_cleanup_failure_cannot_be_reported_as_success(self):
        result = local_wfp_probe.run_fixture('delete_failure')
        self.assertEqual(result['result'], 'cleanup_failed')
        self.assertIn('synthetic_delete_failure', result['errors'])
        self.assertEqual(result['remaining_object'], 'unknown')

    def test_fixture_rejects_unknown_or_arbitrary_input(self):
        for value in ('C:/Windows/System32/cmd.exe', '8.8.8.8', 'apply'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    local_wfp_probe.run_fixture(value)

    def test_cli_failure_fixture_exits_nonzero(self):
        p = subprocess.run([sys.executable, '-B', '-m', 'src.protection.local_wfp_probe',
                            '--fixture', 'readback_mismatch'], capture_output=True, timeout=5)
        self.assertNotEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
