import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import release_trust as trust


class ReleaseTrustTests(unittest.TestCase):
    installer = r'C:\Selected\installer.exe'
    executable = r'C:\Selected\Proxy Manager.exe'

    def setUp(self):
        local = patch.object(trust, '_local_file_is_safe', return_value=True, create=True)
        local.start()
        self.addCleanup(local.stop)

    def test_no_selection_never_reads_or_returns_a_baseline(self):
        with patch.object(trust, '_file_sha256') as sha:
            result = trust.inspect_release_baseline('installer.exe', 'manager.exe', 22999, 24001)
        self.assertEqual(result.status, 'unknown')
        self.assertIsNone(result.baseline)
        sha.assert_not_called()

    def test_selection_must_be_explicit_boolean_and_local_path(self):
        for selected, installer in [(1, self.installer), (True, r'\\server\share\setup.exe')]:
            with self.subTest(selected=selected, installer=installer), \
                 patch.object(trust, '_file_sha256') as sha:
                result = trust.inspect_release_baseline(installer, self.executable, 22999, 24001, selected=selected)
            self.assertIsNone(result.baseline)
            sha.assert_not_called()

    def test_wrong_installer_never_becomes_a_baseline(self):
        with patch.object(trust, '_file_sha256', return_value='0' * 64), \
             patch.object(trust, '_proxy_owner_snapshot') as owner:
            result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
        self.assertNotEqual(result.status, 'pass')
        self.assertIsNone(result.baseline)
        self.assertEqual(result.windows_signature, 'unknown')
        owner.assert_not_called()

    def test_baseline_requires_all_evidence_and_stable_process(self):
        with patch.object(trust, '_file_sha256', return_value=trust.INSTALLER_SHA256), \
             patch.object(trust, '_verify_installed_release', return_value=True), \
             patch.object(trust, '_proxy_owner_snapshot', side_effect=[('pid', 42), ('pid', 42)]):
            result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.baseline.manager_sha256, trust.EXECUTABLE_SHA256)
        self.assertNotIn('manager.exe', repr(result))
        self.assertEqual(result.windows_signature, 'historical_untrusted')
        self.assertEqual(result.package_match, 'pass')
        self.assertEqual(result.installed_match, 'pass')
        self.assertEqual(result.owner_match, 'pass')

    def test_baseline_uses_explicit_selection_on_another_computer(self):
        installer = r'D:\Setup\installer.exe'
        executable = r'D:\Apps\Proxy Manager.exe'
        with patch.object(trust, '_file_sha256', return_value=trust.INSTALLER_SHA256), \
             patch.object(trust, '_verify_installed_release', return_value=True) as verify, \
             patch.object(trust, '_proxy_owner_snapshot', return_value=('pid', 42)) as owner:
            result = trust.inspect_release_baseline(installer, executable, 25124, 25123, selected=True)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.baseline.manager_executable, executable)
        verify.assert_called_once_with(executable)
        for call in owner.call_args_list:
            candidate = call.args[0]
            self.assertEqual((candidate.manager_port, candidate.proxy_port), (25124, 25123))
            self.assertEqual(candidate.manager_executable, executable)

    def test_changed_or_ambiguous_process_never_returns_baseline(self):
        for second in (None, ('pid', 43)):
            with self.subTest(second=second), \
                 patch.object(trust, '_file_sha256', return_value=trust.INSTALLER_SHA256), \
                 patch.object(trust, '_verify_installed_release', return_value=True), \
                 patch.object(trust, '_proxy_owner_snapshot', side_effect=[('pid', 42), second]):
                result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
            self.assertEqual(result.status, 'unknown')
            self.assertIsNone(result.baseline)

    def test_modified_missing_or_extra_installation_file_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'app').mkdir()
            (root / 'app' / 'run.txt').write_bytes(b'correct')
            manifest = {'app/run.txt': hashlib.sha256(b'correct').hexdigest()}
            self.assertTrue(trust._matches_tree(root, manifest))
            (root / 'app' / 'run.txt').write_bytes(b'changed')
            self.assertFalse(trust._matches_tree(root, manifest))
            (root / 'app' / 'run.txt').unlink()
            self.assertFalse(trust._matches_tree(root, manifest))
            (root / 'app' / 'run.txt').write_bytes(b'correct')
            (root / 'extra.txt').write_bytes(b'extra')
            self.assertFalse(trust._matches_tree(root, manifest))

    def test_unrecognized_manifest_or_missing_files_is_unknown(self):
        with patch.object(trust, '_file_sha256', return_value=trust.INSTALLER_SHA256), \
             patch.object(trust, '_verify_installed_release', return_value=False), \
             patch.object(trust, '_proxy_owner_snapshot', return_value=('pid', 42)):
            result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
        self.assertEqual(result.status, 'unknown')
        self.assertIsNone(result.baseline)
        self.assertEqual(result.package_match, 'pass')
        self.assertEqual(result.installed_match, 'unknown')

    def test_installer_changes_during_check_do_not_return_baseline(self):
        with patch.object(trust, '_file_sha256', side_effect=[trust.INSTALLER_SHA256, '0' * 64]), \
             patch.object(trust, '_verify_installed_release', return_value=True), \
             patch.object(trust, '_proxy_owner_snapshot', return_value=('pid', 42)):
            result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
        self.assertEqual(result.status, 'unknown')
        self.assertIsNone(result.baseline)

    def test_untrusted_manifest_is_rejected(self):
        with patch.object(trust.Path, 'read_bytes', return_value=b'{}'):
            self.assertFalse(trust._verify_installed_release(self.executable))

    def test_reparse_point_in_installed_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(trust, '_is_reparse', return_value=True):
                self.assertFalse(trust._matches_tree(Path(folder), {'app.exe': '0' * 64}))

    def test_unsafe_or_nonlocal_selection_is_rejected_before_reading(self):
        with patch.object(trust, '_local_file_is_safe', return_value=False, create=True), \
             patch.object(trust, '_file_sha256') as sha:
            result = trust.inspect_release_baseline(self.installer, self.executable, 22999, 24001, selected=True)
        self.assertEqual(result.status, 'unknown')
        sha.assert_not_called()


if __name__ == '__main__':
    unittest.main()
