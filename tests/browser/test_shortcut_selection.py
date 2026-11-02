import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.browser.shortcut_selection import inspect_shortcut


@unittest.skipUnless(os.name == 'nt', 'Windows shortcut integration')
class ShortcutSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / '专用浏览器'
        self.root.mkdir()
        self.chrome = self.root / 'chrome.exe'
        self.chrome.touch()
        self.shortcut = self.root / 'selected.lnk'
        self.powershell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
        self.env_patch = patch.dict(os.environ, {'LOCALAPPDATA': str(self.root)})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def create_shortcut(self, arguments):
        script = "$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$s=(New-Object -ComObject WScript.Shell).CreateShortcut($d.shortcut);$s.TargetPath=$d.target;$s.Arguments=$d.arguments;$s.Save()"
        payload = json.dumps({'shortcut': str(self.shortcut), 'target': str(self.chrome), 'arguments': arguments})
        p = subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-Command', script],
                           input=payload.encode('utf-8'), capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0)

    def test_real_shortcut_reads_selected_fields_without_claiming_browser_identity(self):
        data_dir = self.root / 'User Data'
        self.create_shortcut(f'--user-data-dir="{data_dir}" --profile-directory="Profile 1"')
        result = inspect_shortcut(str(self.shortcut))
        self.assertEqual(result.status, 'complete')
        self.assertEqual(result.chrome_executable, str(self.chrome))
        self.assertEqual(result.user_data_dir, str(data_dir))
        self.assertEqual(result.profile_directory, 'Profile 1')
        self.assertNotIn(str(self.root), repr(result))

    def test_real_shortcut_missing_or_extra_arguments_requires_review(self):
        self.create_shortcut('--profile-directory="Profile 1"')
        result = inspect_shortcut(str(self.shortcut))
        self.assertEqual(result.status, 'incomplete')
        self.assertIsNone(result.user_data_dir)
        self.create_shortcut('--profile-directory="Profile 1" --proxy-server=http://example.invalid')
        result = inspect_shortcut(str(self.shortcut))
        self.assertEqual(result.status, 'manual_review')
        self.assertNotIn('example.invalid', repr(result))

    def test_duplicate_profile_arguments_require_review(self):
        self.create_shortcut('--profile-directory=Default --profile-directory="Profile 1"')
        self.assertEqual(inspect_shortcut(str(self.shortcut)).status, 'manual_review')

    def test_default_data_directory_and_allowed_claude_url_are_only_candidates(self):
        root = self.root / 'Google' / 'Chrome' / 'User Data'
        (root / 'Profile 1').mkdir(parents=True)
        self.create_shortcut('--profile-directory="Profile 1" https://claude.ai/')
        before = self.shortcut.read_bytes()
        result = inspect_shortcut(str(self.shortcut), allowed_url='https://claude.ai/')
        self.assertEqual(result.status, 'complete')
        self.assertEqual(result.user_data_dir, str(root))
        self.assertEqual(result.data_dir_source, 'default_candidate')
        self.assertEqual(result.profile_directory, 'Profile 1')
        self.assertEqual(self.shortcut.read_bytes(), before)
        self.assertNotIn(str(root), repr(result))

    def test_default_directory_missing_or_selected_profile_missing_is_not_inferred(self):
        self.create_shortcut('--profile-directory="Profile 1" https://claude.ai/')
        self.assertEqual(inspect_shortcut(str(self.shortcut), allowed_url='https://claude.ai/').status, 'incomplete')
        (self.root / 'Google' / 'Chrome' / 'User Data').mkdir(parents=True)
        result = inspect_shortcut(str(self.shortcut), allowed_url='https://claude.ai/')
        self.assertEqual(result.status, 'incomplete')
        self.assertIsNone(result.user_data_dir)

    def test_url_must_match_the_user_allowed_url_and_have_no_sensitive_parts(self):
        data_dir = self.root / 'User Data'
        for url, allowed in [
                ('https://claude.ai/', 'https://claude.ai/'),
                ('https://claude.ai', 'https://claude.ai/')]:
            with self.subTest(url=url):
                self.create_shortcut(f'--user-data-dir="{data_dir}" --profile-directory=Default {url}')
                self.assertEqual(inspect_shortcut(str(self.shortcut), allowed_url=allowed).status, 'complete')
        for url, allowed in [
                ('https://claude.ai/other', 'https://claude.ai/'),
                ('https://claude.ai/?token=private', 'https://claude.ai/?token=private'),
                ('https://claude.ai/#secret', 'https://claude.ai/#secret'),
                ('https://user:pass@claude.ai/', 'https://user:pass@claude.ai/'),
                ('https://claude.ai.evil.invalid/', 'https://claude.ai/'),
                ('https://claude.ai/', None)]:
            with self.subTest(url=url):
                self.create_shortcut(f'--user-data-dir="{data_dir}" --profile-directory=Default {url}')
                result = inspect_shortcut(str(self.shortcut), allowed_url=allowed)
                self.assertEqual(result.status, 'manual_review')
                self.assertNotIn(url, repr(result))

    def test_extra_proxy_debugging_or_duplicate_url_still_require_manual_review(self):
        for extra in ('--proxy-server=http://localhost:24001', '--remote-debugging-port=9222',
                      'https://claude.ai/'):
            with self.subTest(extra=extra):
                self.create_shortcut(f'--profile-directory=Default https://claude.ai/ {extra}')
                self.assertEqual(inspect_shortcut(str(self.shortcut), allowed_url='https://claude.ai/').status,
                                 'manual_review')

    def test_non_shortcut_is_rejected_without_execution(self):
        with self.assertRaises(ValueError):
            inspect_shortcut(str(self.chrome))


if __name__ == '__main__':
    unittest.main()
