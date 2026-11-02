import tempfile
import unittest
from pathlib import Path

from src.browser.inspection import BrowserSelection, inspect_selection


class BrowserInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.chrome = self.root / 'chrome.exe'
        self.chrome.touch()
        self.user_data = self.root / 'user-data'
        (self.user_data / 'Profile 1').mkdir(parents=True)

    def selection(self, **kwargs):
        values = dict(url='https://claude.ai/new', chrome_executable=str(self.chrome),
                      user_data_dir=str(self.user_data), profile_directory='Profile 1')
        values.update(kwargs)
        return BrowserSelection(**values)

    def test_valid_paths_are_not_browser_proxy_evidence(self):
        result = inspect_selection(self.selection())
        self.assertEqual(result.identity_status, 'unconfirmed')
        self.assertEqual(result.proxy_status, 'unconfirmed')
        self.assertFalse(result.may_launch)

    def test_malformed_or_untrusted_url_is_rejected(self):
        for url in ['http://claude.ai', 'https://claude.ai.evil.test',
                    'https://user:password@claude.ai', 'https://claude.ai:444',
                    'https://claude.ai/\n--evil']:
            with self.subTest(url=url):
                result = inspect_selection(self.selection(url=url))
                self.assertEqual(result.input_status, 'failed')
                self.assertFalse(result.may_launch)

    def test_profile_traversal_or_missing_profile_is_rejected(self):
        for name in ['../other', 'missing', '', '.', 'nested/profile']:
            with self.subTest(name=name):
                result = inspect_selection(self.selection(profile_directory=name))
                self.assertEqual(result.input_status, 'failed')
                self.assertFalse(result.may_launch)

    def test_missing_chrome_and_shortcut_do_not_identify_browser(self):
        for exe in [str(self.root / 'missing.exe'), str(self.root / 'shortcut.lnk')]:
            result = inspect_selection(self.selection(chrome_executable=exe))
            self.assertEqual(result.input_status, 'failed')
            self.assertFalse(result.may_launch)

    def test_result_does_not_expose_private_configuration_or_url(self):
        result = inspect_selection(self.selection(url='https://claude.ai/?token=private-secret'))
        self.assertNotIn('private-secret', repr(result))
        self.assertNotIn(str(self.root), repr(result))
        self.assertFalse(result.may_launch)


if __name__ == '__main__':
    unittest.main()
