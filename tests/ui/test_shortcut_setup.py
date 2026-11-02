import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.shortcut_setup import ShortcutDialog
from ui.model import Result, Status
from src.browser.shortcut_selection import inspect_shortcut


def wait_for(root, predicate):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('快捷方式读取未完成')


@unittest.skipUnless(os.name == 'nt', 'Windows shortcut integration')
class ShortcutWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name) / '浏览器测试'
        self.folder.mkdir()
        self.chrome = self.folder / 'chrome.exe'
        self.chrome.touch()
        self.shortcut = self.folder / '测试.lnk'
        self.root = tk.Tk()
        self.config_path = self.folder / 'settings.json'
        self.app = App(self.root, config_path=self.config_path)

    def tearDown(self):
        self.root.update()
        self.root.destroy()
        self.temp.cleanup()

    def create_shortcut(self, arguments):
        script = "$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$s=(New-Object -ComObject WScript.Shell).CreateShortcut($d.path);$s.TargetPath=$d.target;$s.Arguments=$d.args;$s.Save()"
        exe = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
        data = json.dumps({'path': str(self.shortcut), 'target': str(self.chrome), 'args': arguments}).encode('utf-8')
        result = subprocess.run([exe, '-NoProfile', '-NonInteractive', '-Command', script], input=data, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)

    def select(self, dialog):
        with patch('ui.shortcut_setup.filedialog.askopenfilename', return_value=str(self.shortcut)):
            dialog.choose()
        wait_for(self.root, lambda: not dialog.busy)

    def test_real_shortcut_requires_explicit_apply_and_never_saves_or_launches(self):
        data_dir = self.folder / 'User Data'
        self.create_shortcut(f'--user-data-dir="{data_dir}" --profile-directory="Profile 1"')
        before = self.shortcut.read_bytes()
        dialog = ShortcutDialog(self.app)
        self.select(dialog)
        self.assertEqual(self.app.fields['chrome_path'].get(), '')
        self.assertEqual(str(dialog.apply_button['state']), 'normal')
        self.app.saved = True
        self.app.result = Result(owner=Status.PASS)
        self.app._evidence_started = self.app.clock()
        dialog.apply()
        self.assertEqual(self.app.fields['chrome_path'].get(), str(self.chrome))
        self.assertEqual(self.app.fields['user_data_dir'].get(), str(data_dir))
        self.assertEqual(self.app.fields['chrome_profile'].get(), 'Profile 1')
        self.assertEqual(self.shortcut.read_bytes(), before)
        self.assertFalse(self.config_path.exists())
        self.assertFalse(self.app.saved)
        self.assertEqual(self.app.result, Result())
        self.assertIsNone(self.app._evidence_started)
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')
        self.assertIn('未确认', dialog.status.get())

    def test_missing_or_extra_arguments_are_never_applied(self):
        data_dir = self.folder / 'User Data'
        for args, explanation in [(f'--user-data-dir="{data_dir}"', '缺少'),
                                  (f'--user-data-dir="{data_dir}" --profile-directory=Default --proxy-server=http://secret.invalid', '额外'),
                                  (f'--user-data-dir="{data_dir}" --profile-directory=Default --remote-debugging-port=9222', '额外'),
                                  (f'--user-data-dir="{data_dir}" --profile-directory=Default https://example.invalid', '额外')]:
            with self.subTest(args=args):
                self.create_shortcut(args)
                dialog = ShortcutDialog(self.app)
                self.select(dialog)
                self.assertIn(explanation, dialog.status.get())
                self.assertNotIn('secret.invalid', dialog.status.get())
                self.assertEqual(str(dialog.apply_button['state']), 'disabled')
                dialog.apply()
                self.assertEqual(self.app.fields['chrome_path'].get(), '')
                dialog.window.destroy()

    def test_incomplete_display_is_discarded_when_config_changes(self):
        self.create_shortcut(f'--user-data-dir="{self.folder}"')
        dialog = ShortcutDialog(self.app)
        self.select(dialog)
        self.assertEqual(dialog.data_dir.get(), str(self.folder))
        self.app.fields['port'].set('32123')
        wait_for(self.root, lambda: not dialog.data_dir.get())
        self.assertIn('变化', dialog.status.get())

    def test_default_directory_and_matching_url_are_candidate_only(self):
        local = self.folder / 'LocalAppData'
        default_data = local / 'Google' / 'Chrome' / 'User Data'
        (default_data / 'Profile 1').mkdir(parents=True)
        self.create_shortcut('--profile-directory="Profile 1" https://claude.ai/')
        original = self.shortcut.read_bytes()
        with patch.dict(os.environ, {'LOCALAPPDATA': str(local)}):
            dialog = ShortcutDialog(self.app)
            self.select(dialog)
            self.assertEqual(dialog.data_dir.get(), str(default_data))
            self.assertEqual(dialog.profile.get(), 'Profile 1')
            self.assertIn('默认', dialog.status.get())
            self.assertEqual(str(dialog.apply_button['state']), 'normal')
            self.assertEqual(self.app.fields['user_data_dir'].get(), '')
            self.app.saved = True
            self.app.result = Result(owner=Status.PASS)
            self.app._evidence_started = self.app.clock()
            dialog.apply()
        self.assertEqual(self.app.fields['user_data_dir'].get(), str(default_data))
        self.assertFalse(self.app.saved)
        self.assertEqual(self.app.result, Result())
        self.assertIsNone(self.app._evidence_started)
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')
        self.assertFalse(self.config_path.exists())
        self.assertEqual(self.shortcut.read_bytes(), original)
        self.assertIn('未确认', dialog.status.get())

    def test_default_candidate_is_discarded_after_config_change(self):
        local = self.folder / 'LocalAppData'
        (local / 'Google' / 'Chrome' / 'User Data' / 'Profile 1').mkdir(parents=True)
        self.create_shortcut('--profile-directory="Profile 1" https://claude.ai/')
        with patch.dict(os.environ, {'LOCALAPPDATA': str(local)}):
            dialog = ShortcutDialog(self.app)
            self.select(dialog)
            self.assertEqual(str(dialog.apply_button['state']), 'normal')
            self.app.fields['url'].set('https://claude.ai/new')
            dialog.apply()
        self.assertEqual(self.app.fields['user_data_dir'].get(), '')
        self.assertIn('变化', dialog.status.get())

    def test_default_directory_does_not_override_different_selected_url_or_extra_argument(self):
        local = self.folder / 'LocalAppData'
        (local / 'Google' / 'Chrome' / 'User Data' / 'Profile 1').mkdir(parents=True)
        with patch.dict(os.environ, {'LOCALAPPDATA': str(local)}):
            for args, configured_url in [
                ('--profile-directory="Profile 1" https://claude.ai/', 'https://claude.ai/new'),
                ('--profile-directory="Profile 1" https://claude.ai/ --proxy-bypass-list=*', 'https://claude.ai/'),
            ]:
                with self.subTest(args=args):
                    self.app.fields['url'].set(configured_url)
                    self.create_shortcut(args)
                    dialog = ShortcutDialog(self.app)
                    self.select(dialog)
                    self.assertEqual(str(dialog.apply_button['state']), 'disabled')
                    self.assertIn('网址', dialog.status.get())
                    dialog.apply()
                    self.assertEqual(self.app.fields['user_data_dir'].get(), '')
                    dialog.window.destroy()

    def test_absent_default_directory_is_not_assumed(self):
        local = self.folder / 'LocalAppData'
        local.mkdir()
        self.create_shortcut('--profile-directory="Profile 1" https://claude.ai/')
        with patch.dict(os.environ, {'LOCALAPPDATA': str(local)}):
            dialog = ShortcutDialog(self.app)
            self.select(dialog)
            self.assertEqual(str(dialog.apply_button['state']), 'disabled')
            self.assertEqual(dialog.data_dir.get(), '')
            self.assertIn('缺少', dialog.status.get())

    def test_invalid_file_is_rejected_without_displaying_exception(self):
        dialog = ShortcutDialog(self.app, inspector=lambda path, **kwargs: (_ for _ in ()).throw(ValueError('SECRET')))
        self.select(dialog)
        self.assertEqual(str(dialog.apply_button['state']), 'disabled')
        self.assertNotIn('SECRET', dialog.status.get())
        self.assertIn('无法识别', dialog.status.get())

    def test_changes_during_and_after_read_discard_candidate(self):
        self.create_shortcut(f'--user-data-dir="{self.folder}" --profile-directory=Default')
        entered, release = threading.Event(), threading.Event()
        def delayed(path, **kwargs):
            entered.set()
            release.wait(3)
            return inspect_shortcut(path, **kwargs)
        dialog = ShortcutDialog(self.app, inspector=delayed)
        try:
            with patch('ui.shortcut_setup.filedialog.askopenfilename', return_value=str(self.shortcut)):
                dialog.choose()
            self.assertTrue(entered.wait(1))
            self.app.fields['port'].set('12345')
            release.set()
            wait_for(self.root, lambda: not dialog.busy)
            self.assertEqual(str(dialog.apply_button['state']), 'disabled')
            self.assertIn('变化', dialog.status.get())
            self.select(dialog)
            self.app.fields['port'].set('23456')
            dialog.apply()
            self.assertEqual(self.app.fields['chrome_path'].get(), '')
            self.assertIn('变化', dialog.status.get())
        finally:
            release.set()


if __name__ == '__main__':
    unittest.main()
