import os
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

root_path = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root_path))
from src.core.backend import Check, Detection
from src.core.monitoring import MonitorSession
from src.ui.model import Config, save_config
from src.ui.monitor_window import MonitorWindow


def wait_for(root, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('独立监测面板未进入预期状态')


def valid_config(**changes):
    values = dict(port=12001, manager_port=12002, manager_executable='C:/Trusted/Proxy Manager.exe',
                  manager_sha256='a' * 64, expected_ip='192.0.2.41', ip_url='https://ip.example/check',
                  expected_zone='sample-zone', mapping_mode='not_required')
    values.update(changes)
    return Config(**values)


class MonitorWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'settings.json'
        self.root = tk.Tk()
        self.root.withdraw()
        self.sessions = []
        self.calls = []
        self.fail = False
        passed = Check('pass', '')
        failed = Check('fail', 'password=PRIVATE_TEST_VALUE')
        def detector(config):
            self.calls.append(True)
            return Detection(passed, passed, failed if self.fail else passed, passed, Check('unknown', ''),
                             mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        def factory(config):
            session = MonitorSession(config, interval_seconds=.05, max_age_seconds=1, detector=detector)
            self.sessions.append(session)
            return session
        self.factory = factory

    def tearDown(self):
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except tk.TclError:
            pass
        self.temp.cleanup()

    def create_window(self, **kwargs):
        return MonitorWindow(self.root, config_path=self.path, session_factory=self.factory, poll_interval_ms=20, **kwargs)

    def test_missing_or_incomplete_config_prompts_old_app_without_starting(self):
        panel = self.create_window()
        self.assertIn('旧助手', panel.config_status.get())
        self.assertEqual(str(panel.start_button['state']), 'disabled')
        self.assertEqual(self.sessions, [])
        save_config(self.path, valid_config(expected_zone=''))
        wait_for(self.root, lambda: '未确认' in panel.config_status.get())
        self.assertEqual(str(panel.start_button['state']), 'disabled')
        self.assertEqual(self.calls, [])

    def test_valid_config_only_starts_when_clicked_and_never_claims_block(self):
        save_config(self.path, valid_config())
        panel = self.create_window()
        self.root.update()
        self.assertEqual(self.sessions, [])
        self.assertEqual(self.calls, [])
        panel.start_button.invoke()
        wait_for(self.root, lambda: '正在监测' in panel.status.get())
        self.assertEqual(len(self.sessions), 1)
        self.assertGreater(len(self.calls), 0)
        self.assertIn('阻断未启用', panel.status.get())
        self.assertIn('不证明桌面或网页的全部连接', panel.report.get('1.0', 'end'))
        self.assertEqual(str(panel.stop_button['state']), 'normal')

    def test_alarm_stop_and_manual_resume_require_new_success(self):
        save_config(self.path, valid_config())
        panel = self.create_window()
        panel.start_button.invoke()
        wait_for(self.root, lambda: '正在监测' in panel.status.get())
        self.fail = True
        wait_for(self.root, lambda: '发现异常' in panel.status.get())
        self.assertIn('阻断未启用', panel.status.get())
        self.fail = False
        time.sleep(.12)
        self.root.update()
        self.assertIn('发现异常', panel.status.get())
        panel.stop_button.invoke()
        self.assertIn('异常', panel.status.get())
        self.assertEqual(str(panel.resume_button['state']), 'normal')
        panel.resume_button.invoke()
        wait_for(self.root, lambda: '正在监测' in panel.status.get())
        self.assertIn('阻断未启用', panel.status.get())
        self.assertNotIn('PRIVATE_TEST_VALUE', panel.report.get('1.0', 'end'))

    def test_changed_config_stops_old_session_and_discards_late_result(self):
        save_config(self.path, valid_config())
        entered, release = threading.Event(), threading.Event()
        passed = Check('pass', '')
        def slow_detector(config):
            entered.set()
            release.wait(2)
            return Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed,
                             _owner_evidence=('synthetic',), target_trace=passed)
        def factory(config):
            session = MonitorSession(config, interval_seconds=1, max_age_seconds=1, detector=slow_detector)
            self.sessions.append(session)
            return session
        self.factory = factory
        panel = self.create_window()
        try:
            panel.start_button.invoke()
            self.assertTrue(entered.wait(1))
            save_config(self.path, valid_config(expected_zone='different-zone'))
            wait_for(self.root, lambda: '配置已变化' in panel.status.get())
            self.assertEqual(self.sessions[0].snapshot().state, 'stopped')
            release.set()
            time.sleep(.1)
            self.root.update()
            self.assertNotIn('正在监测', panel.status.get())
            self.assertEqual(len(self.sessions), 1)
        finally:
            release.set()

    def test_export_and_copy_are_redacted_and_do_not_include_config(self):
        save_config(self.path, valid_config())
        panel = self.create_window()
        panel.start_button.invoke()
        wait_for(self.root, lambda: '正在监测' in panel.status.get())
        self.fail = True
        wait_for(self.root, lambda: '发现异常' in panel.status.get())
        output = Path(self.temp.name) / 'report.txt'
        with patch('src.ui.monitor_window.filedialog.asksaveasfilename', return_value=str(output)):
            panel.export_button.invoke()
        text = output.read_text(encoding='utf-8')
        self.assertIn('发现异常', text)
        self.assertIn('阻断未启用', text)
        for value in ('192.0.2.41', 'C:/Trusted', 'a' * 64, 'PRIVATE_TEST_VALUE', 'sample-zone'):
            self.assertNotIn(value, text)
        with patch.object(self.root, 'clipboard_clear') as clear, patch.object(self.root, 'clipboard_append') as append:
            panel.copy_button.invoke()
        clear.assert_called_once()
        self.assertNotIn('PRIVATE_TEST_VALUE', append.call_args.args[0])
        self.assertNotIn('192.0.2.41', append.call_args.args[0])

    def test_window_destroy_stops_session_without_touching_other_processes(self):
        save_config(self.path, valid_config())
        panel = self.create_window()
        panel.start_button.invoke()
        wait_for(self.root, lambda: '正在监测' in panel.status.get())
        session = self.sessions[0]
        self.root.destroy()
        self.assertEqual(session.snapshot().state, 'stopped')

    def test_default_path_uses_localappdata_without_writing(self):
        local = Path(self.temp.name) / 'local'
        with patch.dict(os.environ, {'LOCALAPPDATA': str(local)}):
            panel = MonitorWindow(self.root, session_factory=self.factory, poll_interval_ms=20)
            self.assertEqual(panel.config_path, local / 'ClaudeLaunchCenter' / 'settings.json')
            self.assertIn('旧助手', panel.config_status.get())
            self.assertFalse(local.exists())


if __name__ == '__main__':
    unittest.main()
