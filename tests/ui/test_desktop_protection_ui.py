import sys
import tempfile
from dataclasses import replace
from pathlib import Path
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.model import Config, Result, Status
from src.protection.desktop_session import DesktopView


class FakeDesktopRuntime:
    def __init__(self):
        self.view = DesktopView()
        self.starts, self.stops, self.resumes, self.abandoned = [], 0, 0, 0

    def current(self):
        return self.view

    def request_start(self, config, app_id, request_id):
        self.starts.append((config, app_id, request_id))
        self.view = replace(self.view, request_id=request_id, phase='preparing', reason_code='preparing')
        return True

    def request_stop(self):
        self.stops += 1
        return True

    def request_resume(self):
        self.resumes += 1
        return True

    def abandon(self):
        self.abandoned += 1


PASS = Result(common=Status.PASS, mapping_mode='not_required', desktop=Status.PASS, mapping=Status.PASS,
              owner=Status.PASS, target_trace=Status.PASS, desktop_instance=Status.PASS)


class DesktopProtectionUiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.root.withdraw()
        self.runtime = FakeDesktopRuntime()
        self.app = App(self.root, config_path=Path(self.temp.name) / 'settings.json', desktop_runtime=self.runtime)
        self.app.config = Config(port=12001, manager_port=12002, expected_ip='192.0.2.41',
                                 ip_url='https://ip.example/check', mapping_mode='not_required')
        self.app.saved = True
        self.app._applications = ('Claude_pzs8sxrjxfjjc!Claude',)
        self.app._selected_app = 'Claude_pzs8sxrjxfjjc!Claude'

    def tearDown(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self.temp.cleanup()

    def detected(self):
        self.app.result = PASS
        self.app._evidence_started = self.app.clock()
        self.app.refresh()

    def test_buttons_are_absent_without_the_runtime(self):
        root = tk.Tk()
        root.withdraw()
        try:
            plain = App(root, config_path=Path(self.temp.name) / 'other.json')
            self.assertEqual(plain.desktop_protect_button.winfo_manager(), '')
            self.assertNotIn('桌面端保护', plain._render_report())
        finally:
            root.destroy()

    def test_protected_start_needs_a_fresh_passing_detection_and_consumes_it(self):
        self.app.refresh()
        self.assertEqual(str(self.app.desktop_protect_button['state']), 'disabled')
        self.detected()
        self.assertEqual(str(self.app.desktop_protect_button['state']), 'normal')
        self.app.desktop_protect_button.invoke()
        self.assertEqual(len(self.runtime.starts), 1)
        config, app_id, _ = self.runtime.starts[0]
        self.assertEqual((config.proxy_port, app_id), (12001, 'Claude_pzs8sxrjxfjjc!Claude'))
        self.assertFalse(self.app._fresh())
        self.assertEqual(str(self.app.desktop_protect_button['state']), 'disabled')
        self.assertEqual(str(self.app.desktop_stop_button['state']), 'normal')

    def test_desktop_protection_and_chrome_monitor_are_mutually_exclusive(self):
        self.detected()
        self.app._monitor_runtime = object()
        self.app._managed_phase, self.app._managed_cleanup = 'running', 'not_applicable'
        self.app.refresh()
        self.assertEqual(str(self.app.desktop_protect_button['state']), 'disabled')
        self.app._monitor_runtime = None
        self.runtime.view = DesktopView(phase='running', reason_code='protecting')
        self.app._poll_desktop()
        self.app.refresh()
        self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
        self.assertEqual(str(self.app.monitor_target_button['state']), 'disabled')

    def test_resume_only_after_a_resumable_fuse(self):
        self.runtime.view = DesktopView(phase='fused', reason_code='exit_ip_mismatch', resumable=True)
        self.app._poll_desktop()
        self.app.refresh()
        self.assertIn('出口 IP 与预期不一致', self.app.desktop_protect_summary.get())
        self.assertEqual(str(self.app.desktop_resume_button['state']), 'normal')
        self.app.desktop_resume_button.invoke()
        self.assertEqual(self.runtime.resumes, 1)
        self.runtime.view = DesktopView(phase='desktop_exited', reason_code='desktop_exited')
        self.app._poll_desktop()
        self.app.refresh()
        self.assertEqual(str(self.app.desktop_resume_button['state']), 'disabled')

    def test_closing_while_protected_asks_and_leaves_the_desktop_offline(self):
        self.runtime.view = DesktopView(phase='running', reason_code='protecting')
        self.app._poll_desktop()
        with patch('ui.app.messagebox.askyesno', return_value=False):
            self.app.request_close()
        self.assertEqual(self.runtime.abandoned, 0)
        self.assertTrue(self.root.winfo_exists())
        with patch('ui.app.messagebox.askyesno', return_value=True):
            self.app.request_close()
        self.assertEqual(self.runtime.abandoned, 1)

    def test_report_states_scope_and_limits(self):
        self.runtime.view = DesktopView(phase='running', reason_code='protecting', relay_state='forwarding',
                                        cleanup_status='pending', executables=3, events=())
        self.app._poll_desktop()
        report = self.app._render_report()
        self.assertIn('桌面端保护：正在保护桌面端（只走本机代理端口）', report)
        self.assertIn('不保证不直连', report)
        self.assertIn('不是桌面端每条连接的逐条证明', report)


if __name__ == '__main__':
    unittest.main()
