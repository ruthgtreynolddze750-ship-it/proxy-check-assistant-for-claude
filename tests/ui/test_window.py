import sys
import tempfile
import time
import tkinter as tk
from tkinter import ttk
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.model import Result, Status
from ui.adapters import Probe


class FakeBackend:
    def detect(self, config, app_id):
        return Probe(Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS, desktop=Status.PASS if app_id else Status.UNKNOWN, desktop_instance=Status.PASS, browser=Status.PASS, browser_input=Status.PASS, browser_identity=Status.UNKNOWN, browser_proxy=Status.UNKNOWN, observed_ip='198.51.100.19', reason_codes=('password=PRIVATE_TEST_VALUE', 'chat=PRIVATE_TEST_VALUE')), ('valid-id',))

    def launch_desktop(self, config, app_id):
        self.launched = True

    def launch_browser(self, config):
        self.browser_launched = True


class WindowTests(unittest.TestCase):
    def test_minimum_window_keeps_report_and_configuration_accessible(self):
        with tempfile.TemporaryDirectory() as folder:
            root = tk.Tk()
            try:
                app = App(root, config_path=Path(folder) / 'config.json')
                root.geometry('760x700')
                root.update()
                self.assertGreater(app.report.winfo_height(), 60)
                self.assertGreater(app.save_button.winfo_width(), 1)
                self.assertEqual(len(app.settings_tabs.tabs()), 3)
                app.settings_tabs.select(1)
                root.update()
                self.assertTrue(app.entries[2].winfo_ismapped())
                app.settings_tabs.select(2)
                root.update()
                self.assertTrue(app.entries[9].winfo_ismapped())
                def descendants(widget):
                    for child in widget.winfo_children():
                        yield child
                        yield from descendants(child)
                buttons = [widget.cget('text') for widget in descendants(root) if isinstance(widget, ttk.Button)]
                self.assertNotIn('网页候选观测', buttons)
                self.assertIn('首次配置向导', buttons)
                for button in (app.start_monitor_button, app.stop_monitor_button, app.resume_monitor_button):
                    self.assertTrue(button.winfo_ismapped())
                    self.assertGreater(button.winfo_width(), 1)
                    self.assertLessEqual(button.winfo_rootx() + button.winfo_width(),
                                         root.winfo_rootx() + root.winfo_width())
                for label in ('复制报告', '导出报告'):
                    button = next(widget for widget in descendants(root) if isinstance(widget, ttk.Button) and widget.cget('text') == label)
                    self.assertTrue(button.winfo_ismapped())
                    self.assertGreater(button.winfo_width(), 1)
            finally:
                root.destroy()

    def test_window_configuration_detection_export_and_invalidation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = tk.Tk()
            try:
                backend = FakeBackend()
                app = App(root, backend=backend, config_path=Path(folder) / 'config.json')
                root.update()
                for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': 'C:/Trusted/Proxy Manager.exe', 'manager_sha256': 'a' * 64, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'url': 'https://claude.ai/', 'chrome_path': 'C:/Chrome/chrome.exe', 'user_data_dir': 'C:/Chrome/User Data', 'chrome_profile': 'Profile 2'}.items():
                    app.fields[key].set(value)
                with patch('ui.app.messagebox.showinfo'):
                    self.assertTrue(app.save_settings())
                app.detect()
                deadline = time.monotonic() + 2
                while app.busy and time.monotonic() < deadline:
                    root.update()
                    time.sleep(.01)
                app.desktop_choice.current(0)
                app.desktop_choice.event_generate('<<ComboboxSelected>>')
                root.update()
                app.detect()
                while app.busy and time.monotonic() < deadline:
                    root.update()
                    time.sleep(.01)
                self.assertEqual(str(app.desktop_button['state']), 'normal')
                self.assertEqual(str(app.browser_button['state']), 'disabled')
                app.launch_browser()
                self.assertFalse(hasattr(backend, 'browser_launched'))
                output = Path(folder) / 'report.txt'
                with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
                    app.export_report()
                report = output.read_text(encoding='utf-8')
                self.assertNotIn('203.0.113.42', report)
                self.assertNotIn('198.51.100.19', report)
                self.assertIn('网页端：未确认', report)
                with patch.object(root, 'clipboard_clear') as clear, patch.object(root, 'clipboard_append') as append:
                    app.copy_report()
                clear.assert_called_once()
                self.assertNotIn('198.51.100.19', append.call_args.args[0])
                self.assertIn('网页端：未确认', append.call_args.args[0])
                app.full_ip.set(True)
                app.refresh()
                self.assertIn('198.51.100.19', app.report.get('1.0', 'end'))
                with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
                    app.export_report()
                report = output.read_text(encoding='utf-8')
                self.assertIn('203.0.113.42', report)
                self.assertIn('198.51.100.19', report)
                with patch.object(root, 'clipboard_clear'), patch.object(root, 'clipboard_append') as append:
                    app.copy_report()
                self.assertIn('203.0.113.42', append.call_args.args[0])
                self.assertIn('198.51.100.19', append.call_args.args[0])
                self.assertNotIn('C:/Chrome', report)
                self.assertNotIn('a' * 64, report)
                self.assertNotIn('PRIVATE_TEST_VALUE', report)
                self.assertNotIn('PRIVATE_TEST_VALUE', append.call_args.args[0])
                app.full_ip.set(False)
                app.refresh()
                with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
                    app.export_report()
                self.assertNotIn('198.51.100.19', output.read_text(encoding='utf-8'))
                app.show_history()
                root.update()
                self.assertIn('198.51.*.*', app.history[0])
                app.fields['port'].set('54321')
                self.assertEqual(str(app.desktop_button['state']), 'disabled')
                self.assertIn('未确认', app.summary.get())
            finally:
                root.destroy()


if __name__ == '__main__':
    unittest.main()
