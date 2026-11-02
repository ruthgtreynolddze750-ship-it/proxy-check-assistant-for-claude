import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.adapters import Probe
from ui.model import Result, Status
from src.core.backend import LaunchResult


def wait_for(root, predicate):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('后台操作未按预期完成')


class ControlledBackend:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.launches = 0

    def detect(self, config, app_id):
        self.calls += 1
        self.entered.set()
        if not self.release.wait(2):
            raise RuntimeError('SECRET')
        desktop = Status.PASS if app_id == 'valid-id' else Status.UNKNOWN
        return Probe(Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS, desktop=desktop, desktop_instance=Status.PASS), ('valid-id',))

    def launch_desktop(self, config, app_id):
        self.launches += 1

    def launch_browser(self, config):
        self.launches += 1


class AsyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.backend = ControlledBackend()
        self.now = [100.0]
        self.app = App(self.root, backend=self.backend, config_path=Path(self.temp.name) / 'config.json', clock=lambda: self.now[0])
        for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': 'C:/Trusted/Proxy Manager.exe', 'manager_sha256': 'a' * 64, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'url': 'https://claude.ai/', 'chrome_path': 'C:/Chrome/chrome.exe', 'user_data_dir': 'C:/Chrome/User Data', 'chrome_profile': 'Profile 2'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())

    def tearDown(self):
        self.backend.release.set()
        self.root.destroy()
        self.temp.cleanup()

    def test_config_edit_and_duplicate_detection_reject_late_result(self):
        self.assertEqual(self.backend.calls, 0)
        self.app.detect()
        self.assertTrue(self.backend.entered.wait(1))
        self.root.update()
        self.app.detect()
        self.assertEqual(self.backend.calls, 1)
        self.app.fields['port'].set('54321')
        self.backend.release.set()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(self.app.result.common, Status.UNKNOWN)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_evidence_expires_even_without_ui_timer_firing_before_click(self):
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.now[0] += 61
        self.app.launch_desktop()
        self.assertEqual(self.backend.launches, 0)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_detection_finishing_after_expiry_does_not_unlock(self):
        self.app.detect()
        self.assertTrue(self.backend.entered.wait(1))
        self.now[0] += 61
        self.backend.release.set()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(self.app.result.common, Status.UNKNOWN)

    def test_exception_is_not_rendered(self):
        def fail(config, app_id):
            raise RuntimeError('password=SECRET')
        self.backend.detect = fail
        with patch('ui.app.messagebox.showerror') as popup:
            self.app.detect()
            wait_for(self.root, lambda: not self.app.busy)
        self.assertNotIn('SECRET', str(popup.call_args))
        self.assertNotIn('SECRET', self.app.report.get('1.0', 'end'))

    def test_failed_detection_revokes_prior_launch_and_export_is_redacted(self):
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        def fail(config, app_id):
            raise RuntimeError('password=PRIVATE_TEST_VALUE')
        self.backend.detect = fail
        with patch('ui.app.messagebox.showerror'):
            self.app.detect()
            wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')
        self.app.launch_desktop()
        self.assertEqual(self.backend.launches, 0)
        output = Path(self.temp.name) / 'failed-report.txt'
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
            self.app.export_report()
        report = output.read_text(encoding='utf-8')
        self.assertIn('共同检测：未确认', report)
        self.assertIn('网页端：未确认', report)
        self.assertNotIn('PRIVATE_TEST_VALUE', report)
        self.assertNotIn('203.0.113.42', report)
        self.assertNotIn('C:/Chrome', report)

    def test_launch_freezes_inputs_and_uses_chosen_application(self):
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        entered = threading.Event()
        release = threading.Event()
        def launch(config, app_id):
            self.backend.selected = app_id
            entered.set()
            release.wait(2)
        self.backend.launch_desktop = launch
        try:
            with patch('ui.app.messagebox.showinfo'):
                self.app.launch_desktop()
                self.assertTrue(entered.wait(1))
                self.assertEqual(self.backend.selected, 'valid-id')
                self.assertEqual(str(self.app.entries[0]['state']), 'disabled')
                self.assertEqual(str(self.app.desktop_choice['state']), 'disabled')
                release.set()
                wait_for(self.root, lambda: not self.app.busy)
            self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        finally:
            release.set()

    def test_launch_results_distinguish_blocked_failed_activation_and_unknown(self):
        self.backend.release.set()
        scenarios = [
            (LaunchResult('unknown', '启动前代理监听归属发生变化或无法确认'), '启动已阻止', '归属', 'info'),
            (LaunchResult('fail', 'password=PRIVATE_TEST_VALUE'), '未能启动', '未通过', 'error'),
            (LaunchResult('unknown', 'password=PRIVATE_TEST_VALUE', pid=1234), '启动结果未确认', '已发起', 'info'),
            (LaunchResult('pass', 'password=PRIVATE_TEST_VALUE', pid=1234), '启动请求已处理', '激活', 'info'),
            (LaunchResult('unknown', 'password=PRIVATE_TEST_VALUE'), '启动状态未确认', '无法确认', 'info'),
            (None, '启动状态未确认', '无法确认', 'info'),
        ]
        for outcome, title, expected_text, kind in scenarios:
            with self.subTest(title=title):
                self.app.detect()
                wait_for(self.root, lambda: not self.app.busy)
                self.app.desktop_choice.current(0)
                self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
                self.root.update()
                self.app.detect()
                wait_for(self.root, lambda: not self.app.busy)
                self.assertEqual(str(self.app.desktop_button['state']), 'normal')
                self.backend.launch_desktop = lambda config, app_id: outcome
                with patch('ui.app.messagebox.showinfo') as info, patch('ui.app.messagebox.showerror') as error:
                    self.app.launch_desktop()
                    wait_for(self.root, lambda: not self.app.busy)
                popup = info if kind == 'info' else error
                popup.assert_called_once()
                self.assertEqual(popup.call_args.args[0], title)
                self.assertIn(expected_text, popup.call_args.args[1])
                self.assertNotIn('PRIVATE_TEST_VALUE', str(popup.call_args))
                self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
                self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_missing_browser_configuration_does_not_block_desktop_detection(self):
        for key in ('chrome_path', 'user_data_dir', 'chrome_profile'):
            self.app.fields[key].set('')
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_required_mapping_cannot_be_skipped_by_adapter(self):
        self.backend.detect = lambda config, app_id: Probe(Result(common=Status.PASS, desktop=Status.PASS, desktop_instance=Status.PASS), ('valid-id',))
        self.app.fields['mapping_mode'].set('需要目标映射')
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertIn('共同检测：未确认', self.app.summary.get())

    def test_editing_mapping_expectation_invalidates_existing_evidence(self):
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.app.fields['expected_zone'].set('sample-zone')
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertIs(self.app.result.common_status, Status.UNKNOWN)

    def test_missing_trust_blocks_even_if_adapter_claims_owner_pass(self):
        self.app.fields['manager_sha256'].set('')
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertIs(self.app.result.owner, Status.UNKNOWN)

    def test_editing_trust_fingerprint_invalidates_previous_detection(self):
        self.backend.release.set()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.app.detect()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.app.fields['manager_sha256'].set('b' * 64)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')
        self.assertIs(self.app.result.owner, Status.UNKNOWN)


class EntryTests(unittest.TestCase):
    def test_main_opens_and_closes_without_detecting(self):
        from ui import app
        original_tk = tk.Tk
        def make_root():
            root = original_tk()
            root.after(100, root.destroy)
            return root
        with tempfile.TemporaryDirectory() as folder, patch.dict('os.environ', {'LOCALAPPDATA': folder}), patch('ui.app.tk.Tk', side_effect=make_root), patch('ui.adapters.LiveBackend.detect') as detect:
            app.main()
        detect.assert_not_called()

    def test_main_does_not_offer_desktop_protection(self):
        # 2026-11-01: the user paused desktop protection; the entry is the 0.2.8 one again.
        from ui import app
        with tempfile.TemporaryDirectory() as folder, patch.dict('os.environ', {'LOCALAPPDATA': folder}), \
                patch('ui.app.tk.Tk'), patch('ui.app.App') as made:
            app.main()
        self.assertNotIn('desktop_runtime', made.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
