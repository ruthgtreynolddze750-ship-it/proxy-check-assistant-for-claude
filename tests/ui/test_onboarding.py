import json
import subprocess
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
from ui.model import Status, Result
from ui.onboarding import PortCandidates, PortDialog, discover_port_candidates, GUIDE_TEXT


def wait_for(root, predicate):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('本机查询未完成')


class DiscoveryTests(unittest.TestCase):
    def test_only_port_numbers_return_and_no_sensitive_sources_accessed(self):
        reply = subprocess.CompletedProcess([], 0, stdout=json.dumps([24001, 22999, 24001]), stderr='')
        with patch('ui.onboarding.subprocess.run', return_value=reply) as run:
            result = discover_port_candidates()
        self.assertEqual(result.ports, (22999, 24001))
        script = run.call_args.args[0][-1]
        self.assertNotIn('CommandLine', script)
        self.assertNotIn('/api/', script)
        self.assertNotIn('password', script.lower())

    def test_malformed_or_secret_containing_output_is_never_displayed(self):
        reply = subprocess.CompletedProcess([], 0, stdout='{"password":"SECRET"}', stderr='SECRET')
        with patch('ui.onboarding.subprocess.run', return_value=reply):
            result = discover_port_candidates()
        self.assertEqual(result.status, 'unknown')
        self.assertNotIn('SECRET', repr(result))

    def test_guide_refers_to_manual_observation_without_claiming_current_pass(self):
        self.assertIn('LPM', GUIDE_TEXT)
        self.assertIn('未确认', GUIDE_TEXT)
        self.assertIn('收发', GUIDE_TEXT)
        self.assertNotIn('24001', GUIDE_TEXT)
        self.assertNotIn('此前本机', GUIDE_TEXT)
        self.assertNotIn('本机此前', GUIDE_TEXT)
        self.assertIn('实际配置', GUIDE_TEXT)

    def test_guide_identifies_third_party_as_only_current_manual_auxiliary_check(self):
        self.assertIn('https://ip.net.coffee/claude/', GUIDE_TEXT)
        self.assertIn('第三方', GUIDE_TEXT)
        self.assertIn('辅助', GUIDE_TEXT)
        self.assertIn('当次', GUIDE_TEXT)
        self.assertIn('桌面端每条连接', GUIDE_TEXT)

    def test_guide_explains_existing_dependencies_without_installing_or_modifying_them(self):
        self.assertIn('已安装 Proxy Manager', GUIDE_TEXT)
        self.assertIn('已有专用 Chrome', GUIDE_TEXT)
        self.assertIn('LPM 扩展', GUIDE_TEXT)
        self.assertIn('已安装 Claude 桌面端', GUIDE_TEXT)
        self.assertIn('不会安装或修改', GUIDE_TEXT)


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.path = Path(self.temp.name) / 'config.json'
        self.app = App(self.root, config_path=self.path)

    def tearDown(self):
        self.root.update()
        self.root.destroy()
        self.temp.cleanup()

    def test_user_selects_port_roles_and_import_does_not_save_or_trust(self):
        dialog = PortDialog(self.app, discover=lambda: PortCandidates('observed', (22999, 24001)))
        dialog.start()
        wait_for(self.root, lambda: not dialog.busy)
        self.assertEqual(self.app.fields['port'].get(), '')
        dialog.manager.set('22999')
        dialog.proxy.set('24001')
        dialog.apply()
        self.assertEqual(self.app.fields['manager_port'].get(), '22999')
        self.assertEqual(self.app.fields['port'].get(), '24001')
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())
        self.assertFalse(self.app.saved)

    def test_central_setup_uses_existing_candidates_and_requires_explicit_save_and_detect(self):
        from src.browser.shortcut_selection import ShortcutSelection
        from src.core.release_trust import Baseline, ReleaseInspection
        backend = self.app.backend
        with patch.object(backend, 'detect', return_value=Probe(Result())) as detect:
            self.app.open_first_setup()
            wizard = self.app._first_setup_dialog
            self.root.update()
            self.assertTrue(wizard.save_button.winfo_ismapped())
            self.assertGreater(wizard.save_button.winfo_width(), 1)
            self.assertLessEqual(wizard.save_button.winfo_rooty() + wizard.save_button.winfo_height(),
                                 wizard.window.winfo_rooty() + wizard.window.winfo_height())
            self.assertEqual(self.app.fields['expected_ip'].get(), '')
            self.assertFalse(self.path.exists())
            detect.assert_not_called()
            wizard.port_button.invoke()
            ports = self.app._port_dialog
            ports.discover = lambda: PortCandidates('observed', (12001, 12002))
            ports.start()
            wait_for(self.root, lambda: not ports.busy)
            self.assertEqual(self.app.fields['port'].get(), '')
            ports.manager.set('12002')
            ports.proxy.set('12001')
            ports.apply()
            self.assertEqual(wizard.port_entry.get(), '12001')
            ports.window.destroy()
            wizard.shortcut_button.invoke()
            shortcut = self.app._shortcut_dialog
            shortcut.inspector = lambda path, **kwargs: ShortcutSelection('complete', 'C:/Browser/chrome.exe', 'C:/Browser/Data', 'Profile 1', 'shortcut')
            with patch('ui.shortcut_setup.filedialog.askopenfilename', return_value='C:/chosen.lnk'):
                shortcut.choose_button.invoke()
            wait_for(self.root, lambda: not shortcut.busy)
            self.assertEqual(self.app.fields['chrome_path'].get(), '')
            shortcut.apply_button.invoke()
            self.assertEqual(wizard.chrome_entry.get(), 'C:/Browser/chrome.exe')
            shortcut.window.destroy()
            for key, value in {'expected_ip': '192.0.2.41', 'ip_url': 'https://ip.example/check', 'expected_zone': 'sample-zone', 'mapping_mode': '明确不需要目标映射'}.items():
                self.app.fields[key].set(value)
            wizard.release_button.invoke()
            release = self.app._release_dialog
            executable = 'C:\\Trusted\\Proxy Manager.exe'
            result = ReleaseInspection('pass', '', release_source='historical_release_record', package_match='pass', installed_match='pass', owner_match='pass', windows_signature='historical_untrusted', baseline=Baseline(executable, 'a' * 64))
            release.inspector = lambda *args, **kwargs: result
            with patch('ui.release_setup.filedialog.askopenfilename', return_value='C:/installer.exe'), patch('ui.release_setup.filedialog.askdirectory', return_value='C:/Trusted'):
                release.choose_installer()
                release.choose_directory()
            release.inspect_button.invoke()
            wait_for(self.root, lambda: not release.busy)
            release.accept_button.invoke()
            wait_for(self.root, lambda: not release.busy)
            self.assertFalse(self.path.exists())
            self.assertEqual(self.app.fields['manager_sha256'].get(), 'a' * 64)
            release.window.destroy()
            with patch('ui.app.messagebox.showinfo'):
                wizard.save_button.invoke()
                wait_for(self.root, lambda: not self.app.busy)
            self.assertTrue(self.path.exists())
            self.assertTrue(self.app.saved)
            detect.assert_not_called()
            wizard.detect_button.invoke()
            wait_for(self.root, lambda: not self.app.busy)
            detect.assert_called_once()
            self.assertEqual(str(self.app.browser_button['state']), 'disabled')
            self.assertEqual(self.app.fields['expected_ip'].get(), '192.0.2.41')
            self.app.fields['expected_zone'].set('changed-zone')
            self.assertEqual(self.app.result, Result())
            self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_central_setup_does_not_allow_editing_during_launch(self):
        self.app.open_first_setup()
        wizard = self.app._first_setup_dialog
        entered, release = threading.Event(), threading.Event()
        def work():
            entered.set()
            release.wait(2)
        try:
            self.app._start_worker('launch', self.app._generation, self.app.clock(), work)
            self.assertTrue(entered.wait(1))
            self.assertEqual(str(wizard.expected_ip_entry['state']), 'disabled')
            self.assertEqual(str(wizard.port_button['state']), 'disabled')
            release.set()
            with patch('ui.app.messagebox.showinfo'):
                wait_for(self.root, lambda: not self.app.busy)
            self.assertEqual(str(wizard.expected_ip_entry['state']), 'normal')
        finally:
            release.set()

    def test_setup_guide_names_existing_browser_extension_and_desktop_steps(self):
        self.app.open_first_setup()
        wizard = self.app._first_setup_dialog
        self.root.update()
        guide = wizard.guide_label.cget('text')
        for text in ('Proxy Manager', '专用 Chrome', 'LPM', '代理端口', '查找桌面端',
                     '正常退出', '重新检测', '收发', '未确认', '手动填写'):
            self.assertIn(text, guide)
        self.assertTrue(wizard.guide_label.winfo_ismapped())
        self.assertLessEqual(wizard.save_button.winfo_rooty() + wizard.save_button.winfo_height(),
                             wizard.window.winfo_rooty() + wizard.window.winfo_height())
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_copy_guide_address_only_when_clicked_does_not_unlock_or_detect(self):
        simulated = Result(common=Status.PASS, target_trace=Status.PASS, mapping_mode='not_required', mapping=Status.PASS,
                           owner=Status.PASS, browser=Status.PASS, browser_input=Status.PASS,
                           browser_identity=Status.UNKNOWN, browser_proxy=Status.UNKNOWN)
        self.app.saved = True
        self.app.result = simulated
        self.app._evidence_started = self.app.clock()
        self.app.refresh()
        with patch.object(self.app.backend, 'detect') as detect, patch.object(self.app.backend, 'launch_browser') as launch:
            self.app.open_guide()
            guide = self.app._guide_dialog
            self.assertIn('https://ip.net.coffee/claude/', guide.text.get('1.0', 'end'))
            with patch.object(guide.window, 'clipboard_clear') as clear, patch.object(guide.window, 'clipboard_append') as append:
                self.root.update()
                clear.assert_not_called()
                append.assert_not_called()
                guide.copy_button.invoke()
                clear.assert_called_once_with()
                append.assert_called_once_with('https://ip.net.coffee/claude/')
            self.assertIn('已复制', guide.copy_status.get())
            self.assertEqual(str(self.app.browser_button['state']), 'disabled')
            self.assertEqual(self.app.result, simulated)
            self.assertTrue(self.app.saved)
            self.assertFalse(self.path.exists())
            detect.assert_not_called()
            launch.assert_not_called()

    def test_copy_failure_explains_manual_fallback(self):
        self.app.open_guide()
        guide = self.app._guide_dialog
        with patch.object(guide.window, 'clipboard_clear', side_effect=tk.TclError('clipboard unavailable')):
            guide.copy_button.invoke()
        self.assertIn('复制失败', guide.copy_status.get())
        self.assertIn('手动复制', guide.copy_status.get())
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_candidate_is_discarded_when_configuration_changes(self):
        entered, release = threading.Event(), threading.Event()
        def discover():
            entered.set()
            release.wait(2)
            return PortCandidates('observed', (22999, 24001))
        dialog = PortDialog(self.app, discover=discover)
        try:
            dialog.start()
            self.assertTrue(entered.wait(1))
            self.app.fields['port'].set('33333')
            release.set()
            wait_for(self.root, lambda: not dialog.busy)
            self.assertEqual(str(dialog.apply_button['state']), 'disabled')
            self.assertEqual(self.app.fields['port'].get(), '33333')
        finally:
            release.set()

    def test_find_desktop_is_local_and_does_not_run_network_detection(self):
        class Backend:
            def __init__(self): self.detect_calls = 0
            def discover_desktop(self): return ('demo-app-id',)
            def detect(self, *args): self.detect_calls += 1; raise AssertionError('unexpected detection')
        backend = Backend()
        self.app.backend = backend
        self.app.find_desktop()
        wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(backend.detect_calls, 0)
        self.assertEqual(tuple(self.app.desktop_choice['values']), ('demo-app-id',))
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_find_desktop_discards_result_when_configuration_changes(self):
        entered, release = threading.Event(), threading.Event()
        class Backend:
            def discover_desktop(self):
                entered.set()
                release.wait(2)
                return ('demo-app-id',)
        self.app.backend = Backend()
        try:
            self.app.find_desktop()
            self.assertTrue(entered.wait(1))
            self.app.fields['port'].set('12345')
            release.set()
            wait_for(self.root, lambda: not self.app.busy)
            self.assertNotIn('demo-app-id', tuple(self.app.desktop_choice['values']))
            self.assertIn('重新查找', self.app.desktop_lookup.get())
        finally:
            release.set()

    def test_desktop_only_flow_finds_then_detects_once_and_launches_fake(self):
        class Backend:
            def __init__(self): self.detect_calls = 0; self.launched = None
            def discover_desktop(self): return ('demo-app-id',)
            def detect(self, config, app_id):
                self.detect_calls += 1
                return Probe(Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS, desktop=Status.PASS, desktop_instance=Status.PASS), ('demo-app-id',))
            def launch_desktop(self, config, app_id):
                self.launched = (config.port, app_id)
        backend = Backend()
        self.app.backend = backend
        for key, value in {'port': '24001', 'manager_port': '22999', 'manager_executable': 'C:/Trusted/Proxy Manager.exe', 'manager_sha256': 'a' * 64, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
            self.app.find_desktop()
            wait_for(self.root, lambda: not self.app.busy)
            self.app.desktop_choice.current(0)
            self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
            self.root.update()
            self.app.detect()
            wait_for(self.root, lambda: not self.app.busy)
            self.assertEqual(backend.detect_calls, 1)
            self.assertEqual(str(self.app.desktop_button['state']), 'normal')
            self.assertEqual(str(self.app.browser_button['state']), 'disabled')
            self.app.launch_desktop()
            wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(backend.launched, (24001, 'demo-app-id'))


if __name__ == '__main__':
    unittest.main()
