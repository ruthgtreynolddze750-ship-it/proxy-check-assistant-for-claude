"""P2: the report keeps a record of the latest detection and launch; the record never unlocks a launch."""
import sys
import tempfile
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
from test_desktop_protection_ui import FakeDesktopRuntime, PASS as DESKTOP_PASS

APP_ID = 'valid-id'
FULL_IP = '203.0.113.42'


def wait_for(root, predicate):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('后台操作未按预期完成')


def passing(browser=Status.UNKNOWN):
    return Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS,
                  desktop=Status.PASS, desktop_instance=Status.PASS, observed_ip=FULL_IP, browser=browser,
                  browser_input=browser, browser_identity=browser, browser_proxy=browser)


class Backend:
    def __init__(self):
        self.result = passing()
        self.error = None
        self.outcome = LaunchResult('pass', '已激活', pid=4321)
        self.launches = []

    def detect(self, config, app_id):
        if self.error:
            raise self.error
        return Probe(self.result, (APP_ID,))

    def launch_desktop(self, config, app_id):
        self.launches.append('desktop')
        return self.outcome

    def launch_browser(self, config):
        self.launches.append('browser')
        return self.outcome


class LaunchRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.root.withdraw()
        self.backend = Backend()
        self.now = [100.0]
        self.app = App(self.root, backend=self.backend, config_path=Path(self.temp.name) / 'config.json',
                       clock=lambda: self.now[0])
        for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': 'C:/Trusted/Proxy Manager.exe',
                           'manager_sha256': 'a' * 64, 'expected_ip': FULL_IP, 'ip_url': 'https://ip.example/check',
                           'mapping_mode': '明确不需要目标映射', 'url': 'https://claude.ai/',
                           'chrome_path': 'C:/Chrome/chrome.exe', 'user_data_dir': 'C:/Chrome/User Data',
                           'chrome_profile': 'Profile 2'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())

    def tearDown(self):
        self.root.destroy()
        self.temp.cleanup()

    def detect(self):
        with patch('ui.app.messagebox.showerror'):
            self.app.detect()
            wait_for(self.root, lambda: not self.app.busy)

    def detect_with_app(self):
        self.detect()
        self.app.desktop_choice.current(0)
        self.app.desktop_choice.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.detect()

    def launch(self, desktop=True):
        with patch('ui.app.messagebox.showinfo'), patch('ui.app.messagebox.showerror'):
            (self.app.launch_desktop if desktop else self.app.launch_browser)()
            wait_for(self.root, lambda: not self.app.busy)

    def record(self, include_full_ip=False):
        report = self.app._render_report(include_full_ip)
        return [line for line in report.splitlines() if line.startswith('最近一次')], report

    def test_empty_record_before_any_detection_or_launch(self):
        lines, report = self.record()
        self.assertIn('最近一次检测与启动记录（只是记录，不能作为启动依据；关闭助手后不保留）：', report)
        self.assertIn('最近一次检测：本次运行暂无', report)
        self.assertIn('最近一次启动：本次运行暂无', report)

    def test_record_sits_after_the_detection_section_and_before_monitoring(self):
        _, report = self.record()
        self.assertLess(report.index('启动前检测不证明防直连或断连保护。'), report.index('最近一次检测与启动记录'))
        self.assertLess(report.index('最近一次启动：'), report.index(self.app.monitor_summary.get()))

    def test_desktop_launch_after_detection_is_recorded_while_header_stays_undetected(self):
        self.detect_with_app()
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.launch()
        self.assertEqual(self.backend.launches, ['desktop'])
        lines, report = self.record()
        self.assertIn('检测时间：未检测', report)
        detection, launch = lines[1], lines[2]
        self.assertRegex(detection, r'^最近一次检测：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4} · ')
        self.assertIn('共同检测：通过 · 桌面启动前条件：通过 · 网页端：未确认 · 当前已过期', detection)
        self.assertRegex(launch, r'^最近一次启动：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4} · 桌面端（普通启动） · ')
        self.assertTrue(launch.endswith('应用激活请求已成功返回；实际出口和代理参数是否生效仍需确认'))
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_each_launch_outcome_has_its_fixed_text(self):
        cases = [
            (LaunchResult('fail', 'PRIVATE_TEST_VALUE'), '未能启动（启动前检查或启动未通过）'),
            (LaunchResult('unknown', '启动前代理监听归属发生变化或无法确认'), '已阻止启动（启动前代理监听归属变化或无法确认）'),
            (LaunchResult('unknown', 'PRIVATE_TEST_VALUE', pid=12), '已发起应用激活；实际出口和代理参数是否生效尚未确认'),
            (LaunchResult('pass', 'PRIVATE_TEST_VALUE', pid=12), '应用激活请求已成功返回；实际出口和代理参数是否生效仍需确认'),
            (None, '无法确认应用是否已启动'),
        ]
        for outcome, text in cases:
            with self.subTest(text=text):
                self.backend.outcome = outcome
                self.detect_with_app()
                self.launch()
                launch = self.record()[0][2]
                self.assertTrue(launch.endswith(' · 桌面端（普通启动） · ' + text), launch)
                self.assertNotIn('PRIVATE_TEST_VALUE', self.app._render_report())

    def test_browser_launch_and_monitor_block_are_recorded(self):
        self.backend.result = passing(Status.PASS)
        self.app._monitor_browser_bound = lambda: True
        self.detect()
        self.launch(desktop=False)
        self.assertTrue(self.record()[0][2].endswith(' · 网页端（普通启动） · 应用激活请求已成功返回；实际出口和代理参数是否生效仍需确认'))
        self.detect()
        self.app._monitor_worker_allows_launch = lambda session: False
        self.launch(desktop=False)
        self.assertTrue(self.record()[0][2].endswith(' · 网页端（普通启动） · 已阻止网页启动（专用浏览器监测异常或状态未确认）'))

    def test_failed_or_late_detection_is_not_recorded_as_passed(self):
        self.backend.error = RuntimeError('PRIVATE_TEST_VALUE')
        self.detect()
        detection = self.record()[0][1]
        self.assertTrue(detection.endswith(' · 检测未能完成'), detection)
        self.assertNotIn('通过', detection)
        self.backend.error = None
        self.backend.result = Result(common=Status.FAIL, desktop=Status.PASS)
        self.detect()
        self.assertIn('共同检测：失败', self.record()[0][1])

    def test_detection_finished_after_expiry_is_recorded_as_not_used(self):
        original = self.backend.detect

        def late(config, app_id):
            self.now[0] += 61
            return original(config, app_id)
        self.backend.detect = late
        self.detect()
        detection = self.record()[0][1]
        self.assertTrue(detection.endswith(' · 检测结果超时未采用'), detection)
        self.assertNotIn('通过', detection)

    def test_validity_follows_the_sixty_second_window(self):
        self.detect_with_app()
        self.assertTrue(self.record()[0][1].endswith(' · 当前仍有效'))
        self.now[0] += 61
        self.root.update()
        self.assertTrue(self.record()[0][1].endswith(' · 当前已过期'))
        self.app.launch_desktop()
        self.assertEqual(self.backend.launches, [])

    def test_record_never_contains_ip_paths_or_ports(self):
        self.detect_with_app()
        self.launch()
        for full in (False, True):
            lines, _ = self.record(full)
            text = '\n'.join(lines)
            for secret in (FULL_IP, '203.0', 'C:/', '12345', '23456', APP_ID):
                self.assertNotIn(secret, text)


class ProtectedLaunchRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.root.withdraw()
        self.runtime = FakeDesktopRuntime()
        self.app = App(self.root, config_path=Path(self.temp.name) / 'settings.json', desktop_runtime=self.runtime)
        from ui.model import Config
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

    def protect(self):
        self.app.result = DESKTOP_PASS
        self.app._evidence_started = self.app.clock()
        self.app.refresh()
        with patch('ui.app.messagebox.showwarning'):
            self.app.protect_desktop()
        return [line for line in self.app._render_report().splitlines() if line.startswith('最近一次启动：')][0]

    def test_protected_start_request_is_recorded(self):
        self.assertTrue(self.protect().endswith(' · 桌面端（保护启动） · 已请求开始保护'))

    def test_protected_start_failure_is_recorded(self):
        self.runtime.request_start = lambda config, app_id, request_id: False
        self.assertTrue(self.protect().endswith(' · 桌面端（保护启动） · 桌面端保护未能开始'))


if __name__ == '__main__':
    unittest.main()
