import json
import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'src'))
from src.core import backend
from ui.adapters import LiveBackend
from ui.app import App
from ui.model import Config, Status, render_report, save_config, load_config

TRUSTED_PATH = 'C:/Trusted/Proxy Manager.exe'
TRUSTED_HASH = 'a' * 64
OWNER = {'pid': 42, 'started': '123456', 'path': TRUSTED_PATH}


def successful_requests(port, url, timeout, **kwargs):
    if url == 'https://claude.ai/cdn-cgi/trace':
        return b'h=claude.ai\nip=203.0.113.42\n'
    return b'203.0.113.42'


class FakeResponse:
    status = 200
    def __init__(self, payload):
        self.payload = payload
    def read(self, *args):
        return json.dumps(self.payload).encode()


class ManagerConnection:
    mapping = '192.0.2.5 claude.ai'
    def __init__(self, host, port, timeout):
        assert host == '127.0.0.1'
    def request(self, method, path, **kwargs):
        self.path = path
    def getresponse(self):
        if self.path == '/api/proxies_running':
            return FakeResponse([{'port': 12345, 'zone': 'sample-zone', 'reverse_lookup_values': [self.mapping], 'password': 'SECRET'}])
        if self.path == '/api/zones':
            return FakeResponse({'zones': [{'name': 'sample-zone', 'plan': {'type': 'static_res'}, 'password': 'SECRET'}]})
        return FakeResponse({})
    def close(self):
        pass


class CoreIntegrationTests(unittest.TestCase):
    def test_user_expectations_drive_real_core_and_launch_rechecks_mapping(self):
        config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai')
        ManagerConnection.mapping = '192.0.2.5 claude.ai'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            save_config(path, config)
            config = load_config(path)
            with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')), patch.object(backend, '_claude_running', return_value=backend.Check('pass', '')), patch.object(backend, '_activate_application', return_value=123) as activate:
                adapter = LiveBackend()
                probe = adapter.detect(config, 'app-id')
                self.assertIs(probe.result.mapping, Status.PASS)
                self.assertIs(probe.result.common_status, Status.PASS)
                self.assertTrue(probe.result.can_start_desktop)
                self.assertFalse(probe.result.can_start_browser)
                report = render_report(probe.result, config)
                self.assertNotIn('203.0.113.42', report)
                self.assertNotIn('SECRET', report)
                self.assertIn('203.0.*.*', report)
                self.assertIn('203.0.113.42', render_report(probe.result, config, True))
                ManagerConnection.mapping = '192.0.2.5 wrong.example'
                mismatch = adapter.detect(config, 'app-id').result
                self.assertIs(mismatch.mapping, Status.FAIL)
                self.assertIs(mismatch.common_status, Status.FAIL)
                self.assertFalse(mismatch.can_start_desktop)
                outcome = adapter.launch_desktop(config, 'app-id')
                self.assertEqual(outcome.status, 'fail')
                activate.assert_not_called()

    def test_detected_mapping_is_not_substituted_for_missing_user_expectation(self):
        config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required', expected_zone='sample-zone')
        with patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')), patch.object(backend, '_manager', return_value=backend.Check('pass', '')), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, '_fetch_manager_json') as fetch:
            probe = LiveBackend().detect(config, 'app-id')
        self.assertFalse(probe.result.can_start_desktop)
        self.assertIs(probe.result.mapping, Status.UNKNOWN)
        fetch.assert_not_called()

    def test_explicit_not_required_still_verifies_user_expected_isp_zone(self):
        config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', expected_zone='sample-zone')
        with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')):
            result = LiveBackend().detect(config, 'app-id').result
            self.assertTrue(result.can_start_desktop)
            self.assertIn('ISP 区域核验（不要求映射）：通过', render_report(result, config))
            config.expected_zone = 'different-zone'
            mismatch = LiveBackend().detect(config, 'app-id').result
            self.assertIs(mismatch.mapping, Status.FAIL)
            self.assertFalse(mismatch.can_start_desktop)

    def test_window_to_real_core_to_redacted_report_with_simulated_responses(self):
        ManagerConnection.mapping = '192.0.2.5 claude.ai'
        with tempfile.TemporaryDirectory() as folder:
            window = tk.Tk()
            try:
                app = App(window, backend=LiveBackend(), config_path=Path(folder) / 'config.json')
                for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': TRUSTED_PATH, 'manager_sha256': TRUSTED_HASH, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '需要目标映射', 'expected_zone': 'sample-zone', 'mapping_targets': '192.0.2.5 claude.ai'}.items():
                    app.fields[key].set(value)
                with patch('ui.app.messagebox.showinfo'):
                    self.assertTrue(app.save_settings())
                with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')):
                    def wait():
                        deadline = time.monotonic() + 3
                        while app.busy and time.monotonic() < deadline:
                            window.update()
                            time.sleep(.01)
                        self.assertFalse(app.busy)
                    app.detect()
                    wait()
                    app.desktop_choice.current(0)
                    app.desktop_choice.event_generate('<<ComboboxSelected>>')
                    window.update()
                    app.detect()
                    wait()
                    self.assertEqual(str(app.desktop_button['state']), 'normal')
                    self.assertEqual(str(app.browser_button['state']), 'disabled')
                    report_file = Path(folder) / 'report.txt'
                    with patch('ui.app.filedialog.asksaveasfilename', return_value=str(report_file)):
                        app.export_report()
                    report = report_file.read_text(encoding='utf-8')
                    self.assertIn('目标映射与 ISP 区域：通过', report)
                    self.assertIn('203.0.*.*', report)
                    self.assertNotIn('203.0.113.42', report)
                    self.assertNotIn('SECRET', report)
                    self.assertIn('监听归属与可信程序：通过', report)
                    self.assertNotIn(TRUSTED_PATH, report)
                    self.assertNotIn(TRUSTED_HASH, report)
                    app.full_ip.set(True)
                    app.refresh()
                    self.assertIn('203.0.113.42', app.report.get('1.0', 'end'))
                    app.fields['mapping_targets'].set('192.0.2.6 claude.ai')
                    self.assertEqual(str(app.desktop_button['state']), 'disabled')
            finally:
                window.destroy()

    def test_missing_trust_or_different_owner_is_unknown_without_proxy_request(self):
        for scenario in ('missing', 'other_owner', 'different_hash'):
            config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', expected_zone='sample-zone')
            if scenario == 'missing':
                config.manager_sha256 = ''
            proxy_owner = dict(OWNER, pid=77) if scenario == 'other_owner' else OWNER
            digest = 'b' * 64 if scenario == 'different_hash' else TRUSTED_HASH
            with self.subTest(scenario=scenario), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [proxy_owner])), patch.object(backend, '_file_sha256', return_value=digest), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy') as request:
                result = LiveBackend().detect(config, 'app-id').result
            self.assertIs(result.owner, Status.UNKNOWN)
            self.assertIs(result.common_status, Status.UNKNOWN)
            self.assertFalse(result.can_start_desktop)
            self.assertNotIn(TRUSTED_HASH, render_report(result, config))
            self.assertNotIn(TRUSTED_PATH, render_report(result, config))
            request.assert_not_called()

    def test_homepage_403_and_unconfirmed_trace_preserve_owner_and_block(self):
        config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', expected_zone='sample-zone')
        def request(port, url, timeout, **kwargs):
            if url == config.ip_url:
                return b'203.0.113.42'
            raise backend.ProxyHTTPError(403)
        with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=request), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')):
            result = LiveBackend().detect(config, 'app-id').result
        self.assertIs(result.owner, Status.PASS)
        self.assertIs(result.connectivity, Status.UNKNOWN)
        self.assertIs(result.common_status, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)
        self.assertFalse(result.can_start_browser)
        report = render_report(result, config)
        self.assertIn('监听归属与可信程序：通过', report)
        self.assertIn('Claude 首页连通性：未确认', report)
        self.assertIn('Claude 目标请求出口：未确认', report)
        self.assertIn('403', report)
        self.assertNotIn('封号', report)
        self.assertNotIn('SECRET', report)
        self.assertNotIn(TRUSTED_PATH, report)

    def test_window_and_export_show_403_and_unconfirmed_trace_without_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            window = tk.Tk()
            try:
                app = App(window, backend=LiveBackend(), config_path=Path(folder) / 'config.json')
                for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': TRUSTED_PATH, 'manager_sha256': TRUSTED_HASH, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
                    app.fields[key].set(value)
                with patch('ui.app.messagebox.showinfo'):
                    self.assertTrue(app.save_settings())
                def request(port, url, timeout, **kwargs):
                    if url == 'https://ip.example/check':
                        return b'203.0.113.42'
                    raise backend.ProxyHTTPError(403)
                with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=request), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')):
                    app.detect()
                    deadline = time.monotonic() + 3
                    while app.busy and time.monotonic() < deadline:
                        window.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                    app.desktop_choice.current(0)
                    app.desktop_choice.event_generate('<<ComboboxSelected>>')
                    window.update()
                    app.detect()
                    deadline = time.monotonic() + 3
                    while app.busy and time.monotonic() < deadline:
                        window.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                text = app.report.get('1.0', 'end')
                self.assertIn('监听归属与可信程序：通过', text)
                self.assertIn('Claude 首页连通性：未确认', text)
                self.assertIn('Claude 目标请求出口：未确认', text)
                self.assertIn('HTTP 403', text)
                self.assertNotIn('封号', text)
                self.assertNotIn('SECRET', text)
                self.assertEqual(str(app.desktop_button['state']), 'disabled')
                self.assertEqual(str(app.browser_button['state']), 'disabled')
                report_file = Path(folder) / 'report.txt'
                with patch('ui.app.filedialog.asksaveasfilename', return_value=str(report_file)):
                    app.export_report()
                exported = report_file.read_text(encoding='utf-8')
                self.assertIn('HTTP 403', exported)
                self.assertNotIn('SECRET', exported)
                self.assertNotIn('203.0.113.42', exported)
            finally:
                window.destroy()

    def test_window_distinguishes_homepage_403_trace_and_desktop_egress(self):
        with tempfile.TemporaryDirectory() as folder:
            window = tk.Tk()
            try:
                app = App(window, backend=LiveBackend(), config_path=Path(folder) / 'config.json')
                for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': TRUSTED_PATH, 'manager_sha256': TRUSTED_HASH, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
                    app.fields[key].set(value)
                with patch('ui.app.messagebox.showinfo'):
                    self.assertTrue(app.save_settings())
                trace = {'value': b'h=claude.ai\nip=203.0.113.42\n'}
                def request(port, url, timeout, **kwargs):
                    if url == 'https://ip.example/check':
                        return b'203.0.113.42'
                    if url == 'https://claude.ai/cdn-cgi/trace':
                        if trace['value'] is None:
                            raise OSError('PRIVATE_TEST_VALUE')
                        return trace['value']
                    raise backend.ProxyHTTPError(403)
                def wait():
                    deadline = time.monotonic() + 3
                    while app.busy and time.monotonic() < deadline:
                        window.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', return_value=([OWNER], [OWNER])), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=request), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')), patch.object(backend, '_activate_application') as activate:
                    app.detect()
                    wait()
                    app.desktop_choice.current(0)
                    app.desktop_choice.event_generate('<<ComboboxSelected>>')
                    window.update()
                    for value, expected_trace, expected_button in ((b'h=claude.ai\nip=203.0.113.42\n', '通过', 'normal'),
                                                                    (None, '未确认', 'disabled'),
                                                                    (b'h=claude.ai\nip=198.51.100.9\n', '失败', 'disabled')):
                        with self.subTest(trace=expected_trace):
                            trace['value'] = value
                            app.detect()
                            wait()
                            text = app.report.get('1.0', 'end')
                            self.assertIn('Claude 首页连通性：未确认', text)
                            self.assertIn('HTTP 403', text)
                            self.assertIn('Claude 目标请求出口：' + expected_trace, text)
                            self.assertIn('桌面端实际出口：未确认', text)
                            self.assertIn('浏览器进程身份：未确认', text)
                            self.assertNotIn('PRIVATE_TEST_VALUE', text)
                            self.assertNotIn('封号', text)
                            self.assertEqual(str(app.desktop_button['state']), expected_button)
                            self.assertEqual(str(app.browser_button['state']), 'disabled')
                            report_file = Path(folder) / ('trace-' + expected_trace + '.txt')
                            with patch('ui.app.filedialog.asksaveasfilename', return_value=str(report_file)):
                                app.export_report()
                            exported = report_file.read_text(encoding='utf-8')
                            self.assertIn('HTTP 403', exported)
                            self.assertIn('Claude 目标请求出口：' + expected_trace, exported)
                            self.assertIn('桌面端实际出口：未确认', exported)
                            self.assertNotIn('203.0.113.42', exported)
                    activate.assert_not_called()
            finally:
                window.destroy()


    def test_owner_change_before_activation_rejects_launch(self):
        config = Config(port=12345, manager_port=23456, manager_executable=TRUSTED_PATH, manager_sha256=TRUSTED_HASH, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', expected_zone='sample-zone')
        changed = dict(OWNER, started='999999')
        snapshots = [([OWNER], [OWNER]), ([OWNER], [OWNER]), ([OWNER], [changed])]
        with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', side_effect=snapshots), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, '_claude_running', return_value=backend.Check('pass', '')), patch.object(backend, '_activate_application') as activate:
            result = LiveBackend().launch_desktop(config, 'app-id')
        self.assertEqual(result.status, 'unknown')
        activate.assert_not_called()

    def test_window_reports_owner_change_as_blocked_without_activation(self):
        changed = dict(OWNER, started='999999')
        snapshots = [([OWNER], [OWNER])] * 6 + [([OWNER], [changed])]
        with tempfile.TemporaryDirectory() as folder:
            window = tk.Tk()
            try:
                app = App(window, backend=LiveBackend(), config_path=Path(folder) / 'config.json')
                for key, value in {'port': '12345', 'manager_port': '23456', 'manager_executable': TRUSTED_PATH, 'manager_sha256': TRUSTED_HASH, 'expected_ip': '203.0.113.42', 'ip_url': 'https://ip.example/check', 'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
                    app.fields[key].set(value)
                with patch('ui.app.messagebox.showinfo'):
                    self.assertTrue(app.save_settings())
                def wait():
                    deadline = time.monotonic() + 3
                    while app.busy and time.monotonic() < deadline:
                        window.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                with patch.object(backend.http.client, 'HTTPConnection', ManagerConnection), patch.object(backend, '_capture_listener_owners', side_effect=snapshots), patch.object(backend, '_file_sha256', return_value=TRUSTED_HASH), patch.object(backend, '_process_present', return_value=True), patch.object(backend, '_manager_owns_port', return_value=True), patch.object(backend, '_port', return_value=backend.Check('pass', '')), patch.object(backend, '_request_via_proxy', side_effect=successful_requests), patch.object(backend, 'discover_desktop', return_value=('app-id',)), patch.object(backend, 'desktop_status', return_value=backend.Check('pass', '')), patch.object(backend, '_claude_running', return_value=backend.Check('pass', '')), patch.object(backend, '_activate_application') as activate:
                    app.detect()
                    wait()
                    app.desktop_choice.current(0)
                    app.desktop_choice.event_generate('<<ComboboxSelected>>')
                    window.update()
                    app.detect()
                    wait()
                    self.assertEqual(str(app.desktop_button['state']), 'normal')
                    with patch('ui.app.messagebox.showinfo') as info:
                        app.launch_desktop()
                        wait()
                    activate.assert_not_called()
                    self.assertEqual(info.call_args.args[0], '启动已阻止')
                    self.assertIn('归属', info.call_args.args[1])
                    self.assertEqual(str(app.desktop_button['state']), 'disabled')
                    self.assertEqual(str(app.browser_button['state']), 'disabled')
            finally:
                window.destroy()


if __name__ == '__main__':
    unittest.main()
