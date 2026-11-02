import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'src'))
from src.core.backend import Check, Detection
from src.browser.inspection import BrowserInspection
from ui.adapters import LiveBackend, to_core_config, to_browser_selection, from_inspections
from ui.model import Config, Result, Status, render_report


class ContractTests(unittest.TestCase):
    def test_homepage_403_and_trace_pass_are_distinct_from_desktop_egress(self):
        passed = Check('pass', 'synthetic')
        detection = Detection(passed, passed, passed, Check('unknown', 'Claude 首页返回 HTTP 403，服务未确认'),
                              Check('unknown', 'synthetic'), mapping=passed,
                              _owner_evidence=('synthetic',), target_trace=passed)
        self.assertTrue(detection.ready)
        result = from_inspections(detection, None, desktop_status=passed, application_selected=True, mapping_mode='not_required')
        self.assertIs(result.connectivity, Status.UNKNOWN)
        self.assertIs(result.target_trace, Status.PASS)
        self.assertIs(result.desktop_egress, Status.UNKNOWN)
        self.assertIs(result.common_status, Status.PASS)
        self.assertTrue(result.can_start_desktop)
        self.assertFalse(result.can_start_browser)
        report = render_report(result, Config(mapping_mode='not_required', manager_executable='C:/x.exe', manager_sha256='a' * 64))
        self.assertIn('Claude 首页连通性：未确认', report)
        self.assertIn('Claude 目标请求出口：通过', report)
        self.assertIn('桌面端实际出口：未确认', report)
        self.assertIn('HTTP 403', report)
        self.assertNotIn('封号', report)

    def test_missing_or_failing_trace_cannot_unlock_even_if_other_result_says_pass(self):
        for trace in (Status.UNKNOWN, Status.FAIL):
            result = Result(common=Status.PASS, mapping=Status.PASS, owner=Status.PASS,
                            target_trace=trace, mapping_mode='not_required', desktop=Status.PASS,
                            desktop_instance=Status.PASS)
            self.assertFalse(result.can_start_desktop)
            self.assertFalse(result.can_start_browser)

    def test_simulated_contract_maps_inputs_and_does_not_promote_browser_or_desktop(self):
        config = Config(port=12345, manager_port=23456, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', url='https://claude.ai/', chrome_path='C:/Chrome/chrome.exe', user_data_dir='C:/Chrome/User Data', chrome_profile='Profile 2')
        core = to_core_config(config)
        selection = to_browser_selection(config)
        self.assertEqual((core.proxy_port, core.manager_port, core.ip_url), (12345, 23456, 'https://ip.example/check'))
        self.assertEqual((selection.chrome_executable, selection.user_data_dir, selection.profile_directory), (config.chrome_path, config.user_data_dir, config.chrome_profile))
        success = Check('pass', 'do not expose raw text SECRET')
        detection = Detection(success, success, success, success, Check('unknown', 'SECRET'), mapping=success, _owner_evidence=('synthetic',), target_trace=success)
        browser = BrowserInspection('passed', 'unconfirmed', 'unconfirmed', False, 'SECRET')
        result = from_inspections(detection, browser, mapping_mode='not_required')
        self.assertEqual(result.common, Status.PASS)
        self.assertEqual(result.desktop, Status.UNKNOWN)
        self.assertEqual(result.browser, Status.UNKNOWN)
        self.assertFalse(result.can_start_browser)
        report = render_report(result, config)
        self.assertNotIn('SECRET', report)
        self.assertNotIn('203.0.113.42', report)
        self.assertNotIn('ip.example', report)

    def test_unknown_core_status_never_becomes_common_pass(self):
        success = Check('pass', 'ok')
        unknown = Check('unexpected', 'private detail')
        detection = Detection(success, success, unknown, success, unknown)
        browser = BrowserInspection('passed', 'passed', 'passed', True, 'ignored')
        result = from_inspections(detection, browser, mapping_mode='not_required')
        self.assertIs(result.common, Status.UNKNOWN)
        self.assertFalse(result.can_start_browser)

    def test_live_adapter_uses_core_contract_without_real_calls(self):
        config = Config(port=12345, manager_port=23456, manager_executable='C:/Trusted/Proxy Manager.exe', manager_sha256='a' * 64, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai', url='https://claude.ai/', chrome_path='C:/Chrome/chrome.exe', user_data_dir='C:/Chrome/User Data', chrome_profile='Profile 2')
        passed = Check('pass', 'sensitive SECRET')
        detection = Detection(passed, passed, passed, passed, Check('unknown', 'sensitive SECRET'), mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        browser = BrowserInspection('passed', 'unconfirmed', 'unconfirmed', False, 'SECRET')
        with patch('src.core.backend.detect', return_value=detection) as detect, patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed), patch('src.browser.inspection.inspect_selection', return_value=browser), patch('src.core.backend.launch_desktop', return_value=None) as launch:
            adapter = LiveBackend()
            detect.assert_not_called()
            probe = adapter.detect(config, 'app-id')
            self.assertTrue(probe.result.can_start_desktop)
            self.assertFalse(probe.result.can_start_browser)
            self.assertIs(probe.result.desktop_egress, Status.UNKNOWN)
            self.assertNotIn('SECRET', render_report(probe.result, config))
            adapter.launch_desktop(config, 'app-id')
            self.assertEqual(launch.call_args.args[1], 'app-id')
            self.assertEqual(launch.call_args.args[0].manager_port, 23456)
            self.assertEqual(launch.call_args.args[0].expected_zone, 'sample-zone')
            self.assertEqual(launch.call_args.args[0].required_reverse_mappings, ('192.0.2.5 claude.ai',))
            self.assertEqual(launch.call_args.args[0].manager_sha256, 'a' * 64)

    def test_live_adapter_allows_desktop_only_configuration(self):
        config = Config(port=12345, manager_port=23456, manager_executable='C:/Trusted/Proxy Manager.exe', manager_sha256='a' * 64, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai')
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed), patch('src.browser.inspection.inspect_selection') as browser:
            probe = LiveBackend().detect(config, 'app-id')
        browser.assert_not_called()
        self.assertTrue(probe.result.can_start_desktop)
        self.assertEqual(probe.result.browser_status, Status.UNKNOWN)

    def test_missing_mapping_evidence_is_not_pass(self):
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''))
        browser = BrowserInspection('passed', 'unconfirmed', 'unconfirmed', False, '')
        result = from_inspections(detection, browser, mapping_mode='required', desktop_status=passed, application_selected=True)
        self.assertEqual(result.common, Status.UNKNOWN)
        self.assertEqual(result.common_status, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)

    def test_desktop_discovery_failure_does_not_erase_browser_check(self):
        config = Config(port=12345, manager_port=23456, manager_executable='C:/Trusted/Proxy Manager.exe', manager_sha256='a' * 64, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai', url='https://claude.ai/', chrome_path='C:/Chrome/chrome.exe', user_data_dir='C:/Chrome/User Data', chrome_profile='Profile 2')
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        browser = BrowserInspection('passed', 'unconfirmed', 'unconfirmed', False, '')
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', side_effect=OSError('SECRET')), patch('src.core.backend.desktop_status', return_value=passed), patch('src.browser.inspection.inspect_selection', return_value=browser):
            probe = LiveBackend().detect(config, None)
        self.assertIs(probe.result.common_status, Status.PASS)
        self.assertIs(probe.result.browser_input, Status.PASS)
        self.assertIs(probe.result.desktop, Status.UNKNOWN)

    def test_required_mapping_stays_blocked_without_user_expectations(self):
        config = Config(port=12345, manager_port=23456, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='required')
        passed = Check('pass', 'ok')
        detection = SimpleNamespace(manager=passed, port=passed, exit_ip=passed, claude=passed, desktop_egress=Check('unknown', ''), mapping=passed)
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed), patch('src.core.backend.launch_desktop') as launch:
            adapter = LiveBackend()
            result = adapter.detect(config, 'app-id').result
            self.assertIs(result.common, Status.UNKNOWN)
            self.assertFalse(result.can_start_desktop)
            with self.assertRaises(RuntimeError):
                adapter.launch_desktop(config, 'app-id')
            launch.assert_not_called()

    def test_core_not_ready_blocks_ui_even_if_user_marks_mapping_not_required(self):
        config = Config(port=12345, manager_port=23456, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required')
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''))
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed):
            result = LiveBackend().detect(config, 'app-id').result
        self.assertIs(result.common, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)

    def test_missing_zone_stays_unknown_even_with_other_checks_simulated_pass(self):
        config = Config(port=32001, manager_port=32002, manager_executable='D:/Trusted/Proxy Manager.exe',
                        manager_sha256='b' * 64, expected_ip='198.51.100.92',
                        ip_url='https://ip.example/check', mapping_mode='not_required')
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed, _owner_evidence=('synthetic',))
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed):
            result = LiveBackend().detect(config, 'app-id').result
        self.assertIs(result.common_status, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)
        self.assertIn('mapping_input_required', result.reason_codes)

    def test_complete_checks_without_core_owner_evidence_stay_unknown(self):
        config = Config(port=12345, manager_port=23456, manager_executable='C:/Trusted/Proxy Manager.exe', manager_sha256='a' * 64, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', expected_zone='sample-zone')
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed)
        with patch('src.core.backend.detect', return_value=detection), patch('src.core.backend.discover_desktop', return_value=('app-id',)), patch('src.core.backend.desktop_status', return_value=passed):
            result = LiveBackend().detect(config, 'app-id').result
        self.assertIs(result.owner, Status.UNKNOWN)
        self.assertIs(result.common_status, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)

    def test_observed_ip_is_redacted_in_default_report(self):
        passed = Check('pass', 'ok')
        detection = Detection(passed, passed, passed, passed, Check('unknown', ''), observed_ip='198.51.100.19')
        result = from_inspections(detection, None, mapping_mode='not_required')
        report = render_report(result, Config(mapping_mode='not_required'))
        self.assertNotIn('198.51.100.19', report)
        self.assertIn('198.51.*.*', report)

    def test_only_exact_known_403_message_is_rendered_and_not_arbitrary_core_text(self):
        passed = Check('pass', '')
        for message in ('HTTP 403 SECRET', 'Claude 首页返回 HTTP 403，服务未确认 SECRET',
                        'Claude 首页返回 HTTP 500，服务未确认'):
            with self.subTest(message=message):
                detection = Detection(passed, passed, passed, Check('unknown', message), passed, mapping=passed, _owner_evidence=('synthetic',))
                result = from_inspections(detection, None, mapping_mode='not_required')
                report = render_report(result, Config(manager_executable='C:/x.exe', manager_sha256='a' * 64))
                self.assertNotIn('403', report)
                self.assertNotIn('SECRET', report)
                self.assertIs(result.owner, Status.PASS)



if __name__ == '__main__':
    unittest.main()
