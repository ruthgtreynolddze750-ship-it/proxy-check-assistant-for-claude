import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.model import Config, Result, Status, load_config, save_config, render_report


def valid_config(**kwargs):
    fields = dict(port=12345, manager_port=23456, expected_ip='203.0.113.42', ip_url='https://ip.example/check', mapping_mode='not_required', url='https://claude.ai/', chrome_path='C:/Chrome/chrome.exe', user_data_dir='C:/Chrome/User Data', chrome_profile='Profile 2')
    fields.update(kwargs)
    return Config(**fields)


class InterfaceTests(unittest.TestCase):
    def test_new_machine_starts_without_local_values_or_assumed_results(self):
        config = Config()
        self.assertEqual((config.port, config.manager_port), (0, 0))
        for value in (config.expected_ip, config.expected_zone, config.ip_url,
                      config.manager_executable, config.manager_sha256, config.chrome_path,
                      config.user_data_dir, config.chrome_profile):
            self.assertEqual(value, '')
        self.assertEqual(config.mapping_mode, 'unknown')
        with self.assertRaises(ValueError):
            config.validate()
        self.assertIn('共同检测：未确认', render_report(Result(), config))
        self.assertFalse(Result().can_start_browser)
        self.assertFalse(Result().can_start_desktop)

    def test_separate_hosts_round_trip_actual_inputs_without_report_secrets(self):
        import json
        hosts = [
            valid_config(port=12001, manager_port=12002, expected_ip='192.0.2.41', expected_zone='host-one',
                         chrome_path='C:/HostOne/chrome.exe', user_data_dir='C:/HostOne/Data'),
            valid_config(port=32001, manager_port=32002, expected_ip='198.51.100.92', expected_zone='host-two',
                         chrome_path='D:/HostTwo/chrome.exe', user_data_dir='D:/HostTwo/Data'),
        ]
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / str(i) / 'settings.json' for i in range(2)]
            for path, config in zip(paths, hosts):
                save_config(path, config)
                self.assertEqual(load_config(path), config)
                raw = json.loads(path.read_text(encoding='utf-8'))
                self.assertTrue({'password', 'cookie', 'token', 'chat'}.isdisjoint(raw))
                report = render_report(Result(observed_ip=config.expected_ip), config)
                for value in (config.expected_ip, config.expected_zone, config.chrome_path, config.user_data_dir, config.ip_url):
                    self.assertNotIn(value, report)
            self.assertNotEqual(load_config(paths[0]).port, load_config(paths[1]).port)
            self.assertNotEqual(load_config(paths[0]).expected_zone, load_config(paths[1]).expected_zone)

    def test_config_round_trip_and_invalid_config_does_not_replace_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            config = valid_config()
            save_config(path, config)
            self.assertEqual(load_config(path), config)
            with self.assertRaises(ValueError):
                save_config(path, Config(port=0))
            self.assertEqual(load_config(path), config)

    def test_credentials_and_url_query_are_rejected(self):
        for url in ('https://user:password@claude.ai/', 'https://claude.ai/?token=secret', 'https://claude.ai/#secret'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                valid_config(url=url).validate()

    def test_detection_url_excludes_credentials_query_local_and_literal_ip(self):
        for url in ('https://user:secret@example.com/ip', 'https://example.com/ip?token=secret', 'http://example.com/ip', 'https://127.0.0.1/', 'https://localhost/', 'https://example.com/#secret'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                valid_config(ip_url=url).validate()

    def test_config_repr_does_not_expose_ip_or_detection_url(self):
        self.assertNotIn('203.0.113.42', repr(valid_config()))
        self.assertNotIn('ip.example', repr(valid_config()))

    def test_browser_pass_cannot_override_unconfirmed_identity_or_proxy(self):
        result = Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS, mapping_mode='not_required', browser=Status.PASS, browser_input=Status.PASS)
        self.assertFalse(result.can_start_browser)
        result.browser_identity = Status.PASS
        self.assertFalse(result.can_start_browser)
        result.browser_proxy = Status.PASS
        self.assertTrue(result.can_start_browser)
        result.browser_input = Status.FAIL
        self.assertFalse(result.can_start_browser)

    def test_existing_legacy_configuration_is_preserved_for_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text('{"port":12345,"expected_ip":"203.0.113.42","url":"https://claude.ai/","chrome_path":"C:/Chrome/chrome.exe","chrome_profile":"Profile 2"}', encoding='utf-8')
            loaded = load_config(path)
            self.assertEqual(loaded.port, 12345)
            self.assertEqual(loaded.chrome_profile, 'Profile 2')
            with self.assertRaises(ValueError):
                loaded.validate()

    def test_malformed_config_file_is_rejected_without_crash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text('{"port": 12345, "expected_ip": null, "url": "https://claude.ai/", "chrome_path": "x", "chrome_profile": "y"}', encoding='utf-8')
            with self.assertRaises(ValueError):
                load_config(path)

    def test_unknown_is_not_startable(self):
        result = Result()
        self.assertFalse(result.can_start_desktop)
        self.assertFalse(result.can_start_browser)
        self.assertIn('未确认', render_report(result, Config()))

    def test_start_permissions_require_common_and_individual_pass(self):
        result = Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS, owner=Status.PASS, mapping_mode='not_required', desktop=Status.PASS, desktop_instance=Status.PASS, browser=Status.UNKNOWN)
        self.assertTrue(result.can_start_desktop)
        self.assertFalse(result.can_start_browser)
        result.common = Status.FAIL
        self.assertFalse(result.can_start_desktop)

    def test_required_mapping_must_pass_and_unknown_policy_cannot_pass(self):
        result = Result(common=Status.PASS, target_trace=Status.PASS, owner=Status.PASS, desktop=Status.PASS, desktop_instance=Status.PASS, mapping_mode='required')
        self.assertFalse(result.can_start_desktop)
        self.assertIn('共同检测：未确认', render_report(result, valid_config(mapping_mode='required')))
        result.mapping = Status.FAIL
        self.assertFalse(result.can_start_desktop)
        result.mapping = Status.PASS
        self.assertTrue(result.can_start_desktop)
        result.mapping_mode = 'unknown'
        self.assertFalse(result.can_start_desktop)
        self.assertIn('映射要求：未确认', render_report(result, valid_config(mapping_mode='unknown')))

    def test_common_config_can_save_without_browser_paths(self):
        config = valid_config(chrome_path='', user_data_dir='', chrome_profile='')
        config.validate_common()
        config.validate_desktop()
        with self.assertRaises(ValueError):
            config.validate_browser()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            save_config(path, config)
            self.assertEqual(load_config(path), config)

    def test_invalid_browser_paths_do_not_block_desktop(self):
        config = valid_config(chrome_path='missing.exe', user_data_dir='relative', chrome_profile='bad/name')
        config.validate_desktop()
        with self.assertRaises(ValueError):
            config.validate_browser()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            save_config(path, config)
            self.assertEqual(load_config(path), config)

    def test_previous_eight_field_config_keeps_values_and_requires_mapping_choice(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text('{"port":12345,"manager_port":23456,"expected_ip":"203.0.113.42","ip_url":"https://ip.example/check","url":"https://claude.ai/","chrome_path":"C:/Chrome/chrome.exe","user_data_dir":"C:/Chrome/User Data","chrome_profile":"Profile 2"}', encoding='utf-8')
            config = load_config(path)
            self.assertEqual(config.port, 12345)
            self.assertEqual(config.mapping_mode, 'unknown')

    def test_mapping_expectations_are_explicit_validated_and_persisted(self):
        config = valid_config(mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai; 192.0.2.6 example.org')
        self.assertEqual(config.required_mappings(), ('192.0.2.5 claude.ai', '192.0.2.6 example.org'))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            save_config(path, config)
            self.assertEqual(load_config(path), config)
        self.assertNotIn('sample-zone', repr(config))
        self.assertNotIn('192.0.2.5', repr(config))
        with self.assertRaises(ValueError):
            valid_config(mapping_targets='password=SECRET').validate()

    def test_previous_mapping_mode_config_is_preserved_without_invented_expectations(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text('{"port":12345,"manager_port":23456,"expected_ip":"203.0.113.42","ip_url":"https://ip.example/check","mapping_mode":"required","url":"https://claude.ai/","chrome_path":"","user_data_dir":"","chrome_profile":""}', encoding='utf-8')
            config = load_config(path)
            self.assertEqual(config.mapping_mode, 'required')
            self.assertEqual(config.expected_zone, '')
            self.assertEqual(config.required_mappings(), ())

    def test_previous_complete_config_leaves_manager_trust_unconfirmed(self):
        import json
        old = valid_config(mapping_mode='required', expected_zone='sample-zone', mapping_targets='192.0.2.5 claude.ai')
        from dataclasses import asdict
        data = asdict(old)
        data.pop('manager_executable')
        data.pop('manager_sha256')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            loaded = load_config(path)
            self.assertEqual(loaded.expected_zone, 'sample-zone')
            self.assertEqual(loaded.manager_executable, '')
            self.assertEqual(loaded.manager_sha256, '')
            self.assertNotIn('manager_sha256', path.read_text(encoding='utf-8'))

    def test_trusted_manager_fields_are_optional_but_checked_and_hidden(self):
        config = valid_config(manager_executable='C:/Trusted/Proxy Manager.exe', manager_sha256='a' * 64)
        config.validate_common()
        self.assertNotIn('Trusted', repr(config))
        self.assertNotIn('a' * 64, repr(config))
        self.assertNotIn('Trusted', render_report(Result(), config))
        self.assertNotIn('a' * 64, render_report(Result(), config))
        for fields in ({'manager_executable':'relative.exe'}, {'manager_sha256':'not-a-hash'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                valid_config(**fields).validate_common()

    def test_owner_unknown_overrides_otherwise_passing_result(self):
        result = Result(common=Status.PASS, mapping=Status.PASS, mapping_mode='required', desktop=Status.PASS, desktop_instance=Status.PASS)
        self.assertEqual(result.common_status, Status.UNKNOWN)
        self.assertFalse(result.can_start_desktop)
        self.assertIn('监听归属与可信程序：未确认', render_report(result, valid_config(mapping_mode='required')))

    def test_report_uses_allowlist_and_masks_ips_by_default(self):
        config = Config(port=12345, expected_ip='203.0.113.42', url='https://claude.ai/', chrome_path='C:/secret/credentials.exe')
        result = Result(common=Status.PASS, desktop=Status.UNKNOWN, browser=Status.FAIL, observed_ip='198.51.100.19')
        report = render_report(result, config)
        self.assertNotIn('203.0.113.42', report)
        self.assertNotIn('198.51.100.19', report)
        self.assertNotIn('credentials', report)
        self.assertIn('独立测试请求', report)
        self.assertIn('203.0.113.42', render_report(result, config, include_full_ip=True))

    def test_malformed_observed_ip_is_not_in_report(self):
        report = render_report(Result(observed_ip='password=SECRET'), Config())
        self.assertNotIn('SECRET', report)

    def test_report_renders_only_known_reason_codes(self):
        report = render_report(Result(reason_codes=('proxy_unavailable', 'password=SECRET')), Config())
        self.assertIn('代理入口不可用', report)
        self.assertNotIn('SECRET', report)


if __name__ == '__main__':
    unittest.main()
