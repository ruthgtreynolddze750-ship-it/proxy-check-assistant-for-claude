import json
import os
import socket
import threading
import unittest
from unittest.mock import patch

from src.core import backend


class CoreTests(unittest.TestCase):
    def setUp(self):
        owner = patch.object(backend, '_proxy_owner_snapshot', return_value=('manager', 123), create=True)
        owner.start()
        self.owner_patch = owner
        self.addCleanup(owner.stop)

    def config(self, **kwargs):
        data = dict(proxy_port=24001, manager_port=22999,
                    expected_ip='203.0.113.10', ip_url='https://ip.example/test')
        data.update(kwargs)
        return backend.Config(**data)

    def test_matching_test_ip_is_distinct_from_unverified_desktop_egress(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.10"}', b'', b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertFalse(result.ready)
        self.assertEqual(result.desktop_egress.status, 'unknown')
        self.assertNotIn('203.0.113.10', json.dumps(result.report(), ensure_ascii=False))

    def test_mismatch_does_not_allow_launch(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.11"}', b'', b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertFalse(result.ready)
        self.assertEqual(result.exit_ip.status, 'fail')

    def test_another_computer_uses_its_own_port_ip_zone_and_mapping(self):
        config = self.config(proxy_port=25123, manager_port=25124,
                             expected_ip='198.51.100.42', expected_zone='other-zone',
                             mapping_mode='required',
                             required_reverse_mappings=('192.0.2.20 example.test',))
        proxies = [{'port': 25123, 'zone': 'other-zone',
                    'reverse_lookup_values': ['192.0.2.20 example.test']}]
        zones = {'zones': [{'name': 'other-zone', 'plan': {'type': 'static_res'}}]}
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_manager', return_value=passed) as manager, \
             patch.object(backend, '_port', return_value=passed) as port, \
             patch.object(backend, '_manager_owns_port', return_value=True) as owns, \
             patch.object(backend, '_fetch_manager_json', side_effect=[proxies, zones]) as fetch, \
             patch.object(backend, '_request_via_proxy', side_effect=[b'198.51.100.42', b'', b'h=claude.ai\nip=198.51.100.42\n']) as request:
            result = backend.detect(config)
        self.assertTrue(result.ready)
        manager.assert_called_once_with(25124, config.timeout)
        port.assert_called_once_with(25123, config.timeout)
        owns.assert_called_once_with(25124)
        self.assertTrue(all(call.args[0] == 25124 for call in fetch.call_args_list))
        self.assertTrue(all(call.args[0] == 25123 for call in request.call_args_list))
        self.assertEqual(result.exit_ip.status, 'pass')
        self.assertEqual(result.mapping.status, 'pass')

    def test_missing_trust_baseline_does_not_probe_or_allow_launch(self):
        self.owner_patch.stop()
        config = self.config(proxy_port=25123, manager_port=25124,
                             expected_ip='198.51.100.42', expected_zone='other-zone')
        with patch.object(backend, '_capture_listener_owners') as owner, \
             patch.object(backend, '_request_via_proxy') as request:
            result = backend.detect(config)
        self.assertFalse(result.ready)
        self.assertEqual(result.port.status, 'unknown')
        owner.assert_not_called()
        request.assert_not_called()

    def test_proxy_request_failure_does_not_expose_error_or_allow_launch(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=OSError('password=secret')):
            result = backend.detect(self.config())
        self.assertFalse(result.ready)
        self.assertEqual(result.exit_ip.status, 'unknown')
        self.assertNotIn('secret', repr(result))

    def test_invalid_or_credentialed_url_is_rejected_before_network(self):
        with patch.object(backend, '_request_via_proxy') as request:
            result = backend.detect(self.config(ip_url='https://user:secret@ip.example/'))
        self.assertFalse(result.ready)
        request.assert_not_called()
        self.assertNotIn('secret', repr(result))

    def test_existing_claude_is_never_started(self):
        with patch.object(backend, '_claude_running', return_value=backend.Check('fail', '已有实例')), \
             patch.object(backend, 'detect') as detect, patch.object(backend.subprocess, 'Popen') as popen:
            result = backend.launch_desktop(self.config(), 'Claude.exe')
        self.assertEqual(result.status, 'fail')
        detect.assert_not_called()
        popen.assert_not_called()

    def test_unknown_process_state_never_starts(self):
        with patch.object(backend, '_claude_running', return_value=backend.Check('unknown', '无法确认')), \
             patch.object(backend.subprocess, 'Popen') as popen:
            result = backend.launch_desktop(self.config(), 'Claude.exe')
        self.assertEqual(result.status, 'unknown')
        popen.assert_not_called()

    def test_ready_but_existing_instance_before_launch_blocks(self):
        check = backend.Check('pass', '通过')
        detection = backend.Detection(check, check, check, check, backend.Check('unknown', '未确认'), mapping=check, _owner_evidence=('manager', 123), target_trace=check)
        with patch.object(backend, '_claude_running', side_effect=[check, backend.Check('fail', '已有实例')]), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), patch.object(backend, '_activate_application', create=True) as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        self.assertEqual(result.status, 'fail')
        activate.assert_not_called()

    def test_public_ip_only_and_explicit_proxy(self):
        with patch.object(backend.http.client, 'HTTPSConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{}'
            backend._request_via_proxy(24001, 'https://example.test/ip', 2)
        connection.assert_called_once_with('127.0.0.1', 24001, timeout=2, context=unittest.mock.ANY)
        connection.return_value.set_tunnel.assert_called_once_with('example.test', 443)

    def test_connect_request_goes_to_local_proxy_without_fallback(self):
        received = []
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def proxy():
            with listener:
                conn, _ = listener.accept()
                with conn:
                    received.append(conn.recv(4096))
                    conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
        thread = threading.Thread(target=proxy, daemon=True)
        thread.start()
        with self.assertRaises(OSError):
            backend._request_via_proxy(port, 'https://example.test/ip', 2)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(received[0].startswith(b'CONNECT example.test:443 HTTP/'))

    def test_manager_port_without_matching_owner_remains_unknown(self):
        with patch.object(backend, '_process_present', return_value=True), \
             patch.object(backend, '_manager_owns_port', return_value=False), \
             patch.object(backend.http.client, 'HTTPConnection') as connection:
            result = backend._manager(22999, 2)
        self.assertEqual(result.status, 'unknown')
        connection.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows process lookup')
    def test_windows_port_lookup_rejects_unrelated_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            self.assertFalse(backend._manager_owns_port(listener.getsockname()[1]))

    def test_launch_uses_proxy_flag_after_fresh_checks(self):
        check = backend.Check('pass', '通过')
        detection = backend.Detection(check, check, check, check, backend.Check('unknown', '未确认'), mapping=check, _owner_evidence=('manager', 123), target_trace=check)
        with patch.object(backend, '_claude_running', return_value=check), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), \
             patch.object(backend, '_activate_application', return_value=123, create=True) as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        activate.assert_called_once_with('Claude_test!Claude', '--proxy-server=http://127.0.0.1:24001')
        self.assertEqual(result.status, 'unknown')
        self.assertEqual(result.pid, 123)

    def test_launch_uses_the_selected_computers_proxy_port(self):
        passed = backend.Check('pass', '通过')
        detection = backend.Detection(passed, passed, passed, passed,
                                      backend.Check('unknown', '未确认'), mapping=passed,
                                      _owner_evidence=('manager', 123), target_trace=passed)
        with patch.object(backend, '_claude_running', return_value=passed), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), \
             patch.object(backend, '_activate_application', return_value=123) as activate:
            backend.launch_desktop(self.config(proxy_port=25123, manager_port=25124), 'Claude_test!Claude')
        activate.assert_called_once_with('Claude_test!Claude', '--proxy-server=http://127.0.0.1:25123')

    @unittest.skipUnless(os.name == 'nt', 'Windows COM activation ABI')
    def test_activation_interface_receives_application_and_proxy_arguments(self):
        import ctypes
        import uuid
        from unittest.mock import MagicMock

        received = []
        activate_type = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_wchar_p,
                                           ctypes.c_wchar_p, ctypes.c_uint32,
                                           ctypes.POINTER(ctypes.c_uint32))
        release_type = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)

        @activate_type
        def activate(obj, app_id, arguments, options, pid):
            received.append((app_id, arguments, options))
            pid[0] = 4321
            return 0

        @release_type
        def release(obj):
            received.append('released')
            return 0

        vtable = (ctypes.c_void_p * 4)()
        vtable[2] = ctypes.cast(release, ctypes.c_void_p).value
        vtable[3] = ctypes.cast(activate, ctypes.c_void_p).value
        instance = ctypes.pointer(ctypes.cast(vtable, ctypes.POINTER(ctypes.c_void_p)))
        ole = MagicMock()
        ole.CoInitializeEx.return_value = 0

        def create(clsid, outer, context, iid, output):
            received.append((str(uuid.UUID(bytes_le=bytes(clsid._obj.data))),
                             str(uuid.UUID(bytes_le=bytes(iid._obj.data))), context))
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(instance, ctypes.c_void_p)
            return 0

        ole.CoCreateInstance.side_effect = create
        with patch.object(ctypes, 'OleDLL', return_value=ole):
            pid = backend._activate_application('Claude_test!Claude', '--proxy-server=http://127.0.0.1:24001')
        self.assertEqual(pid, 4321)
        self.assertEqual(received, [
            ('45ba127d-10a8-46ea-8ab7-56ea9078943c', '2e941141-7f97-4756-ba1d-9decde894a3d', 4),
            ('Claude_test!Claude', '--proxy-server=http://127.0.0.1:24001', 0),
            'released',
        ])
        ole.CoUninitialize.assert_called_once()

    def test_unregistered_app_id_never_activates(self):
        with patch.object(backend, '_claude_running', return_value=backend.Check('pass', '通过')), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',), create=True), \
             patch.object(backend, '_activate_application', create=True) as activate:
            result = backend.launch_desktop(self.config(), 'Unrelated!App')
        self.assertEqual(result.status, 'unknown')
        activate.assert_not_called()

    def test_cli_same_name_is_not_the_desktop_app(self):
        package = {'aumid': 'Claude_test!Claude', 'executable': r'C:\Apps\Claude\Claude.exe'}
        cli = {'path': r'C:\Users\Alice\.local\bin\claude.exe', 'product': 'Claude Code'}
        with patch.object(backend, '_desktop_snapshot', return_value=([package], [cli])), \
             patch.dict(os.environ, {'USERPROFILE': r'C:\Users\Alice'}):
            self.assertEqual(backend._claude_running().status, 'pass')

    def test_unknown_claude_executable_is_not_assumed_safe(self):
        package = {'aumid': 'Claude_test!Claude', 'executable': r'C:\Apps\Claude\Claude.exe'}
        with patch.object(backend, '_desktop_snapshot', return_value=([package], [{'path': r'C:\Other\Claude.exe', 'product': ''}])):
            self.assertEqual(backend._claude_running().status, 'unknown')

    def test_registered_package_desktop_process_blocks_start(self):
        path = r'C:\Apps\Claude\Claude.exe'
        with patch.object(backend, '_desktop_snapshot', return_value=([{'aumid': 'Claude_test!Claude', 'executable': path}], [{'path': path, 'product': 'Claude'}])):
            self.assertEqual(backend._claude_running().status, 'fail')

    def test_claude_same_host_https_redirect_is_followed_via_proxy(self):
        with patch.object(backend.http.client, 'HTTPSConnection') as connection:
            first = unittest.mock.MagicMock(status=302)
            first.getheader.return_value = '/login'
            second = unittest.mock.MagicMock(status=200)
            second.read.return_value = b'ok'
            connection.return_value.getresponse.side_effect = [first, second]
            body = backend._request_via_proxy(24001, 'https://claude.ai/', 2, allow_same_host_redirects=True)
        self.assertEqual(body, b'ok')
        self.assertEqual(connection.return_value.set_tunnel.call_count, 2)
        self.assertEqual(connection.return_value.request.call_args_list[1].args[:2], ('GET', '/login'))

    def test_redirect_to_another_host_is_rejected(self):
        with patch.object(backend.http.client, 'HTTPSConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            response.getheader.return_value = 'https://elsewhere.example/login'
            with self.assertRaises(OSError):
                backend._request_via_proxy(24001, 'https://claude.ai/', 2, allow_same_host_redirects=True)
            self.assertEqual(connection.call_count, 1)

    def test_https_downgrade_and_redirect_loop_are_rejected(self):
        for location in ('http://claude.ai/login', '/login'):
            with self.subTest(location=location), patch.object(backend.http.client, 'HTTPSConnection') as connection:
                response = connection.return_value.getresponse.return_value
                response.status = 302
                response.getheader.return_value = location
                with self.assertRaises((OSError, ValueError)):
                    backend._request_via_proxy(24001, 'https://claude.ai/', 2, allow_same_host_redirects=True)
                self.assertLessEqual(connection.call_count, 4)

    def test_unknown_or_unreadable_process_path_blocks_start(self):
        with patch.object(backend, '_desktop_snapshot', return_value=([{'aumid': 'Claude_test!Claude', 'executable': r'C:\Apps\Claude\Claude.exe'}], [{'path': None, 'product': None}])):
            self.assertEqual(backend._claude_running().status, 'unknown')

    def test_activation_error_does_not_fall_back_to_executable(self):
        check = backend.Check('pass', '通过')
        detection = backend.Detection(check, check, check, check, backend.Check('unknown', '未确认'), mapping=check, _owner_evidence=('manager', 123), target_trace=check)
        with patch.object(backend, '_claude_running', return_value=check), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), \
             patch.object(backend, '_activate_application', side_effect=OSError('secret')), \
             patch.object(backend.subprocess, 'Popen') as popen:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        self.assertEqual(result.status, 'unknown')
        self.assertNotIn('secret', repr(result))
        popen.assert_not_called()

    def test_missing_mapping_evidence_blocks_even_when_other_checks_pass(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.10"}', b'', b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertEqual(result.mapping.status, 'unknown')
        self.assertFalse(result.ready)

    def test_actual_test_ip_is_masked_by_default_and_explicitly_available(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.11"}', b'', b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertNotIn('203.0.113.11', repr(result))
        self.assertNotIn('203.0.113.11', json.dumps(result.report()))
        self.assertEqual(result.report(include_full_ip=True)['observed_ip'], '203.0.113.11')

    def test_no_actual_ip_when_proxy_request_fails(self):
        with patch.object(backend, '_manager', return_value=backend.Check('pass', '运行中')), \
             patch.object(backend, '_port', return_value=backend.Check('pass', '可连接')), \
             patch.object(backend, '_request_via_proxy', side_effect=OSError('password=secret')):
            result = backend.detect(self.config())
        self.assertIsNone(result.observed_ip)
        self.assertNotIn('secret', json.dumps(result.report()))

    def test_claude_trace_checks_target_and_expected_ip(self):
        good = b'h=claude.ai\nip=203.0.113.10\n'
        with patch.object(backend, '_request_via_proxy', return_value=good) as request:
            result = backend.inspect_claude_trace(self.config())
        self.assertEqual(result.status, 'pass')
        self.assertEqual(request.call_args.args[1], 'https://claude.ai/cdn-cgi/trace')

    def test_claude_trace_mismatch_and_invalid_response_never_pass(self):
        cases = [(b'h=claude.ai\nip=203.0.113.11\n', 'fail'),
                 (b'h=other.example\nip=203.0.113.10\n', 'unknown'),
                 (b'h=claude.ai\nh=claude.ai\nip=203.0.113.10\n', 'unknown'),
                 (b'h=claude.ai\n', 'unknown')]
        for response, status in cases:
            with self.subTest(status=status, response=response), \
                 patch.object(backend, '_request_via_proxy', return_value=response):
                result = backend.inspect_claude_trace(self.config())
            self.assertEqual(result.status, status)

    def test_home_403_is_separate_from_matching_target_trace(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy', side_effect=[
                 b'203.0.113.10', backend.ProxyHTTPError(403), b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertEqual(result.claude.status, 'unknown')
        self.assertIn('403', result.claude.message)
        self.assertEqual(result.target_trace.status, 'pass')
        self.assertTrue(result.ready)
        self.assertEqual(result.desktop_egress.status, 'unknown')

    def test_home_200_cannot_replace_missing_or_mismatched_target_trace(self):
        passed = backend.Check('pass', '通过')
        for response in (b'h=claude.ai\nip=203.0.113.11\n', b'h=claude.ai\n', OSError('unavailable')):
            with self.subTest(response=response), \
                 patch.object(backend, '_manager', return_value=passed), \
                 patch.object(backend, '_port', return_value=passed), \
                 patch.object(backend, '_mapping', return_value=passed), \
                 patch.object(backend, '_request_via_proxy', side_effect=[b'203.0.113.10', b'', response]):
                result = backend.detect(self.config())
            self.assertEqual(result.claude.status, 'pass')
            self.assertNotEqual(result.target_trace.status, 'pass')
            self.assertFalse(result.ready)

    def test_home_403_remains_unknown_when_trace_passes(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'203.0.113.10', backend.ProxyHTTPError(403), b'h=claude.ai\nip=203.0.113.10\n']):
            result = backend.detect(self.config())
        self.assertEqual(result.claude.status, 'unknown')
        self.assertIn('403', result.claude.message)
        self.assertEqual(result.target_trace.status, 'pass')
        self.assertTrue(result.ready)

    def test_trace_mismatch_blocks_desktop_activation_even_with_home_403(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_claude_running', return_value=passed), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy',
                          side_effect=[b'203.0.113.10', backend.ProxyHTTPError(403), b'h=claude.ai\nip=203.0.113.11\n']), \
             patch.object(backend, '_activate_application') as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.detection.claude.status, 'unknown')
        self.assertIn('403', result.detection.claude.message)
        activate.assert_not_called()

    def test_matching_target_trace_allows_activation_with_home_403(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_claude_running', return_value=passed), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy', side_effect=[
                 b'203.0.113.10', backend.ProxyHTTPError(403), b'h=claude.ai\nip=203.0.113.10\n']), \
             patch.object(backend, '_activate_application', return_value=123) as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        activate.assert_called_once_with('Claude_test!Claude', '--proxy-server=http://127.0.0.1:24001')
        self.assertEqual(result.status, 'unknown')
        self.assertEqual(result.detection.claude.status, 'unknown')
        self.assertEqual(result.detection.target_trace.status, 'pass')
        self.assertEqual(result.detection.desktop_egress.status, 'unknown')

    def test_mapping_requires_matching_port_zone_isp_and_explicit_pairs(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        proxies = [{'port': 24001, 'zone': 'work-zone', 'reverse_lookup_values': ['192.0.2.5 claude.ai'], 'password': 'secret'}]
        zones = {'zones': [{'name': 'work-zone', 'plan': {'type': 'static_res'}, 'password': 'secret'}]}
        with patch.object(backend, '_manager_owns_port', return_value=True), \
             patch.object(backend, '_fetch_manager_json', side_effect=[proxies, zones]):
            result = backend._mapping(config)
        self.assertEqual(result.status, 'pass')
        self.assertNotIn('secret', repr(result))

    def test_mapping_never_passes_missing_or_contradictory_evidence(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        for proxy, zone in [
            ({'port': 24001, 'zone': 'work-zone'}, {'name': 'work-zone', 'plan': {'type': 'static_res'}}),
            ({'port': 24001, 'zone': 'other', 'reverse_lookup_values': ['192.0.2.5 claude.ai']}, {'name': 'work-zone', 'plan': {'type': 'static_res'}}),
            ({'port': 24001, 'zone': 'work-zone', 'reverse_lookup_values': ['192.0.2.5 claude.ai']}, {'name': 'work-zone', 'plan': {'type': 'resident'}}),
        ]:
            with self.subTest(proxy=proxy, zone=zone), patch.object(backend, '_manager_owns_port', return_value=True), \
                 patch.object(backend, '_fetch_manager_json', side_effect=[[proxy], {'zones': [zone]}]):
                self.assertNotEqual(backend._mapping(config).status, 'pass')

    def test_mapping_rejects_invalid_config_before_reading_manager(self):
        config = self.config(mapping_mode='required', expected_zone='', required_reverse_mappings=('192.0.2.5 claude.ai',))
        with patch.object(backend, '_fetch_manager_json', create=True) as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_mapping_requires_local_management_owner(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        with patch.object(backend, '_manager_owns_port', return_value=False), \
             patch.object(backend, '_fetch_manager_json', create=True) as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_local_api_discards_sensitive_fields_before_return(self):
        payload = [{'port': 24001, 'zone': 'work-zone', 'password': 'secret',
                    'customer': 'secret', 'ext_proxies': ['user:secret@host'],
                    'reverse_lookup_values': ['192.0.2.5 claude.ai']}]
        with patch.object(backend.http.client, 'HTTPConnection') as conn:
            reply = conn.return_value.getresponse.return_value
            reply.status = 200
            reply.read.return_value = json.dumps(payload).encode()
            result = backend._fetch_manager_json(22999, '/api/proxies_running', 2)
        conn.assert_called_once_with('127.0.0.1', 22999, timeout=2)
        self.assertNotIn('secret', repr(result))
        self.assertTrue(result[0]['ext_proxies'])

    def test_external_proxy_and_alternate_reverse_lookup_cannot_pass(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        base = {'port': 24001, 'zone': 'work-zone', 'reverse_lookup_values': ['192.0.2.5 claude.ai']}
        zones = {'zones': [{'name': 'work-zone', 'plan': {'type': 'static_res'}}]}
        for field in ('ext_proxies', 'reverse_lookup_dns', 'reverse_lookup_file'):
            proxy = dict(base, **{field: True})
            with self.subTest(field=field), patch.object(backend, '_manager_owns_port', return_value=True), \
                 patch.object(backend, '_fetch_manager_json', side_effect=[[proxy], zones]):
                self.assertEqual(backend._mapping(config).status, 'unknown')

    def test_unrecognized_manager_does_not_call_api(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        with patch.object(backend, '_manager_owns_port', return_value=False), \
             patch.object(backend, '_fetch_manager_json') as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_no_mapping_mode_is_unknown_without_reading_management_api(self):
        config = self.config(expected_zone='work-zone', required_reverse_mappings=('192.0.2.5 claude.ai',))
        with patch.object(backend, '_fetch_manager_json') as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_legacy_config_defaults_to_unknown_even_without_mapping_fields(self):
        config = backend.Config(24001, 22999, '203.0.113.10', 'https://ip.example/test')
        self.assertEqual(config.mapping_mode, 'unknown')
        with patch.object(backend, '_fetch_manager_json') as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_required_mode_without_mapping_is_unknown_without_reading_api(self):
        config = self.config(mapping_mode='required', expected_zone='work-zone')
        with patch.object(backend, '_fetch_manager_json') as fetch:
            self.assertEqual(backend._mapping(config).status, 'unknown')
            fetch.assert_not_called()

    def test_launch_blocks_when_mapping_is_unknown(self):
        passed = backend.Check('pass', '通过')
        unknown = backend.Check('unknown', '未确认')
        detection = backend.Detection(passed, passed, passed, passed, unknown)
        with patch.object(backend, '_claude_running', return_value=passed), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), \
             patch.object(backend, '_activate_application') as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        self.assertNotEqual(result.status, 'pass')
        activate.assert_not_called()

    def test_unrelated_proxy_port_owner_blocks_even_when_other_checks_match(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.10"}', b'']), \
             patch.object(backend, '_proxy_owner_snapshot', return_value=None, create=True):
            result = backend.detect(self.config())
        self.assertFalse(result.ready)

    def test_owner_change_during_detection_closes_start_gate(self):
        passed = backend.Check('pass', '通过')
        with patch.object(backend, '_manager', return_value=passed), \
             patch.object(backend, '_port', return_value=passed), \
             patch.object(backend, '_mapping', return_value=passed), \
             patch.object(backend, '_request_via_proxy', side_effect=[b'{"ip":"203.0.113.10"}', b'', b'h=claude.ai\nip=203.0.113.10\n']), \
             patch.object(backend, '_proxy_owner_snapshot', side_effect=[('pid', 1), ('pid', 2)], create=True):
            result = backend.detect(self.config())
        self.assertFalse(result.ready)
        self.assertEqual(result.port.status, 'unknown')

    def test_owner_change_after_detection_blocks_activation(self):
        passed = backend.Check('pass', '通过')
        unknown = backend.Check('unknown', '未确认')
        detection = backend.Detection(passed, passed, passed, passed, unknown,
                                      mapping=passed, _owner_evidence=('pid', 1), target_trace=passed)
        with patch.object(backend, '_claude_running', return_value=passed), \
             patch.object(backend, 'discover_desktop', return_value=('Claude_test!Claude',)), \
             patch.object(backend, 'detect', return_value=detection), \
             patch.object(backend, '_proxy_owner_snapshot', return_value=('pid', 2), create=True), \
             patch.object(backend, '_activate_application') as activate:
            result = backend.launch_desktop(self.config(), 'Claude_test!Claude')
        self.assertEqual(result.status, 'unknown')
        activate.assert_not_called()

    def test_owner_snapshot_requires_same_process_and_independent_pinned_binary(self):
        self.owner_patch.stop()
        path = r'C:\Program Files\Proxy Manager\Proxy Manager.exe'
        digest = 'a' * 64
        config = self.config(manager_executable=path, manager_sha256=digest)
        base = {'pid': 123, 'started': '638966136000000000', 'path': path}
        with patch.object(backend, '_capture_listener_owners', return_value=([base], [base]), create=True), \
             patch.object(backend, '_file_sha256', return_value=digest, create=True):
            self.assertIsNotNone(backend._proxy_owner_snapshot(config))
        for suspect in [dict(base, pid=124), dict(base, started='different'),
                        dict(base, path=r'C:\Other\Proxy Manager.exe')]:
            with self.subTest(suspect=suspect), \
                 patch.object(backend, '_capture_listener_owners', return_value=([base], [suspect]), create=True), \
                 patch.object(backend, '_file_sha256', return_value=digest, create=True):
                self.assertIsNone(backend._proxy_owner_snapshot(config))

    def test_owner_snapshot_unknown_for_multiple_listeners_missing_pin_or_changed_hash(self):
        self.owner_patch.stop()
        path = r'C:\Program Files\Proxy Manager\Proxy Manager.exe'
        digest = 'a' * 64
        base = {'pid': 123, 'started': '638966136000000000', 'path': path}
        for manager, proxy, expected_hash in [([base, dict(base, pid=124)], [base], digest),
                                                ([base], [base], ''),
                                                ([base], [base], 'b' * 64)]:
            config = self.config(manager_executable=path, manager_sha256=expected_hash)
            with self.subTest(expected_hash=expected_hash), \
                 patch.object(backend, '_capture_listener_owners', return_value=(manager, proxy), create=True), \
                 patch.object(backend, '_file_sha256', return_value=digest, create=True):
                self.assertIsNone(backend._proxy_owner_snapshot(config))

    def test_not_required_checks_isp_and_zone_without_mapping(self):
        config = self.config(mapping_mode='not_required', expected_zone='work-zone')
        proxy = {'port': 24001, 'zone': 'work-zone'}
        other = {'port': 24002, 'zone': 'other-zone'}
        zone = {'name': 'work-zone', 'plan': {'type': 'static_res'}}
        with patch.object(backend, '_manager_owns_port', return_value=True), \
             patch.object(backend, '_fetch_manager_json', side_effect=[[other, proxy], {'zones': [zone]}]):
            self.assertEqual(backend._mapping(config).status, 'pass')

    def test_not_required_does_not_bypass_port_zone_or_isp_evidence(self):
        config = self.config(mapping_mode='not_required', expected_zone='work-zone')
        for proxies, zones in [
            ([{'port': 24002, 'zone': 'work-zone'}], [{'name': 'work-zone', 'plan': {'type': 'static_res'}}]),
            ([{'port': 24001, 'zone': 'other'}], [{'name': 'work-zone', 'plan': {'type': 'static_res'}}]),
            ([{'port': 24001, 'zone': 'work-zone'}], [{'name': 'work-zone', 'plan': {}}]),
            ([{'port': 24001, 'zone': 'work-zone'}] * 2, [{'name': 'work-zone', 'plan': {'type': 'static_res'}}]),
            ([{'port': 24001, 'zone': 'work-zone'}], [{'name': 'work-zone', 'plan': {'type': 'static_res'}}] * 2),
            ([{'port': 24001, 'zone': 'work-zone', 'ext_proxies': True}], [{'name': 'work-zone', 'plan': {'type': 'static_res'}}]),
            ([{'port': 24001, 'zone': 'work-zone'}], [{'name': 'work-zone', 'plan': {'type': 'future-type'}}]),
        ]:
            with self.subTest(proxies=proxies, zones=zones), patch.object(backend, '_manager_owns_port', return_value=True), \
                 patch.object(backend, '_fetch_manager_json', side_effect=[proxies, {'zones': zones}]):
                self.assertNotEqual(backend._mapping(config).status, 'pass')

    def test_duplicate_json_key_is_not_trusted(self):
        with patch.object(backend.http.client, 'HTTPConnection') as conn:
            reply = conn.return_value.getresponse.return_value
            reply.status = 200
            reply.read.return_value = b'[{"port":24001,"port":24002}]'
            with self.assertRaises(ValueError):
                backend._fetch_manager_json(22999, '/api/proxies_running', 2)

    def test_malformed_item_is_not_silently_ignored(self):
        with patch.object(backend.http.client, 'HTTPConnection') as conn:
            reply = conn.return_value.getresponse.return_value
            reply.status = 200
            reply.read.return_value = b'[{"port":24001},null]'
            with self.assertRaises(ValueError):
                backend._fetch_manager_json(22999, '/api/proxies_running', 2)

    def test_management_redirect_error_or_oversize_is_not_accepted(self):
        for status, payload in [(302, b'[]'), (500, b'[]'), (200, b'x' * 2097153)]:
            with self.subTest(status=status), patch.object(backend.http.client, 'HTTPConnection') as conn:
                reply = conn.return_value.getresponse.return_value
                reply.status = status
                reply.read.return_value = payload
                with self.assertRaises((OSError, ValueError)):
                    backend._fetch_manager_json(22999, '/api/proxies_running', 2)
                self.assertEqual(conn.call_count, 1)


if __name__ == '__main__':
    unittest.main()
