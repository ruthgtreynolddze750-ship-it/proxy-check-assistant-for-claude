import unittest
import threading
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import Mock
from src.browser import request_probe as probe
from src.browser.cdp_pipe import CdpChannel, ProbeError


class ProductionProbeTests(unittest.TestCase):
    def navigation_fixture(self):
        value = object.__new__(probe.ProductionProbe)
        value._lock = threading.Lock()
        value._closed = threading.Event()
        value._invalidated = False
        value.protected_plan = SimpleNamespace(round_timeout_seconds=10)
        value.grant = probe.ProductionSessionGrant(SimpleNamespace(digest='a'*64), threading.Event())
        now = time.monotonic()
        value._exit_receipts = [SimpleNamespace(sampled_at=now, expires_at=now+30)]
        value._last_result = SimpleNamespace(profile_trace=SimpleNamespace(
            context=SimpleNamespace(browser_context_id='selected-profile-context')))
        value._channel = Mock()
        value._channel.command.return_value = {'targetId':'selected-target'}
        value.route_provider = lambda:SimpleNamespace(expires_at=now+2)
        return value

    def test_navigation_opens_only_validated_claude_url_in_confirmed_context(self):
        value = self.navigation_fixture()
        self.assertEqual(value.open_selected_url('https://claude.ai/new'), 'selected-target')
        calls = value._channel.mock_calls
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[:2], ('Target.createTarget',
            {'url':'https://claude.ai/new', 'browserContextId':'selected-profile-context'}))

    def test_navigation_invalid_cancelled_or_stale_evidence_never_sends_command(self):
        for condition in ('invalid_url', 'cancelled', 'expired_exit', 'missing_route', 'expired_route'):
            with self.subTest(condition=condition):
                value = self.navigation_fixture()
                url = 'https://claude.ai/'
                if condition == 'invalid_url':
                    url = 'https://example.test/'
                elif condition == 'cancelled':
                    value.grant.close()
                elif condition == 'expired_exit':
                    value._exit_receipts[-1].expires_at = time.monotonic()-1
                elif condition == 'missing_route':
                    value.route_provider = lambda:None
                else:
                    value.route_provider = lambda:SimpleNamespace(expires_at=time.monotonic()-1)
                with self.assertRaises(ProbeError):
                    value.open_selected_url(url)
                value._channel.command.assert_not_called()

    def test_backend_navigation_requires_current_lease_even_before_watchdog_updates_state(self):
        from src.protection.managed_session import NativeManagedBackend
        backend = NativeManagedBackend()
        backend.cancel = threading.Event()
        backend.relay = Mock()
        backend.relay.snapshot.return_value = SimpleNamespace(state='listening')
        backend.relay._live.return_value = False
        backend.probe = Mock()
        with self.assertRaises(ValueError):
            backend.open_selected_url('https://claude.ai/')
        backend.probe.open_selected_url.assert_not_called()

    def test_metadata_projector_returns_only_paths_and_discards_sensitive_url_arguments(self):
        self.assertTrue(hasattr(probe, 'PRODUCTION_METADATA_PROJECTOR'), '普通浏览器元数据必须在采集端投影')
        projector = probe.PRODUCTION_METADATA_PROJECTOR
        self.assertNotIn('Get-CimInstance', projector)
        script = projector + r'''
        $item=[Console]::In.ReadToEnd() | ConvertFrom-Json
        Get-ClaudePathMetadata $item | ConvertTo-Json -Compress
        '''
        payload = {'ExecutablePath': r'C:\ordinary\chrome.exe',
                   'CommandLine': r'"C:\ordinary\chrome.exe" --user-data-dir="C:\private ordinary" https://example.test/secret?token=FAKE_SENSITIVE_TOKEN'}
        shell = str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
        result = subprocess.run([shell,'-NoProfile','-NonInteractive','-Command',script],
            input=json.dumps(payload).encode(),capture_output=True,timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,check=True)
        self.assertNotIn(b'FAKE_SENSITIVE_TOKEN', result.stdout+result.stderr)
        self.assertNotIn(b'https://', result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout.decode('utf-8-sig')),
            {'executable':r'C:\ordinary\chrome.exe','user_data_dir':r'C:\private ordinary'})

    def test_user_session_permission_is_not_the_consumed_three_round_trial_grant(self):
        self.assertTrue(hasattr(probe, 'ProductionSessionGrant'), '缺少用户主动会话许可')
        plan = SimpleNamespace(digest='a'*64)
        grant = probe.ProductionSessionGrant(plan, threading.Event())
        grant.consume_launch(plan)
        for index in range(5):
            sample = f'{index+1:032x}'
            self.assertEqual(grant.consume_round(sample), index+1)
            grant.finish_round(sample)
        with self.assertRaises(ProbeError):
            grant.consume_round(f'{1:032x}')
        grant.close()
        self.assertFalse(grant.is_live())
        with self.assertRaises(ProbeError):
            grant.consume_round(f'{6:032x}')

    def test_cancelled_channel_never_starts_another_request(self):
        event = threading.Event()
        class Transport:
            def send(self, *args):
                raise AssertionError('取消后仍发送了协议命令')
        channel = CdpChannel(Transport())
        channel.cancelled = event
        event.set()
        with self.assertRaises(ProbeError):
            channel.send('Page.navigate', {}, 1e12)


if __name__ == '__main__':
    unittest.main()
