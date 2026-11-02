import sys
import tempfile
import time
import tkinter as tk
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import PropertyMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.model import Config, Result, Status
from ui.monitor_binding import BindingEvidence, create_bound_monitor
from src.core.backend import Check, Detection
from src.core.monitoring import BrowserBinding, BrowserBindingEvidence, MonitorSession
from src.protection.session_relay import RelaySnapshot, SessionRelay
from tests.ui.test_monitor_binding import Provider
from tests.ui.test_monitoring_ui import wait_for


class RelayUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.provider = Provider()
        self.created = []
        self.relay_calls = []
        self.override = None
        self.callback_error = False
        self.detector_calls = []
        self.fail_detector = False
        def callback(key):
            self.relay_calls.append(key)
            if self.callback_error:
                raise RuntimeError('PRIVATE_CALLBACK_ERROR')
            if not self.created or self.created[-1].binding_key != key:
                return None
            return self.override if self.override is not None else self.relay.snapshot()
        def factory(config, evidence, *, relay_max_lease_seconds, max_samples=None):
            self.received_limit = relay_max_lease_seconds
            binding = BrowserBinding(evidence.config.chrome_path, evidence.config.user_data_dir, 'Default',
                                     evidence.generation, evidence.pid, evidence.process_started, ((789, 1011),))
            passed = Check('pass', '')
            def detector(config):
                self.detector_calls.append(1)
                if self.fail_detector:
                    raise RuntimeError('PRIVATE_DETECTOR_ERROR')
                return Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed,
                                 _owner_evidence=('fixture',), target_trace=passed)
            def request(config, selected, sample_id):
                now = time.monotonic()
                return BrowserBindingEvidence(
                    selected, sample_id, now, 'pass', 'pass', 'pass', config.proxy_port, ('fixture',),
                    config.expected_ip, source='runtime', expires_at=now + 5,
                    request_profile_status='pass', request_profile_directory='Default',
                    request_profile_source='selected_profile_context')
            monitor = create_bound_monitor(
                config, evidence, browser_binding=binding, binding_provider=request, detector=detector,
                interval_seconds=getattr(self, 'test_interval', .05), max_age_seconds=5, identity_refresh_seconds=.5,
                request_budget_seconds=.05, request_evidence_ttl_seconds=5,
                relay_max_lease_seconds=relay_max_lease_seconds, max_samples=max_samples)
            self.created.append(monitor)
            # 真实执行器只构造和绑定，不 start，无监听、无系统查询。
            self.relay = SessionRelay(None, config, verifier=object(), max_lease_seconds=relay_max_lease_seconds)
            self.relay.bind(binding)
            self.relay.attach_monitor(monitor)
            return monitor
        self.app = App(self.root, config_path=Path(self.temp.name) / 'unused-settings.json',
                       monitor_factory=factory, monitor_binding_provider=self.provider,
                       monitor_relay_snapshot=callback, relay_max_lease_seconds=.5,
                       monitor_max_samples=getattr(self, 'sample_limit', None))
        self.app.config = Config(port=12001, manager_port=12002, expected_ip='192.0.2.41',
                                 ip_url='https://ip.example/check', mapping_mode='not_required',
                                 chrome_path='C:/Fixture/chrome.exe', user_data_dir='C:/Fixture/Data',
                                 chrome_profile='Default')
        self.app.saved = True
        now = time.monotonic()
        self.provider.value = BindingEvidence(replace(self.app.config), 123, 456, 'fixture-generation',
                                              now, now + 10, True, True)
        self.app.refresh()

    def tearDown(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self.assertFalse(self.app.config_path.exists())
        self.temp.cleanup()

    def start(self):
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: '已绑定，尚未监听' in self.app.report.get('1.0', 'end'))

    def test_explicit_click_passes_lease_limit_and_reads_actual_bound_snapshot(self):
        with patch('src.core.backend._request_via_proxy') as request:
            self.assertEqual(self.created, [])
            self.assertEqual(self.relay_calls, [])
            self.start()
            self.assertEqual(self.received_limit, .5)
            self.assertIsNone(self.relay.endpoint)
            self.assertEqual(self.relay_calls[-1], self.created[-1].binding_key)
            self.assertIn('本地测试', self.app.report.get('1.0', 'end'))
            self.assertIn('系统与路由保护：未确认', self.app.report.get('1.0', 'end'))
            self.assertFalse(self.app._monitor_allows_launch())
            self.assertFalse(self.app._monitor_worker_allows_launch(self.created[-1]))
            request.assert_not_called()

    def test_reported_protected_and_unknown_reason_never_promote_protection(self):
        self.start()
        self.override = RelaySnapshot('listening', 'PRIVATE_COOKIE', 1, 'local_test', 'protected')
        wait_for(self.root, lambda: '转发器报告监听中' in self.app.report.get('1.0', 'end'))
        report = self.app.report.get('1.0', 'end')
        self.assertIn('转发原因未确认', report)
        for value in ('PRIVATE_COOKIE', 'fixture-generation', 'C:/Fixture', '保护已启用', '保护已生效'):
            self.assertNotIn(value, report)
        self.assertIn('系统与路由保护：未确认', report)
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_closed_snapshot_updates_report_without_affecting_desktop_evidence(self):
        self.start()
        self.app.result = Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS,
                                 owner=Status.PASS, desktop=Status.PASS, desktop_instance=Status.PASS,
                                 mapping_mode='not_required')
        self.app._applications = ('fixture-desktop',)
        self.app._selected_app = 'fixture-desktop'
        self.app._evidence_started = self.app.clock()
        original, started = self.app.result, self.app._evidence_started
        self.override = RelaySnapshot('closed', 'lease_expired', 0, 'runtime_unverified')
        wait_for(self.root, lambda: '转发租约已过期' in self.app.report.get('1.0', 'end'))
        self.assertIs(self.app.result, original)
        self.assertEqual(self.app._evidence_started, started)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertFalse(self.app._monitor_allows_launch())

    def test_callback_failure_is_redacted_and_not_treated_as_protected(self):
        self.start()
        self.callback_error = True
        wait_for(self.root, lambda: '转发快照不可用' in self.app.report.get('1.0', 'end'))
        self.assertNotIn('PRIVATE_CALLBACK_ERROR', self.app.report.get('1.0', 'end'))
        self.assertIn('系统与路由保护：未确认', self.app.report.get('1.0', 'end'))

    def test_malformed_relay_snapshot_cannot_keep_previous_listening_display(self):
        self.start()
        self.override = RelaySnapshot('listening', 'lease_active', 1, 'local_test')
        wait_for(self.root, lambda: '转发器报告监听中' in self.app.report.get('1.0', 'end'))
        self.override = replace(self.override, active_connections=True)
        wait_for(self.root, lambda: '转发快照不可用' in self.app.report.get('1.0', 'end'))
        self.assertNotIn('转发器报告监听中', self.app.report.get('1.0', 'end'))
        self.assertFalse(self.app._monitor_allows_launch())

    def test_binding_expiry_clears_relay_snapshot_and_stops_reading_old_session(self):
        self.start()
        self.provider.value = replace(self.provider.value, expires_at=self.app.clock() - .01)
        wait_for(self.root, lambda: self.app._monitor_session is None)
        count = len(self.relay_calls)
        self.root.update()
        self.assertEqual(len(self.relay_calls), count)
        self.assertNotIn('已绑定，尚未监听', self.app.report.get('1.0', 'end'))
        self.assertEqual(self.created[-1].snapshot().state, 'stopped')

    def test_callback_requires_explicit_valid_lease_limit_and_binding_provider(self):
        for kwargs in ({}, {'relay_max_lease_seconds': 2},
                       {'relay_max_lease_seconds': True, 'monitor_binding_provider': self.provider}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                App(self.root, config_path=self.app.config_path, monitor_relay_snapshot=lambda key: None, **kwargs)


class SingleDiagnosticUITests(unittest.TestCase):
    setUp = RelayUITests.setUp
    tearDown = RelayUITests.tearDown
    sample_limit = 1
    test_interval = 30.0

    def record_state(self, stage):
        if not hasattr(self, 'state_evidence'):
            self.state_evidence = []
        report = self.app.report.get('1.0', 'end')
        self.state_evidence.append(dict(
            stage=stage, summary=self.app.monitor_summary.get(),
            start=str(self.app.start_monitor_button['state']),
            resume=str(self.app.resume_monitor_button['state']),
            browser=str(self.app.browser_button['state']), calls=len(self.detector_calls),
            report=[line for line in report.splitlines() if any(word in line for word in ('诊断', '转发', '保护', '采样'))]))

    def test_same_single_session_displays_completion_without_resampling_or_protection(self):
        from ui.adapters import to_core_config
        self.provider.value = replace(self.provider.value, proxy_confirmed=False)
        config = to_core_config(self.app.config)
        evidence = self.provider.value
        binding = BrowserBinding(evidence.config.chrome_path, evidence.config.user_data_dir, 'Default',
                                 evidence.generation, evidence.pid, evidence.process_started, ((789, 1011),))
        passed = Check('pass', '')
        def detector(config):
            self.detector_calls.append(1)
            return Detection(passed, passed, passed, passed, Check('unknown', ''), mapping=passed,
                             _owner_evidence=('fixture',), target_trace=passed)
        def request(config, selected, sample_id):
            now = time.monotonic()
            return BrowserBindingEvidence(selected, sample_id, now, 'pass', 'pass', 'pass',
                                          config.proxy_port, ('fixture',), config.expected_ip,
                                          source='runtime', expires_at=now + 5,
                                          request_profile_status='pass', request_profile_directory='Default',
                                          request_profile_source='selected_profile_context')
        # 协调器直接准备核心会话；不伪造 UI 的首次诊断前代理确认。
        monitor = MonitorSession(config, browser_binding=binding, binding_key=evidence.key,
                                 binding_provider=request, detector=detector, max_samples=1,
                                 interval_seconds=30, max_age_seconds=5)
        self.created.append(monitor)
        self.relay = SessionRelay(None, config, verifier=object(), max_lease_seconds=.5)
        self.relay.bind(binding)
        self.relay.attach_monitor(monitor)
        with patch.object(self.app, '_monitor_factory') as factory:
            self.app.start_monitor()
            factory.assert_not_called()
        self.assertFalse(self.app.attach_completed_diagnostic(monitor))
        self.assertEqual(self.detector_calls, [])
        self.record_state('pre_diagnostic_proxy_unknown')
        monitor.start()
        wait_for(self.root, lambda: monitor.snapshot().state == 'monitoring')
        self.assertFalse(self.app.attach_completed_diagnostic(monitor))
        now = self.app.clock()
        self.provider.value = replace(self.provider.value, proxy_confirmed=True,
                                      verified_at=now, expires_at=now + 5)
        with patch.object(monitor, 'start', side_effect=AssertionError('不可重复开始')), \
                patch.object(monitor, 'resume', side_effect=AssertionError('不可重复采样')):
            self.assertTrue(self.app.attach_completed_diagnostic(monitor))
        wait_for(self.root, lambda: '本次采样完成，不再采样' in self.app.monitor_summary.get())
        self.assertIs(self.app._monitor_session, monitor)
        self.assertIs(self.relay._monitor, monitor)
        self.assertTrue(monitor.accepts_relay_lease(monitor.relay_lease()))
        self.assertEqual(len(self.detector_calls), 1)
        self.assertEqual(str(self.app.start_monitor_button['text']), '开始单轮诊断')
        self.record_state('single_completed')
        for state, reason, label in (
            ('reserved', 'port_reserved_no_forwarding', '端口已预留，未转发'),
            ('diagnostic', 'bounded_trace_only', '仅受控单次诊断'),
            ('sealed', 'diagnostic_complete_no_forwarding', '诊断通道已封闭'),
            ('listening', 'lease_active', '转发器报告监听中')):
            self.override = RelaySnapshot(state, reason, 0, 'local_test', 'protected')
            wait_for(self.root, lambda: label in self.app.report.get('1.0', 'end'))
            self.record_state(state)
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertNotIn('保护已启用', self.app.report.get('1.0', 'end'))
        self.assertEqual(str(self.app.resume_monitor_button['state']), 'disabled')
        self.assertFalse(self.app._monitor_allows_launch())
        self.app.resume_monitor()
        self.app.stop_monitor_button.invoke()
        self.app.start_monitor()
        self.app.resume_monitor()
        self.provider.value = replace(self.provider.value, process_started=457)
        self.app._poll_monitor()
        self.app.refresh()
        self.app.start_monitor()
        self.record_state('stopped_no_retry')
        self.assertEqual(len(self.detector_calls), 1)
        self.assertEqual(len(self.created), 1)
        self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_completed_attachment_rejects_unfinished_or_different_binding_without_stopping_it(self):
        from ui.adapters import to_core_config
        monitor = self.app._monitor_factory(to_core_config(self.app.config), self.provider.value,
                                           relay_max_lease_seconds=.5, max_samples=1)
        with patch.object(monitor, 'start') as start, patch.object(monitor, 'stop') as stop:
            self.assertFalse(self.app.attach_completed_diagnostic(monitor))
            start.assert_not_called()
            stop.assert_not_called()
        monitor.start()
        wait_for(self.root, lambda: monitor.snapshot().state == 'monitoring')
        with patch.object(MonitorSession, 'relay_config', new_callable=PropertyMock,
                          return_value=replace(monitor.relay_config, proxy_port=12345)):
            self.assertFalse(self.app.attach_completed_diagnostic(monitor))
        with patch.object(MonitorSession, 'relay_binding', new_callable=PropertyMock,
                          return_value=replace(monitor.relay_binding, profile_directory='Other')):
            self.assertFalse(self.app.attach_completed_diagnostic(monitor))
        self.provider.value = replace(self.provider.value, process_started=999)
        with patch.object(monitor, 'stop') as stop:
            self.assertFalse(self.app.attach_completed_diagnostic(monitor))
            stop.assert_not_called()
        monitor.stop()

    def test_failed_single_attempt_cannot_be_retried(self):
        self.fail_detector = True
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: '本次诊断异常，不自动重试' in self.app.monitor_summary.get())
        self.app.resume_monitor()
        self.app.stop_monitor()
        self.app.start_monitor()
        self.assertEqual(len(self.detector_calls), 1)
        self.assertEqual(len(self.created), 1)
        self.assertNotIn('PRIVATE_DETECTOR_ERROR', self.app.report.get('1.0', 'end'))
        self.assertEqual(str(self.app.resume_monitor_button['state']), 'disabled')
        self.record_state('single_failed')

    def test_factory_cannot_return_continuous_session_for_single_diagnostic(self):
        self.test_interval = .05
        original = self.app._monitor_factory
        self.app._monitor_factory = lambda config, evidence, **options: original(
            config, evidence, relay_max_lease_seconds=options['relay_max_lease_seconds'])
        self.app.start_monitor_button.invoke()
        self.assertEqual(self.detector_calls, [])
        self.assertEqual(self.created[-1].snapshot().state, 'stopped')
        self.assertIsNone(self.app._monitor_session)
        self.assertIn('未确认', self.app.monitor_summary.get())

    def test_single_diagnostic_mode_rejects_ambiguous_or_multiple_sample_limits(self):
        for limit in (True, 0, 2, 3, '1'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                App(self.root, config_path=self.app.config_path, monitor_binding_provider=self.provider,
                    monitor_max_samples=limit)


if __name__ == '__main__':
    unittest.main()
