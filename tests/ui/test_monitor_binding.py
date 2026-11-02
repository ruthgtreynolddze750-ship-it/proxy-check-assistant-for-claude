import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.monitor_binding import BindingEvidence
from tests.ui.test_monitoring_ui import FakeMonitor, wait_for


class Provider:
    def __init__(self):
        self.value = None

    def current(self):
        return self.value


class BoundMonitor(FakeMonitor):
    def __init__(self, config, binding):
        super().__init__(config)
        self.binding_key = binding.key

    def snapshot(self):
        return replace(super().snapshot(), scope='dedicated_browser',
                       browser_status='pass' if self.current.state == 'monitoring' else 'unknown')


class BindingTimingTests(unittest.TestCase):
    def setUp(self):
        from src.core.monitoring import BrowserBinding
        from ui.adapters import to_core_config
        from ui.model import Config
        self.config = Config(port=12001, manager_port=12002, expected_ip='192.0.2.41',
                             ip_url='https://ip.example/check', chrome_path='C:/Fixture/chrome.exe',
                             user_data_dir='C:/Fixture/Data', chrome_profile='Default')
        self.core_config = to_core_config(self.config)
        self.evidence = BindingEvidence(self.config, 123, 456, 'fixture', 99.0, 109.0, True, True)
        self.binding = BrowserBinding(self.config.chrome_path, self.config.user_data_dir, 'Default',
                                      'fixture', 123, 456, ((789, 1011),))
        self.timing = dict(interval_seconds=2.0, max_age_seconds=10.0, identity_refresh_seconds=2.0,
                           request_budget_seconds=1.0, request_evidence_ttl_seconds=10.0)

    def create(self, **timing):
        from ui.monitor_binding import create_bound_monitor
        return create_bound_monitor(self.core_config, self.evidence, browser_binding=self.binding,
                                    clock=lambda: 100.0, **timing)

    def test_default_sampling_cannot_be_silently_selected(self):
        with patch('src.core.monitoring.MonitorSession') as session:
            with self.assertRaises(TypeError):
                self.create()
            session.assert_not_called()

    def test_every_timing_parameter_is_explicit(self):
        for missing in self.timing:
            with self.subTest(missing=missing), patch('src.core.monitoring.MonitorSession') as session:
                values = dict(self.timing)
                del values[missing]
                with self.assertRaises(TypeError):
                    self.create(**values)
                session.assert_not_called()

    def test_incompatible_or_invalid_budget_rejected_before_session_creation(self):
        cases = (
            dict(interval_seconds=30.0, max_age_seconds=60.0, request_evidence_ttl_seconds=30.0),
            dict(interval_seconds=7.0),  # 间隔加两次请求预算恰好达到身份剩余 9 秒。
            dict(max_age_seconds=4.0), dict(request_evidence_ttl_seconds=4.0),
            dict(identity_refresh_seconds=9.0), dict(request_budget_seconds=4.0),
        )
        cases += tuple({key: value} for key in self.timing
                       for value in (0, -1, True, float('nan'), float('inf'), '1', 10 ** 400))
        for override in cases:
            with self.subTest(override=override), patch('src.core.monitoring.MonitorSession') as session:
                with self.assertRaises(ValueError):
                    self.create(**(self.timing | override))
                session.assert_not_called()

    def test_remaining_lifetime_is_used_without_extending_evidence(self):
        self.evidence = replace(self.evidence, verified_at=94.0, expires_at=104.0)
        with patch('src.core.monitoring.MonitorSession') as session:
            with self.assertRaises(ValueError):
                self.create(**self.timing)
            session.assert_not_called()
        self.assertEqual(self.evidence.expires_at, 104.0)

    def test_compatible_explicit_budget_creates_unstarted_real_session(self):
        from src.core.monitoring import MonitorSession
        session = self.create(**self.timing)
        self.assertIsInstance(session, MonitorSession)
        self.assertEqual(session.snapshot().state, 'stopped')
        self.assertEqual(session.snapshot().browser_status, 'unknown')
        self.assertEqual(session.binding_key, self.evidence.key)
        self.assertEqual(self.evidence.expires_at, 109.0)

    def test_short_relay_lease_is_an_additional_sampling_deadline(self):
        self.evidence = replace(self.evidence, verified_at=100.0, expires_at=160.0)
        slow = self.timing | dict(interval_seconds=30, max_age_seconds=60, request_evidence_ttl_seconds=60)
        with patch('src.core.monitoring.MonitorSession') as session:
            with self.assertRaises(ValueError):
                self.create(**slow, relay_max_lease_seconds=2.0)
            session.assert_not_called()
        timing = self.timing | dict(interval_seconds=.2, request_budget_seconds=.3)
        session = self.create(**timing, relay_max_lease_seconds=2.0)
        self.assertEqual(session.snapshot().state, 'stopped')

    def test_invalid_relay_lease_limit_rejected_before_session_creation(self):
        for limit in (0, -1, True, 11, float('nan'), float('inf'), 10 ** 400):
            with self.subTest(limit=limit), patch('src.core.monitoring.MonitorSession') as session:
                with self.assertRaises(ValueError):
                    self.create(**self.timing, relay_max_lease_seconds=limit)
                session.assert_not_called()

    def test_single_diagnostic_has_one_attempt_budget_without_relaxing_continuous_mode(self):
        timing = self.timing | dict(interval_seconds=30, request_budget_seconds=3)
        session = self.create(**timing, relay_max_lease_seconds=2, max_samples=1)
        self.assertEqual(session.relay_sample_limit, 1)
        self.assertEqual(session.snapshot().state, 'stopped')
        for limit in (None, 0, 2, 3, True, '1'):
            with self.subTest(limit=limit), patch('src.core.monitoring.MonitorSession') as constructor:
                with self.assertRaises(ValueError):
                    self.create(**timing, relay_max_lease_seconds=2, max_samples=limit)
                constructor.assert_not_called()
        with self.assertRaises(ValueError):
            self.create(**(timing | dict(request_budget_seconds=9)), relay_max_lease_seconds=2, max_samples=1)


class BindingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.provider = Provider()
        self.created = []
        def factory(config, binding):
            session = BoundMonitor(config, binding)
            self.created.append(session)
            return session
        self.app = App(self.root, config_path=Path(self.temp.name) / 'settings.json',
                       monitor_factory=factory, monitor_binding_provider=self.provider)
        for key, value in {'port':'12001', 'manager_port':'12002', 'manager_executable':'C:/Trusted/Proxy.exe',
                           'manager_sha256':'a' * 64, 'expected_ip':'192.0.2.41',
                           'ip_url':'https://ip.example/check', 'mapping_mode':'明确不需要目标映射',
                           'expected_zone':'sample-zone'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())

    def tearDown(self):
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except tk.TclError:
            pass
        self.temp.cleanup()

    def bind(self):
        now = self.app.clock()
        self.provider.value = BindingEvidence(replace(self.app.config), 123, 456, 'test-generation',
                                              now, now + 10, True, True)
        self.app.refresh()

    def test_bound_session_created_only_after_click_and_stops_when_identity_changes(self):
        self.bind()
        self.assertEqual(self.created, [])
        self.assertEqual(str(self.app.start_monitor_button['state']), 'normal')
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.provider.value = replace(self.provider.value, process_started=457)
        wait_for(self.root, lambda: session.stops == 1)
        session.update('monitoring')
        self.root.update()
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertIn('身份', self.app.monitor_summary.get())
        self.assertTrue(self.app._monitor_latched)

    def test_expired_unconfirmed_and_mismatched_configuration_never_enable(self):
        self.bind()
        original = self.provider.value
        for evidence in (replace(original, expires_at=self.app.clock() - .01),
                         replace(original, proxy_confirmed=False),
                         replace(original, config=replace(original.config, expected_zone='another'))):
            self.provider.value = evidence
            self.app.refresh()
            self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
            self.app.start_monitor()
        self.assertEqual(self.created, [])

    def test_expiry_stops_active_session_and_cannot_auto_restore(self):
        self.bind()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        self.provider.value = replace(self.provider.value, expires_at=self.app.clock() - .01)
        wait_for(self.root, lambda: session.stops == 1)
        self.provider.value = replace(self.provider.value, verified_at=self.app.clock(), expires_at=self.app.clock() + 10)
        self.root.update()
        self.assertEqual(session.starts, 1)
        self.assertTrue(self.app._monitor_latched)

    def test_close_stops_only_injected_bound_session(self):
        self.bind()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        self.root.destroy()
        self.assertEqual(session.stops, 1)

    def test_factory_without_matching_identity_is_stopped_before_start(self):
        self.bind()
        session = FakeMonitor(None)
        self.app._monitor_factory = lambda config, binding: session
        self.app.start_monitor_button.invoke()
        self.assertEqual(session.starts, 0)
        self.assertEqual(session.stops, 1)
        self.assertIn('身份', self.app.monitor_summary.get())

    def test_binding_change_inside_factory_stops_new_session_before_start(self):
        self.bind()
        def factory(config, binding):
            session = BoundMonitor(config, binding)
            self.created.append(session)
            self.provider.value = replace(binding, process_started=999)
            return session
        self.app._monitor_factory = factory
        self.app.start_monitor_button.invoke()
        self.assertEqual(self.created[-1].starts, 0)
        self.assertEqual(self.created[-1].stops, 1)

    def test_binding_change_during_start_stops_session_immediately(self):
        self.bind()
        provider = self.provider
        class ChangingMonitor(BoundMonitor):
            def start(self):
                super().start()
                provider.value = replace(provider.value, process_started=999)
        self.app._monitor_factory = lambda config, binding: ChangingMonitor(config, binding)
        self.app.start_monitor_button.invoke()
        self.assertIsNone(self.app._monitor_session)
        self.assertIn('身份', self.app.monitor_summary.get())

    def test_start_exception_stops_partially_started_session(self):
        self.bind()
        class BrokenStart(BoundMonitor):
            def start(self):
                super().start()
                raise RuntimeError('PRIVATE_RAW_ERROR')
        session = BrokenStart(None, self.provider.value)
        self.app._monitor_factory = lambda config, binding: session
        self.app.start_monitor_button.invoke()
        self.assertEqual(session.stops, 1)
        self.assertIsNone(self.app._monitor_session)
        self.assertNotIn('PRIVATE_RAW_ERROR', self.app.monitor_summary.get())

    def test_resume_exception_stops_partially_resumed_session(self):
        self.bind()
        class BrokenResume(BoundMonitor):
            def resume(self):
                super().resume()
                raise RuntimeError('PRIVATE_RAW_ERROR')
        session = BrokenResume(None, self.provider.value)
        self.app._monitor_factory = lambda config, binding: session
        self.app.start_monitor_button.invoke()
        session.update('alarm', reasons=('exit_ip_mismatch',))
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        self.app.resume_monitor_button.invoke()
        self.assertEqual(session.stops, 1)
        self.assertIsNone(self.app._monitor_session)
        self.assertNotIn('PRIVATE_RAW_ERROR', self.app.monitor_summary.get())

    def test_session_identity_change_stops_session(self):
        self.bind()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        session.binding_key = ('different-identity',)
        wait_for(self.root, lambda: session.stops == 1)
        self.assertTrue(self.app._monitor_latched)

    def test_session_identity_read_failure_stops_session_without_leaking_error(self):
        self.bind()
        class BadIdentity(FakeMonitor):
            @property
            def binding_key(self):
                raise RuntimeError('PRIVATE_RAW_ERROR')
        session = BadIdentity(None)
        self.app._monitor_session = session
        self.app._monitor_binding_key = self.provider.value.key
        self.app._poll_monitor()
        self.assertEqual(session.stops, 1)
        self.assertNotIn('PRIVATE_RAW_ERROR', self.app.monitor_summary.get())

    def test_stop_failure_on_binding_loss_is_not_automatically_retried(self):
        self.bind()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        calls = []
        def fail_stop():
            calls.append(1)
            raise RuntimeError('PRIVATE_RAW_ERROR')
        session.stop = fail_stop
        self.provider.value = None
        wait_for(self.root, lambda: self.app._monitor_invalid)
        time.sleep(.12)
        self.root.update()
        self.assertEqual(len(calls), 1)
        self.assertIn('停止未确认', self.app.monitor_summary.get())
        self.assertNotIn('PRIVATE_RAW_ERROR', self.app.report.get('1.0', 'end'))
        session.stop = lambda: None

    def test_binding_replacement_requires_explicit_start_and_manual_recheck(self):
        self.bind()
        self.app.start_monitor_button.invoke()
        old = self.created[-1]
        old.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.provider.value = replace(self.provider.value, process_started=999)
        wait_for(self.root, lambda: old.stops == 1)
        self.app.refresh()
        self.assertEqual(len(self.created), 1)
        self.app.start_monitor_button.invoke()
        new = self.created[-1]
        self.assertIsNot(old, new)
        new.update('monitoring')
        self.app._poll_monitor()
        self.app.refresh()
        self.assertIn('异常锁存', self.app.monitor_summary.get())
        self.app.resume_monitor_button.invoke()
        self.assertEqual(new.resumes, 1)
        new.update('monitoring')
        self.app._poll_monitor()
        self.app.refresh()
        self.assertIn('正在监测', self.app.monitor_summary.get())

    def use_core(self, *, missing_provider=False, max_age=1, interval=.05):
        from src.core.backend import Check, Detection
        from src.core.monitoring import BrowserBinding, BrowserBindingEvidence
        from ui.monitor_binding import create_bound_monitor
        for key, value in {'chrome_path':'C:/Fixture/Chrome/chrome.exe',
                           'user_data_dir':'C:/Fixture/ChromeData', 'chrome_profile':'Default'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
        self.bind()
        self.samples = []
        self.request_status = 'pass'
        self.request_profile_status = 'pass'
        self.request_profile_directory = 'Default'
        self.request_profile_source = 'selected_profile_context'
        passed = Check('pass', '')
        self.detector = lambda config: Detection(
            passed, passed, passed, passed, Check('unknown', ''), mapping=passed,
            _owner_evidence=('synthetic',), target_trace=passed)
        def evidence_provider(config, binding, sample_id):
            self.samples.append(sample_id)
            now = time.monotonic()
            return BrowserBindingEvidence(binding, sample_id, now, 'pass', self.request_status,
                                          'pass', config.proxy_port, ('synthetic',), config.expected_ip,
                                          source='runtime', expires_at=now + max_age,
                                          request_profile_status=self.request_profile_status,
                                          request_profile_directory=self.request_profile_directory,
                                          request_profile_source=self.request_profile_source)
        def factory(config, evidence):
            binding = BrowserBinding(evidence.config.chrome_path, evidence.config.user_data_dir,
                                     evidence.config.chrome_profile, evidence.generation,
                                     evidence.pid, evidence.process_started, ((789, 1011),))
            session = create_bound_monitor(
                config, evidence, browser_binding=binding,
                binding_provider=None if missing_provider else evidence_provider,
                detector=lambda config: self.detector(config),
                interval_seconds=interval, max_age_seconds=max_age, identity_refresh_seconds=.5,
                request_budget_seconds=.02, request_evidence_ttl_seconds=max_age)
            self.created.append(session)
            return session
        self.app._monitor_factory = factory

    def test_real_core_binding_replacement_and_manual_restore(self):
        self.use_core()
        self.assertEqual(self.created, [])
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        old = self.created[-1]
        self.assertEqual(old.binding_key, self.provider.value.key)
        self.assertEqual(old.snapshot().scope, 'dedicated_browser')
        self.assertEqual(old.snapshot().browser_status, 'pass')
        with self.assertRaises(AttributeError):
            old.binding_key = ('changed',)
        self.assertIn('浏览器本次绑定：通过', self.app._render_report())
        self.provider.value = replace(self.provider.value, process_started=999, generation='next-generation')
        wait_for(self.root, lambda: self.app._monitor_session is None)
        self.assertEqual(old.snapshot().state, 'stopped')
        self.assertNotIn('浏览器本次绑定：通过', self.app._render_report())
        self.assertEqual(len(self.created), 1)
        self.app.start_monitor_button.invoke()
        new = self.created[-1]
        wait_for(self.root, lambda: new.snapshot().state == 'monitoring')
        self.app._poll_monitor()
        self.app.refresh()
        self.assertTrue(self.app._monitor_latched)
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: not self.app._monitor_latched)
        self.assertEqual(new.snapshot().browser_status, 'pass')
        self.assertGreaterEqual(len(set(self.samples)), 3)
        report = self.app.report.get('1.0', 'end')
        self.assertIn('浏览器本次绑定：通过', report)
        self.assertIn('不证明全部连接', report)
        for private in ('Fixture', 'test-generation', 'next-generation', 'synthetic'):
            self.assertNotIn(private, report)

    def test_real_core_missing_request_provider_stays_unknown_without_detection(self):
        self.use_core(missing_provider=True)
        with patch('src.core.backend._request_via_proxy') as request:
            self.detector = lambda config: self.fail('缺提供者时不应调用检测器')
            self.app.start_monitor_button.invoke()
            wait_for(self.root, lambda: self.app._monitor_latched)
            snapshot = self.created[-1].snapshot()
            self.assertEqual(snapshot.browser_status, 'unknown')
            self.assertIn('browser_provider_missing', snapshot.reason_codes)
            self.assertIn('浏览器请求证据提供者未接入', self.app._render_report())
            self.assertIn('浏览器本次绑定：未确认', self.app._render_report())
            self.assertFalse(self.app._monitor_allows_launch())
            request.assert_not_called()

    def test_bound_factory_cannot_substitute_independent_snapshot(self):
        self.bind()
        session = BoundMonitor(None, self.provider.value)
        session.snapshot = lambda: session.current
        self.app._monitor_factory = lambda config, binding: session
        self.app.start_monitor_button.invoke()
        self.assertTrue(self.app._monitor_latched)
        self.assertEqual(session.stops, 1)
        self.assertNotIn('浏览器本次绑定：通过', self.app._render_report())

    def test_real_core_expired_binding_stops_and_discards_inflight_result(self):
        self.use_core()
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.detector
        def delayed(config):
            entered.set()
            release.wait(2)
            result = original(config)
            finished.set()
            return result
        self.detector = delayed
        try:
            self.app.start_monitor_button.invoke()
            old = self.created[-1]
            wait_for(self.root, entered.is_set)
            self.provider.value = replace(self.provider.value, expires_at=self.app.clock() - .01)
            wait_for(self.root, lambda: self.app._monitor_session is None)
            release.set()
            wait_for(self.root, finished.is_set)
            self.assertEqual(old.snapshot().state, 'stopped')
            self.assertEqual(old.snapshot().browser_status, 'unknown')
            self.assertEqual(self.samples, [])
            self.assertTrue(self.app._monitor_latched)
            self.assertNotIn('浏览器本次绑定：通过', self.app._render_report())
        finally:
            release.set()

    def test_real_core_unconfirmed_request_latches_until_manual_recheck(self):
        self.use_core()
        self.request_status = 'unknown'
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: self.app._monitor_latched)
        self.assertIn('浏览器证据未确认', self.app._render_report())
        self.request_status = 'pass'
        time.sleep(.1)
        self.root.update()
        self.assertTrue(self.app._monitor_latched)
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: not self.app._monitor_latched)
        self.assertIn('浏览器本次绑定：通过', self.app._render_report())

    def test_real_core_profile_must_be_observed_in_request_context(self):
        self.use_core()
        self.request_profile_source = 'configured_profile'
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: self.app._monitor_latched)
        self.assertIn('浏览器本次请求的配置目录未确认', self.app.report.get('1.0', 'end'))
        self.request_profile_source = 'selected_profile_context'
        self.request_profile_directory = 'PRIVATE_OTHER_PROFILE'
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: '浏览器本次请求的配置目录不一致' in self.app.report.get('1.0', 'end'))
        self.assertTrue(self.app._monitor_latched)
        self.assertNotIn('PRIVATE_OTHER_PROFILE', self.app.report.get('1.0', 'end'))
        self.request_profile_directory = 'Default'
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: not self.app._monitor_latched)
        self.assertIn('浏览器本次绑定：通过', self.app.report.get('1.0', 'end'))

    def test_adapter_rejects_selection_or_configuration_mismatch(self):
        from src.core.monitoring import BrowserBinding
        from ui.adapters import to_core_config
        from ui.monitor_binding import create_bound_monitor
        self.use_core()
        evidence = self.provider.value
        binding = BrowserBinding('C:/Other/chrome.exe', evidence.config.user_data_dir, 'Default',
                                 evidence.generation, evidence.pid, evidence.process_started, ((789, 1011),))
        timing = dict(interval_seconds=.05, max_age_seconds=1, identity_refresh_seconds=.5,
                      request_budget_seconds=.02, request_evidence_ttl_seconds=1)
        with self.assertRaises(ValueError):
            create_bound_monitor(to_core_config(self.app.config), evidence, browser_binding=binding, **timing)
        binding = replace(binding, executable=evidence.config.chrome_path)
        config = replace(to_core_config(self.app.config), proxy_port=12345)
        with self.assertRaises(ValueError):
            create_bound_monitor(config, evidence, browser_binding=binding, **timing)

    def test_bound_core_timeout_requires_manual_recheck(self):
        from src.core.backend import Check, Detection
        self.use_core(max_age=.2)
        passed = Check('pass', '')
        wait = threading.Event()
        scenario = {'block': False}
        def detector(config):
            if scenario['block']:
                wait.wait(2)
            return Detection(passed, passed, passed, passed, Check('unknown', ''),
                             mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        self.detector = detector
        try:
            self.app.start_monitor_button.invoke()
            wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
            scenario['block'] = True
            wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
            self.assertIn('已过期', self.app.report.get('1.0', 'end'))
            scenario['block'] = False
            wait.set()
            time.sleep(.1)
            self.root.update()
            self.assertIn('异常锁存', self.app.monitor_summary.get())
            self.app.resume_monitor_button.invoke()
            wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        finally:
            wait.set()


if __name__ == '__main__':
    unittest.main()
