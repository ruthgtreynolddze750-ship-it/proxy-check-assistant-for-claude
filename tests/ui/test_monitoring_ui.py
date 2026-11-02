import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.model import Result, Status


@dataclass(frozen=True)
class Event:
    occurred_at: datetime
    reason_code: str
    action_code: str
    sequence: int


@dataclass(frozen=True)
class Snapshot:
    state: str = 'stopped'
    protection: str = 'not_enabled'
    checked_at: datetime | None = None
    last_success_at: datetime | None = None
    reason_codes: tuple = ()
    sequence: int = 0
    events: tuple = ()
    scope: str = 'independent_proxy'
    browser_status: str = 'unknown'


class FakeMonitor:
    def __init__(self, config):
        self.config = config
        self.current = Snapshot()
        self.starts = self.stops = self.resumes = 0

    def start(self):
        self.starts += 1
        self.current = Snapshot(state='checking', sequence=self.current.sequence + 1)

    def stop(self):
        self.stops += 1
        self.current = Snapshot(state='stopped', sequence=self.current.sequence + 1)

    def resume(self):
        self.resumes += 1
        self.current = Snapshot(state='checking', sequence=self.current.sequence + 1)

    def snapshot(self):
        return self.current

    def update(self, state, *, protection='not_enabled', reasons=(), events=()):
        now = datetime.now(timezone.utc)
        self.current = Snapshot(state=state, protection=protection, checked_at=now,
                                last_success_at=now if state == 'monitoring' else None,
                                reason_codes=reasons, sequence=self.current.sequence + 1, events=events)


def wait_for(root, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('监测界面未进入预期状态')


class MonitorUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.created = []
        def factory(config):
            session = FakeMonitor(config)
            self.created.append(session)
            return session
        self.app = App(self.root, config_path=Path(self.temp.name) / 'settings.json', monitor_factory=factory)
        # 离线样本仅测试监测状态机；实际浏览器绑定仍由生产代码关闭。
        self.app._monitor_browser_bound = lambda: True

    def tearDown(self):
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except tk.TclError:
            pass
        self.temp.cleanup()

    def save_config(self):
        for key, value in {'port': '12001', 'manager_port': '12002', 'manager_executable': 'C:/Trusted/Proxy Manager.exe',
                           'manager_sha256': 'a' * 64, 'expected_ip': '192.0.2.41', 'ip_url': 'https://ip.example/check',
                           'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
            self.app.fields[key].set(value)
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())

    def set_launch_ready(self):
        self.app.result = Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS,
                                 owner=Status.PASS, desktop=Status.PASS, desktop_instance=Status.PASS,
                                 mapping_mode='not_required')
        self.app._applications = ('valid-id',)
        self.app._selected_app = 'valid-id'
        self.app._evidence_started = self.app.clock()
        self.app.refresh()

    def test_chrome_identity_unconfirmed_blocks_monitor_even_with_saved_settings(self):
        self.app._monitor_browser_bound = App._monitor_browser_bound.__get__(self.app, App)
        self.save_config()
        self.app.result = Result(common=Status.PASS, target_trace=Status.PASS, mapping=Status.PASS,
                                 owner=Status.PASS, mapping_mode='not_required', browser=Status.PASS,
                                 browser_input=Status.PASS, browser_identity=Status.PASS, browser_proxy=Status.PASS)
        self.app._evidence_started = self.app.clock()
        self.app.refresh()
        self.assertIn('专用浏览器身份未确认', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
        self.app.start_monitor()
        self.assertEqual(self.created, [])
        self.assertEqual(str(self.app.resume_monitor_button['state']), 'disabled')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_monitor_alarm_does_not_modify_desktop_or_block_desktop_backend(self):
        from src.core.backend import LaunchResult
        self.app._monitor_browser_bound = App._monitor_browser_bound.__get__(self.app, App)
        self.save_config()
        self.set_launch_ready()
        original = self.app.result
        session = FakeMonitor(None)
        self.app._monitor_session = session
        session.update('alarm', reasons=('exit_ip_mismatch',))
        self.app._poll_monitor()
        self.app.refresh()
        self.assertEqual(self.app.result, original)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        with patch.object(self.app.backend, 'launch_desktop', return_value=LaunchResult('unknown', 'test')) as launch, patch('ui.app.messagebox.showinfo'):
            self.app.desktop_button.invoke()
            wait_for(self.root, lambda: not self.app.busy)
        launch.assert_called_once()

    def test_all_monitor_fault_states_preserve_fresh_desktop_evidence(self):
        self.save_config()
        self.set_launch_ready()
        original, evidence = self.app.result, self.app._evidence_started
        now = datetime.now(timezone.utc)
        cases = (
            Snapshot(state='alarm', reason_codes=('exit_ip_mismatch',), sequence=1),
            Snapshot(state='checking', protection='unknown', sequence=1),
            Snapshot(state='monitoring', checked_at=now, last_success_at=now, sequence=129,
                     events=tuple(Event(now, 'check_pass', 'monitor_only', i) for i in range(1, 130))),
        )
        for snapshot in cases:
            with self.subTest(state=snapshot.state, events=len(snapshot.events)):
                self.app._monitor_sequence = self.app._monitor_event_cursor = 0
                self.app._monitor_latched = self.app._monitor_invalid = False
                self.app._monitor_error = ''
                session = FakeMonitor(None)
                session.current = snapshot
                self.app._monitor_session = session
                self.app._poll_monitor()
                self.app.refresh()
                self.assertIs(self.app.result, original)
                self.assertEqual(self.app._evidence_started, evidence)
                self.assertEqual(str(self.app.desktop_button['state']), 'normal')
                self.app.stop_monitor()
                self.assertIs(self.app.result, original)
                self.assertEqual(self.app._evidence_started, evidence)
                self.assertEqual(str(self.app.desktop_button['state']), 'normal')

    def test_no_start_on_initialization_and_requires_saved_config(self):
        self.root.update()
        self.assertEqual(self.created, [])
        self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
        self.assertIn('未启用', self.app.monitor_summary.get())
        self.save_config()
        self.assertEqual(str(self.app.start_monitor_button['state']), 'normal')
        self.assertEqual(self.created, [])

    def test_alarm_latches_launch_until_manual_resume_and_fresh_success(self):
        self.save_config()
        self.set_launch_ready()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.assertIn('未启用', self.app.monitor_summary.get())
        event = Event(datetime.now(timezone.utc), 'ip_mismatch', 'unknown', 1)
        session.update('alarm', reasons=('ip_mismatch',), events=(event,))
        wait_for(self.root, lambda: '异常' in self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')
        session.update('monitoring')
        self.root.update()
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: session.resumes == 1)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.assertTrue(self.app.result.can_start_desktop)

    def test_config_change_stops_session_and_discards_old_snapshot(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.app.fields['expected_zone'].set('different-zone')
        wait_for(self.root, lambda: session.stops > 0)
        session.update('monitoring')
        self.root.update()
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertFalse(self.app.saved)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_protection_is_never_promoted_and_event_report_is_sanitized(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        event = Event(datetime.now(timezone.utc), 'password=PRIVATE_TEST_VALUE', 'cookie=PRIVATE_TEST_VALUE', 1)
        session.update('alarm', protection='protected', reasons=('PRIVATE_TEST_VALUE',), events=(event,))
        wait_for(self.root, lambda: '异常' in self.app.monitor_summary.get())
        self.assertNotIn('已生效', self.app.monitor_summary.get())
        report = self.app.report.get('1.0', 'end')
        self.assertIn('阻断', report)
        self.assertNotIn('PRIVATE_TEST_VALUE', report)

    def test_stopping_monitor_does_not_clear_a_latched_alarm(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('alarm', reasons=('ip_mismatch',))
        wait_for(self.root, lambda: '异常' in self.app.monitor_summary.get())
        self.app.stop_monitor_button.invoke()
        wait_for(self.root, lambda: session.stops > 0)
        self.set_launch_ready()
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_config_change_after_alarm_keeps_alarm_visible(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('alarm', reasons=('ip_mismatch',))
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        self.app.fields['expected_zone'].set('changed-zone')
        self.assertIn('异常', self.app.monitor_summary.get())
        self.assertIn('复检', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_stopping_during_manual_recheck_does_not_claim_recheck_is_running(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('alarm', reasons=('ip_mismatch',))
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        self.app.resume_monitor_button.invoke()
        self.assertIn('复检中', self.app.monitor_summary.get())
        self.app.stop_monitor_button.invoke()
        self.assertNotIn('复检中', self.app.monitor_summary.get())
        self.assertIn('需手动复检', self.app.monitor_summary.get())

    def test_incompatible_snapshot_blocks_and_reports_interface_problem(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.snapshot = lambda: object()
        wait_for(self.root, lambda: '接口' in self.app.monitor_summary.get())
        self.set_launch_ready()
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertIn('未确认', self.app.monitor_summary.get())

    def test_event_history_is_bounded_and_does_not_repeat_or_leak(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        now = datetime.now(timezone.utc)
        events = tuple(Event(now, 'password=PRIVATE_TEST_VALUE', 'cookie=PRIVATE_TEST_VALUE', i) for i in range(1, 129))
        session.current = Snapshot(state='monitoring', checked_at=now, last_success_at=now, sequence=128, events=events)
        wait_for(self.root, lambda: len(self.app._monitor_events) == 100)
        self.root.update()
        self.assertEqual(len(self.app._monitor_events), 100)
        self.assertNotIn('PRIVATE_TEST_VALUE', self.app.report.get('1.0', 'end'))

    def test_oversized_core_event_snapshot_is_not_treated_as_healthy(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        now = datetime.now(timezone.utc)
        events = tuple(Event(now, 'check_pass', 'monitor_only', i) for i in range(1, 130))
        session.current = Snapshot(state='monitoring', checked_at=now, last_success_at=now, sequence=129, events=events)
        wait_for(self.root, lambda: '接口' in self.app.monitor_summary.get())
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_launch_worker_rejects_oversized_snapshot_before_ui_poll(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        now = datetime.now(timezone.utc)
        events = tuple(Event(now, 'check_pass', 'monitor_only', i) for i in range(1, 130))
        session.current = Snapshot(state='monitoring', checked_at=now, last_success_at=now, sequence=129, events=events)
        self.assertFalse(self.app._monitor_worker_allows_launch(session))

    def test_alert_before_retained_event_window_is_still_latched(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        now = datetime.now(timezone.utc)
        events = (Event(now, 'exit_ip_mismatch', 'alert_only', 1),) + tuple(
            Event(now, 'check_pass', 'monitor_only', i) for i in range(2, 129))
        session.current = Snapshot(state='monitoring', checked_at=now, last_success_at=now, sequence=128, events=events)
        self.assertFalse(self.app._monitor_worker_allows_launch(session))
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_invalid_snapshot_does_not_prevent_stopping_on_config_change(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        session.snapshot = lambda: object()
        self.app.fields['expected_zone'].set('changed-zone')
        self.assertEqual(session.stops, 1)
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_invalid_snapshot_does_not_prevent_manual_stop(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        session.snapshot = lambda: object()
        self.app.stop_monitor_button.invoke()
        self.assertEqual(session.stops, 1)
        self.assertIn('未确认', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_unconfirmed_monitoring_snapshot_never_displays_healthy(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        now = datetime.now(timezone.utc)
        session.current = Snapshot(state='monitoring', checked_at=now, last_success_at=None, sequence=2)
        wait_for(self.root, lambda: '未确认' in self.app.monitor_summary.get())
        self.assertNotIn('正在监测', self.app.monitor_summary.get())
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_actual_core_session_uses_manual_resume_after_simulated_alarm(self):
        from src.core.backend import Check, Detection
        from src.core.monitoring import MonitorSession
        passed = Check('pass', '')
        failure = Check('fail', 'PRIVATE_TEST_VALUE')
        scenario = {'fail': False}
        def detector(config):
            return Detection(passed, passed, failure if scenario['fail'] else passed,
                             Check('unknown', 'Claude 首页返回 HTTP 403，服务未确认'),
                             Check('unknown', ''), mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        self.app._monitor_factory = lambda config: MonitorSession(config, interval_seconds=.05, max_age_seconds=1, detector=detector)
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        scenario['fail'] = True
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        self.assertIn('发现异常，阻断未启用', self.app.monitor_summary.get())
        self.assertIn('独立出口与预期不一致', self.app.report.get('1.0', 'end'))
        self.assertNotIn('PRIVATE_TEST_VALUE', self.app.report.get('1.0', 'end'))
        scenario['fail'] = False
        time.sleep(.15)
        self.root.update()
        self.assertIn('异常锁存', self.app.monitor_summary.get())
        self.app.resume_monitor_button.invoke()
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.assertFalse(self.app.result.can_start_desktop)
        self.assertIn('阻断保护：未启用', self.app.monitor_summary.get())

    def test_actual_core_expiry_is_reported_without_claiming_disconnection(self):
        from src.core.backend import Check, Detection
        from src.core.monitoring import MonitorSession
        passed = Check('pass', '')
        detector = lambda config: Detection(passed, passed, passed, passed, Check('unknown', ''),
                                            mapping=passed, _owner_evidence=('synthetic',), target_trace=passed)
        self.app._monitor_factory = lambda config: MonitorSession(config, interval_seconds=5, max_age_seconds=.2, detector=detector)
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        report = self.app.report.get('1.0', 'end')
        self.assertIn('监测证据：已过期', report)
        self.assertIn('未确认已断开', report)
        self.assertEqual(str(self.app.desktop_button['state']), 'disabled')

    def test_monitor_event_export_obeys_ip_choice_and_hides_raw_details(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        event = Event(datetime.now(timezone.utc), 'exit_ip_mismatch', 'alert_only', 1)
        session.update('alarm', reasons=('exit_ip_mismatch',), events=(event,))
        wait_for(self.root, lambda: '异常锁存' in self.app.monitor_summary.get())
        output = Path(self.temp.name) / 'report.txt'
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
            self.app.export_report()
        redacted = output.read_text(encoding='utf-8')
        self.assertIn('监测事件', redacted)
        self.assertIn('独立出口与预期不一致', redacted)
        self.assertIn('仅提示，未确认断连', redacted)
        self.assertNotIn('192.0.2.41', redacted)
        self.assertNotIn('C:/Trusted', redacted)
        self.assertNotIn('a' * 64, redacted)
        self.app.full_ip.set(True)
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(output)):
            self.app.export_report()
        self.assertIn('192.0.2.41', output.read_text(encoding='utf-8'))

    def test_desktop_launch_worker_does_not_consult_monitor(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.set_launch_ready()
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        original_snapshot = session.snapshot
        def snapshot():
            if threading.current_thread() is not threading.main_thread():
                session.update('alarm', reasons=('ip_mismatch',))
            return original_snapshot()
        session.snapshot = snapshot
        with patch.object(self.app.backend, 'launch_desktop') as launch, patch('ui.app.messagebox.showinfo'):
            self.app.launch_desktop()
            wait_for(self.root, lambda: not self.app.busy)
        launch.assert_called_once()
        self.assertNotIn('异常', self.app.monitor_summary.get())

    def test_browser_worker_alarm_preserves_fresh_desktop_evidence(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        session = self.created[-1]
        session.update('monitoring')
        wait_for(self.root, lambda: '正在监测' in self.app.monitor_summary.get())
        self.set_launch_ready()
        self.app.result = replace(self.app.result, browser=Status.PASS, browser_input=Status.PASS,
                                  browser_identity=Status.PASS, browser_proxy=Status.PASS)
        self.app.refresh()
        original, evidence = self.app.result, self.app._evidence_started
        original_snapshot = session.snapshot
        def snapshot():
            if threading.current_thread() is not threading.main_thread():
                session.update('alarm', reasons=('exit_ip_mismatch',))
            return original_snapshot()
        session.snapshot = snapshot
        with patch.object(self.app.backend, 'launch_browser') as launch, patch('ui.app.messagebox.showinfo'):
            self.app.launch_browser()
            wait_for(self.root, lambda: not self.app.busy)
        launch.assert_not_called()
        self.assertIs(self.app.result, original)
        self.assertEqual(self.app._evidence_started, evidence)
        self.assertEqual(str(self.app.desktop_button['state']), 'normal')
        self.assertEqual(str(self.app.browser_button['state']), 'disabled')

    def test_close_stops_session_without_launching_or_killing_apps(self):
        self.save_config()
        self.app.start_monitor_button.invoke()
        wait_for(self.root, lambda: bool(self.created))
        session = self.created[-1]
        self.root.destroy()
        deadline = time.monotonic() + 2
        while session.stops == 0 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertGreater(session.stops, 0)


class MonitorEntryTests(unittest.TestCase):
    def test_default_factory_cannot_create_unbound_proxy_monitor(self):
        from ui.app import _default_monitor_factory
        with patch('src.core.monitoring.MonitorSession') as monitor:
            with self.assertRaises(RuntimeError):
                _default_monitor_factory(None)
        monitor.assert_not_called()

    def test_main_entry_controls_with_injected_offline_monitor(self):
        import ui.app as app_module
        actual_app = app_module.App
        outcome = []
        with tempfile.TemporaryDirectory() as folder:
            def make_app(root, backend, monitor_runtime):
                from src.protection.managed_session import ManagedSessionRuntime
                self.assertIsInstance(monitor_runtime, ManagedSessionRuntime)
                sessions = []
                def factory(config):
                    sessions.append(FakeMonitor(config))
                    return sessions[-1]
                app = actual_app(root, backend=app_module.UnconnectedBackend(),
                                 config_path=Path(folder) / 'settings.json', monitor_factory=factory)
                app._monitor_browser_bound = lambda: True  # 仅注入离线测试场景。
                def exercise():
                    try:
                        for key, value in {'port': '12001', 'manager_port': '12002',
                                           'manager_executable': 'C:/Trusted/Proxy Manager.exe',
                                           'manager_sha256': 'a' * 64, 'expected_ip': '192.0.2.41',
                                           'ip_url': 'https://ip.example/check',
                                           'mapping_mode': '明确不需要目标映射', 'expected_zone': 'sample-zone'}.items():
                            app.fields[key].set(value)
                        app.save_settings()
                        app.start_monitor_button.invoke()
                        session = sessions[-1]
                        session.update('monitoring')
                        app._poll_monitor()
                        app.refresh()
                        outcome.append(app.monitor_summary.get())
                        session.update('alarm', reasons=('exit_ip_mismatch',))
                        app._poll_monitor()
                        app.refresh()
                        outcome.append(app.monitor_summary.get())
                        app.resume_monitor_button.invoke()
                        session.update('monitoring')
                        app._poll_monitor()
                        app.refresh()
                        outcome.append(app.monitor_summary.get())
                        app.stop_monitor_button.invoke()
                        outcome.append(app.monitor_summary.get())
                        outcome.append(app.report.get('1.0', 'end'))
                    except Exception as error:
                        outcome.append(error)
                    finally:
                        root.destroy()
                root.after(20, exercise)
                return app
            with patch('ui.app.App', side_effect=make_app), patch('ui.app.messagebox.showinfo'):
                app_module.main()
        self.assertEqual(len(outcome), 5, repr(outcome))
        self.assertIn('正在监测', outcome[0])
        self.assertIn('异常锁存', outcome[1])
        self.assertIn('正在监测', outcome[2])
        self.assertIn('已停止', outcome[3])
        self.assertIn('阻断保护：未启用', outcome[4])
        self.assertNotIn('C:/Trusted', outcome[4])


if __name__ == '__main__':
    unittest.main()
