"""Synthetic manager results through the real Tk report, copy and history paths."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import patch

import test_managed_runtime_ui as fixtures
from src.core.backend import DetectionStep, Check
from src.protection.managed_session import ManagerSampleDiagnostic, RuntimeView
from ui import monitoring_presentation as presentation


PRIVATE = 'SECRET_USER password=SECRET_TOKEN https://private.example/ 198.51.100.77 C:\\Users\\SECRET_USER\\private'


def diagnostic(**changes):
    return replace(ManagerSampleDiagnostic('rejected', 1.25, 25,
        (('manager', 'unknown'), ('port', 'pass')),
        (DetectionStep('manager', 'unknown', 1.2, 'timeout'),),
        rejection_reason='manager_sample_invalid'), **changes)


class ManagerDiagnosticPresentationTests(unittest.TestCase):
    def test_nine_error_categories_are_distinct_fixed_chinese(self):
        labels = ('取消或截止期限', '超时', 'HTTP 状态异常', 'HTTP 协议异常', '编码异常',
                  '进程查询异常', '系统调用异常', '数据格式异常', '未分类异常')
        codes = ('cancelled_or_deadline', 'timeout', 'http_status', 'http_protocol', 'encoding',
                 'process_query', 'os_error', 'invalid_data', 'unexpected_error')
        for code, label in zip(codes, labels):
            with self.subTest(code=code):
                view = presentation.present_manager_diagnostic(diagnostic(error_code=code))
                self.assertIn('采样错误类别：' + label, '\n'.join(view.report_lines()))
                self.assertTrue(view.failed)

    def test_fixed_checks_stages_and_numeric_durations(self):
        stages = ('owner_before', 'manager', 'proxy_port', 'exit_ip', 'claude_home',
                  'target_trace', 'mapping', 'owner_after')
        labels = ('采样前监听归属', '管理器接口', '本地代理端口', '独立出口', 'Claude 首页（参考项）',
                  '目标出口请求', '映射与区域', '采样后监听归属')
        view = presentation.present_manager_diagnostic(diagnostic(
            steps=tuple(DetectionStep(s, 'unknown', .25, 'timeout') for s in stages)))
        report = '\n'.join(view.report_lines())
        for label in labels:
            self.assertIn(label, report)
        self.assertIn('1.25 秒', report)
        self.assertIn('25.00 秒', report)
        self.assertIn('管理器接口：未确认', report)
        self.assertIn('采样证据无效', report)

    def test_unknown_values_and_invalid_durations_never_echo_payloads(self):
        for duration in (PRIVATE, float('nan'), float('inf'), -1, True, 10**200):
            with self.subTest(duration_type=type(duration).__name__):
                view = presentation.present_manager_diagnostic(diagnostic(outcome=PRIVATE,
                    elapsed_seconds=duration, budget_seconds=duration,
                    checks=((PRIVATE, PRIVATE),),
                    steps=(SimpleNamespace(stage=PRIVATE, status=PRIVATE,
                        elapsed_seconds=duration, error_code=PRIVATE, message=PRIVATE),),
                    error_code=PRIVATE, rejection_reason=PRIVATE))
                report = '\n'.join(view.report_lines()) + view.summary
                for token in ('SECRET', '198.51.100.77', 'private.example', 'C:\\Users', 'nan', 'inf'):
                    self.assertNotIn(token, report)
                self.assertIn('未确认', report)

    def test_absent_and_malformed_details_are_safe_and_bounded(self):
        self.assertIsNone(presentation.present_manager_diagnostic(None))
        for checks, steps in ((PRIVATE, PRIVATE), ((None, [PRIVATE], [PRIVATE]*3), (None, {})),
                              ([(PRIVATE, PRIVATE)]*1000, [SimpleNamespace(stage=PRIVATE)]*1000)):
            view = presentation.present_manager_diagnostic(diagnostic(checks=checks, steps=steps))
            report = '\n'.join(view.report_lines())
            self.assertNotIn('SECRET', report)
            self.assertLess(len(report), 4000)

    def test_reference_homepage_failure_does_not_reclassify_accepted_sample(self):
        view = presentation.present_manager_diagnostic(diagnostic(outcome='accepted',
            checks=(('claude', 'fail'),), rejection_reason=''))
        self.assertFalse(view.failed)
        self.assertIn('Claude 首页（参考项）：未通过', '\n'.join(view.report_lines()))
        self.assertNotIn('保护已', '\n'.join(view.report_lines()))


class ManagerDiagnosticTkTests(unittest.TestCase):
    make_app = fixtures.ManagedLifecycleTests.make_app
    setUp = fixtures.ManagedSelectionTests.setUp
    tearDown = fixtures.ManagedSelectionTests.tearDown

    def start(self):
        self.assertTrue(self.app.select_monitor_target(self.target))
        self.app.start_monitor()

    def publish_failure(self, detail=None):
        self.runtime.view = replace(self.runtime.view, phase='alarm', reason_code='manager_sample_failed',
            cleanup_status='confirmed', manager_diagnostic=detail or diagnostic())
        self.app._poll_monitor()
        self.app.refresh()

    def history_text(self):
        self.app.show_history()
        window = [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
        text = next(w for w in window.winfo_children() if isinstance(w, tk.Text))
        value = text.get('1.0', 'end-1c')
        window.destroy()
        return value

    def test_alarm_report_copy_export_and_history_read_back_same_safe_detail(self):
        self.start()
        self.publish_failure(diagnostic(steps=(DetectionStep('manager', 'unknown', 1.2, 'timeout'),
            SimpleNamespace(stage=PRIVATE, status=PRIVATE, elapsed_seconds=PRIVATE, error_code=PRIVATE))))
        self.root.deiconify()
        self.root.geometry('760x700')
        self.root.update()
        self.assertGreater(self.app.report.winfo_height(), 60)
        self.assertTrue(self.app.start_monitor_button.winfo_ismapped())
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('管理器采样诊断：未通过', report)
        self.assertIn('管理器接口', self.app.monitor_summary.get())
        self.assertIn('超时', report)
        self.assertIn('待真实验收', report)
        self.assertNotIn('SECRET', report)
        try:
            previous = self.root.clipboard_get()
        except tk.TclError:
            previous = None
        try:
            self.app.copy_report()
            self.assertEqual(self.root.clipboard_get(), report)
        finally:
            self.root.clipboard_clear()
            if previous is not None:
                self.root.clipboard_append(previous)
        target = self.base / 'report.txt'
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(target)):
            self.app.export_report()
        self.assertEqual(target.read_text(encoding='utf-8'), report)
        self.assertIn('首次异常', self.history_text())
        self.assertIn('超时', self.history_text())
        self.assertNotIn('SECRET', self.history_text())
        self.app.full_ip.set(True)
        self.app.refresh()
        full_report = self.app.report.get('1.0', 'end-1c')
        self.assertIn(self.app.config.expected_ip, full_report)
        for token in ('SECRET', '198.51.100.77', 'private.example', 'C:\\Users'):
            self.assertNotIn(token, full_report)
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(self.app._monitor_protection, 'not_enabled')

    def test_first_failure_survives_stop_cleanup_and_late_good_sample_without_duplicates(self):
        self.start()
        self.publish_failure()
        count = len(self.app._monitor_events)
        self.app.stop_monitor()
        self.runtime.view = replace(self.runtime.view, phase='idle', reason_code='user_stopped',
            cleanup_status='confirmed', manager_diagnostic=diagnostic(outcome='accepted',
                checks=(('manager', 'pass'),), steps=(), rejection_reason=''))
        for _ in range(3):
            self.app._poll_monitor()
        self.assertEqual(len(self.app._monitor_events), count)
        self.assertIn('超时', self.app._render_report())
        self.assertIn('管理器接口：未确认', self.app._render_report())
        self.assertIn('首次异常', self.history_text())

    def test_new_request_clears_current_detail_but_keeps_history_and_rejects_old_request(self):
        self.start()
        self.publish_failure()
        old_view = self.runtime.view
        self.app.start_monitor()
        self.runtime.view = old_view
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'preparing')
        self.assertIsNone(self.app._managed_diagnostic)
        self.assertIn('首次异常', self.history_text())

    def test_old_runtime_without_diagnostic_field_remains_compatible(self):
        self.start()
        class LegacyView(RuntimeView):
            def __getattribute__(self, name):
                if name == 'manager_diagnostic':
                    raise AttributeError(name)
                return super().__getattribute__(name)
        values = vars(replace(self.runtime.view, phase='alarm', reason_code='manager_sample_failed',
                              cleanup_status='confirmed')).copy()
        values.pop('manager_diagnostic')
        self.runtime.view = LegacyView(**values)
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'alarm')
        self.assertEqual(self.app._managed_error, '')
        self.assertIn('管理器采样未通过', self.app._render_report())
        self.assertIn('管理器采样诊断：暂无记录', self.app._render_report())

    def test_diagnostic_success_cannot_promote_invalid_running_binding(self):
        self.start()
        self.runtime.view = replace(self.runtime.view, phase='running',
            manager_diagnostic=diagnostic(outcome='accepted', steps=(), rejection_reason=''))
        self.app._poll_monitor()
        self.assertIsNone(self.app._monitor_session)
        self.assertTrue(self.app._managed_stop_requested)
        self.assertIn('待真实验收', self.app._render_report())


class ActualRuntimeDiagnosticTkTests(unittest.TestCase):
    setUp = fixtures.ProductionRuntimeAppTests.setUp
    tearDown = fixtures.ProductionRuntimeAppTests.tearDown
    wait_for = fixtures.ProductionRuntimeAppTests.wait_for

    def test_actual_runtime_failed_sample_reaches_tk_report_and_history_after_cleanup(self):
        self.app.start_monitor()
        self.wait_for(lambda: self.app._monitor_session is not None)
        good = self.backend.check_manager(self.backend.config, self.app.clock() + 25)
        bad = replace(good, mapping=Check('unknown', PRIVATE))
        self.backend.check_manager = lambda *args: bad
        self.backend.manager_steps = (DetectionStep('mapping', 'unknown', .1, 'http_status'),)
        self.runtime._sample_loop('manager', 0, 5, 25)
        self.wait_for(lambda: self.runtime.current().cleanup_status == 'confirmed')
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('映射与区域：未确认', report)
        self.assertIn('HTTP 状态异常', report)
        self.assertIn('采样证据无效', report)
        self.assertNotIn('SECRET', report)
        self.assertTrue(self.backend.revoked)
        self.assertIsNone(self.app._monitor_view)
        self.assertTrue(any('首次异常' in event[1] for event in self.app._monitor_events))
        self.assertIn('待真实验收', report)


if __name__ == '__main__':
    unittest.main()
