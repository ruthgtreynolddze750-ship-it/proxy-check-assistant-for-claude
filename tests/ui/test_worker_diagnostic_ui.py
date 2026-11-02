"""Redacted relay worker diagnostics through the existing report and real Tk."""
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
import sys
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[2]),
                str(Path(__file__).resolve().parents[2] / 'src')]
import test_managed_runtime_ui as fixtures
from src.protection.managed_session import RuntimeView
from src.protection.session_relay import RelaySnapshot
from ui.monitoring_presentation import runtime_report_lines


PRIVATE = 'SECRET_TOKEN password=PRIVATE https://private.example/ 198.51.100.77 C:\\Users\\SECRET_USER'


def diagnostic(**changes):
    values = dict(stage='client_recv', error_code='connection_reset', incomplete=False)
    values.update(changes)
    return SimpleNamespace(**values)


def with_detail(view, detail):
    object.__setattr__(view, 'worker_diagnostic', detail)
    return view


def report_for(detail):
    return '\n'.join(runtime_report_lines(with_detail(RuntimeView(), detail), 100))


class DamagedDiagnostic:
    def __getattribute__(self, name):
        raise RuntimeError(PRIVATE)

    def __str__(self):
        raise AssertionError('Raw diagnostic must not be rendered')


class WorkerDiagnosticPresentationTests(unittest.TestCase):
    def assert_safe(self, report):
        for token in ('SECRET', 'PRIVATE', 'private.example', '198.51.100.77', 'C:\\Users'):
            self.assertNotIn(token, report)
        self.assertIn('待用户真实验收', report)

    def test_absent_failure_is_not_presented_as_success(self):
        for report in (report_for(None), '\n'.join(runtime_report_lines(None, 100))):
            self.assertIn('转发异常诊断：暂无记录', report)
            self.assertNotIn('转发诊断通过', report)
            self.assert_safe(report)

    def test_all_known_stages_have_fixed_labels(self):
        stages = (('client_identity', '客户端身份核验'), ('client_setup', '客户端连接设置'),
            ('diagnostic_header', '受控诊断请求头读取'), ('diagnostic_send', '受控诊断发送'),
            ('upstream_listener', '上游监听归属核验'), ('upstream_socket', '创建上游连接'),
            ('upstream_setup', '上游连接设置'), ('upstream_connect', '连接上游'),
            ('upstream_identity', '上游连接归属核验'), ('pump', '双向转发'),
            ('pump_setup', '转发连接设置'), ('pump_select', '等待连接读写'),
            ('client_recv', '读取客户端数据'), ('upstream_recv', '读取上游数据'),
            ('client_send', '向客户端发送数据'), ('upstream_send', '向上游发送数据'),
            ('client_half_close', '关闭客户端发送方向'), ('upstream_half_close', '关闭上游发送方向'))
        for code, label in stages:
            with self.subTest(stage=code):
                report = report_for(diagnostic(stage=code))
                self.assertIn('转发异常环节：' + label, report)
                self.assertNotIn('转发诊断有缺失', report)
                self.assert_safe(report)

    def test_all_known_categories_have_fixed_labels(self):
        categories = (('connection_reset', '连接重置'), ('connection_aborted', '连接中止'),
            ('connection_refused', '连接被拒绝'), ('broken_pipe', '管道已断开'),
            ('timeout', '超时'), ('os_error', '系统调用异常'),
            ('invalid_data', '数据格式异常'), ('other_error', '其他异常'))
        for code, label in categories:
            with self.subTest(error=code):
                self.assertIn('转发错误类别：' + label, report_for(diagnostic(error_code=code)))

    def test_unknown_or_nonprimitive_fields_are_incomplete_and_never_echoed(self):
        class TextSubclass(str):
            def __hash__(self):
                raise AssertionError('Untrusted string subclass must not be used as a key')
        for value in (PRIVATE, None, [], {}, True, 123, TextSubclass('client_recv')):
            with self.subTest(value_type=type(value).__name__):
                report = report_for(diagnostic(stage=value, error_code=value))
                self.assertIn('转发异常环节：未确认', report)
                self.assertIn('转发错误类别：未确认', report)
                self.assertIn('转发诊断有缺失', report)
                self.assert_safe(report)

    def test_unknown_stage_explicitly_marks_incomplete(self):
        report = report_for(diagnostic(stage='unknown'))
        self.assertIn('转发异常环节：未确认', report)
        self.assertIn('转发诊断有缺失', report)

    def test_only_exact_false_means_record_not_incomplete(self):
        for value in (True, None, 0, '', PRIVATE):
            with self.subTest(value_type=type(value).__name__):
                report = report_for(diagnostic(incomplete=value))
                self.assertIn('转发诊断有缺失', report)
                self.assert_safe(report)

    def test_damaged_record_never_breaks_report_or_exposes_private_text(self):
        for value in (PRIVATE, [PRIVATE], {'stage': PRIVATE}, DamagedDiagnostic(), SimpleNamespace()):
            with self.subTest(value_type=type(value).__name__):
                report = report_for(value)
                self.assertIn('转发诊断有缺失', report)
                self.assert_safe(report)

    def test_missing_runtime_field_is_explicitly_incomplete(self):
        class LegacyView(RuntimeView):
            def __getattribute__(self, name):
                if name == 'worker_diagnostic':
                    raise AttributeError(name)
                return super().__getattribute__(name)
        report = '\n'.join(runtime_report_lines(LegacyView(), 100))
        self.assertIn('转发诊断有缺失', report)
        self.assert_safe(report)

    def test_worker_error_with_null_record_is_not_reported_as_no_failure(self):
        view = with_detail(RuntimeView(relay_snapshot=RelaySnapshot('closed', 'worker_error', 0, 'local_test')), None)
        report = '\n'.join(runtime_report_lines(view, 100))
        self.assertIn('转发诊断有缺失', report)
        self.assertNotIn('转发异常诊断：暂无记录', report)

    def test_extra_attributes_are_ignored_and_no_cause_or_timing_is_invented(self):
        detail = diagnostic(raw_exception=PRIVATE, address=PRIVATE, request=PRIVATE, credentials=PRIVATE)
        report = report_for(detail)
        self.assert_safe(report)
        self.assertEqual(report.count('转发异常环节：'), 1)
        self.assertEqual(report.count('转发错误类别：'), 1)
        for text in ('真人验证导致', '转发异常耗时', '远端主动', '自动恢复'):
            self.assertNotIn(text, report)
        self.assertEqual(detail.raw_exception, PRIVATE)

    def test_actual_core_record_contract_and_missing_record_sentinel(self):
        from src.protection.session_relay import WorkerFailureDiagnostic
        self.assertEqual(tuple(item.name for item in fields(WorkerFailureDiagnostic)),
                         ('stage', 'error_code', 'incomplete'))
        detail = WorkerFailureDiagnostic('upstream_connect', 'timeout')
        with self.assertRaises(FrozenInstanceError):
            detail.stage = 'client_recv'
        report = report_for(detail)
        self.assertIn('转发异常环节：连接上游', report)
        self.assertIn('转发错误类别：超时', report)
        missing = report_for(WorkerFailureDiagnostic('unknown', 'unavailable', True))
        self.assertIn('转发错误类别：未确认', missing)
        self.assertIn('转发诊断有缺失', missing)


class WorkerDiagnosticTkTests(unittest.TestCase):
    make_app = fixtures.ManagedLifecycleTests.make_app
    setUp = fixtures.ManagedSelectionTests.setUp
    tearDown = fixtures.ManagedSelectionTests.tearDown

    def alarm(self, detail):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.runtime.view = with_detail(replace(self.runtime.view, phase='alarm', reason_code='relay_closed',
            cleanup_status='confirmed', relay_snapshot=RelaySnapshot('closed', 'worker_error', 0, 'local_test')), detail)
        self.app._poll_monitor()
        self.app.refresh()

    def assert_copy_export(self, report):
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
        path = self.base/'worker-report.txt'
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(path)):
            self.app.export_report()
        self.assertEqual(path.read_text(encoding='utf-8'), report)

    def test_report_copy_export_show_one_safe_record_even_with_full_ip_enabled(self):
        self.alarm(diagnostic(raw_exception=PRIVATE, address=PRIVATE))
        for full_ip in (False, True):
            self.app.full_ip.set(full_ip)
            self.app.refresh()
            report = self.app.report.get('1.0', 'end-1c')
            self.assertIn('转发异常环节：读取客户端数据', report)
            self.assertIn('转发错误类别：连接重置', report)
            self.assertEqual(report.count('转发异常环节：'), 1)
            self.assertNotIn('SECRET', report)
            self.assert_copy_export(report)
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(self.app._monitor_protection, 'not_enabled')
        self.assertIn('待用户真实验收', report)

    def test_malformed_diagnostic_copy_export_keep_existing_failure_and_cleanup(self):
        self.alarm(diagnostic(stage=PRIVATE, error_code=PRIVATE, incomplete=PRIVATE))
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('转发处理未能完成', report)
        self.assertIn('本次资源清理：已确认', report)
        self.assertIn('转发诊断有缺失', report)
        self.assertNotIn('SECRET', report)
        self.assert_copy_export(report)

    def test_late_other_request_cannot_replace_displayed_failure(self):
        self.alarm(diagnostic())
        self.runtime.view = replace(self.runtime.view, request_id='old-unrelated-request',
                                    worker_diagnostic=diagnostic(stage='upstream_connect', error_code='timeout'))
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('转发异常环节：读取客户端数据', report)
        self.assertNotIn('转发异常环节：连接上游', report)


class ActualWorkerRuntimeTkTests(unittest.TestCase):
    setUp = fixtures.ProductionRuntimeAppTests.setUp
    tearDown = fixtures.ProductionRuntimeAppTests.tearDown
    wait_for = fixtures.ProductionRuntimeAppTests.wait_for
    assert_copy_export = WorkerDiagnosticTkTests.assert_copy_export

    def test_actual_runtime_carries_first_worker_record_to_report_copy_export_and_stop(self):
        from src.protection.session_relay import WorkerFailureDiagnostic
        self.app.start_monitor()
        self.wait_for(lambda: self.app._monitor_session is not None)
        detail = WorkerFailureDiagnostic('upstream_recv', 'connection_reset')
        # Synthetic failure snapshot; the actual runtime still handles alarm and cleanup.
        self.backend.snapshot = lambda: RelaySnapshot('closed', 'worker_error', 0,
            'runtime_unverified', worker_diagnostic=detail)
        self.wait_for(lambda: self.runtime.current().phase == 'alarm'
                      and self.runtime.current().cleanup_status == 'confirmed')
        self.assertIs(self.runtime.current().worker_diagnostic, detail)
        self.assertIs(self.runtime.current().relay_snapshot.worker_diagnostic, detail)
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('转发异常环节：读取上游数据', report)
        self.assertIn('转发错误类别：连接重置', report)
        self.assertIn('待用户真实验收', report)
        self.assert_copy_export(report)
        self.assertTrue(self.backend.revoked)
        self.assertIsNone(self.app._monitor_view)
        self.app.stop_monitor()
        self.app._poll_monitor()
        self.assertIs(self.runtime.current().worker_diagnostic, detail)
        self.assertIn('转发异常环节：读取上游数据', self.app._render_report())


if __name__ == '__main__':
    unittest.main()
