"""Synthetic guard snapshots through the production report and real Tk."""
from dataclasses import replace
import sys
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[2]),
                str(Path(__file__).resolve().parents[2] / 'src')]
import test_managed_runtime_ui as fixtures
from src.protection.managed_session import RuntimeView
from ui.monitoring_presentation import runtime_report_lines


PRIVATE = 'SECRET_USER password=SECRET_TOKEN https://private.example/ 198.51.100.77 C:\\Users\\SECRET_USER\\private'


def diagnostic(**changes):
    values = dict(outcome='timeout', elapsed_seconds=.51, budget_seconds=.5,
        steps=(SimpleNamespace(stage='guard_read', status='running', elapsed_seconds=.501),
               SimpleNamespace(stage='policy_identity_before', status='returned', elapsed_seconds=.351)),
        sample_sequence=7, scope='sample', incomplete=False, error_code='')
    values.update(changes)
    return SimpleNamespace(**values)


def report_for(detail):
    view = RuntimeView()
    object.__setattr__(view, 'guard_diagnostic', detail)
    return '\n'.join(runtime_report_lines(view, 100))


class DamagedDiagnostic:
    def __getattribute__(self, name):
        raise RuntimeError(PRIVATE)

    def __str__(self):
        raise AssertionError('Raw diagnostic must not be rendered')


class GuardDiagnosticCompatibilityTests(unittest.TestCase):
    def test_missing_diagnostic_is_explicit_without_affecting_protection_notice(self):
        class LegacyView(RuntimeView):
            def __getattribute__(self, name):
                if name == 'guard_diagnostic':
                    raise AttributeError(name)
                return super().__getattribute__(name)
        report = '\n'.join(runtime_report_lines(LegacyView(), 100))
        self.assertIn('快速核验阶段诊断：暂无记录', report)
        self.assertIn('待用户真实验收', report)

    def test_null_diagnostic_is_safe_and_explicit(self):
        view = RuntimeView()
        object.__setattr__(view, 'guard_diagnostic', None)
        report = '\n'.join(runtime_report_lines(view, 100))
        self.assertIn('快速核验阶段诊断：暂无记录', report)

    def test_damaged_or_raw_diagnostic_falls_back_without_copying_private_text(self):
        for value in (PRIVATE, [PRIVATE], {'raw': PRIVATE}, DamagedDiagnostic()):
            with self.subTest(value_type=type(value).__name__):
                view = RuntimeView()
                object.__setattr__(view, 'guard_diagnostic', value)
                report = '\n'.join(runtime_report_lines(view, 100))
                self.assertIn('快速核验阶段诊断：未确认', report)
                for token in ('SECRET', '198.51.100.77', 'private.example', 'C:\\Users'):
                    self.assertNotIn(token, report)
                self.assertIn('待用户真实验收', report)


class GuardDiagnosticPresentationTests(unittest.TestCase):
    def test_inflight_returned_and_raised_are_distinct_without_summing_nested_time(self):
        detail = diagnostic(steps=diagnostic().steps + (
            SimpleNamespace(stage='policy_engine_close', status='raised', elapsed_seconds=.01),))
        report = report_for(detail)
        self.assertIn('快速核验阶段诊断：已超时', report)
        self.assertIn('采样总耗时：510.0 毫秒；采样预算：500.0 毫秒', report)
        self.assertIn('运行中，已持续 501.0 毫秒', report)
        self.assertIn('已返回，用时 351.0 毫秒', report)
        self.assertIn('抛出异常，用时 10.0 毫秒', report)
        self.assertIn('父子阶段耗时有包含关系，不相加', report)
        self.assertIn('不是精确超时瞬间', report)
        self.assertIn('采样序号：7', report)
        self.assertEqual(detail.steps[0].status, 'running')

    def test_all_seventeen_approved_stage_labels_are_readable(self):
        stages = ('guard_read','bound_before','proxy_before','routes','policy_read',
            'policy_engine_open','policy_capabilities','policy_identity_before','policy_objects_before',
            'policy_objects_after','policy_identity_after','policy_engine_close','relay_policy',
            'bound_after','proxy_after','lease_issue','relay_renew')
        report = report_for(diagnostic(steps=tuple(SimpleNamespace(stage=stage, status='returned',
            elapsed_seconds=.01) for stage in stages)))
        self.assertEqual(sum(line.startswith('快速核验阶段：') for line in report.splitlines()), 17)
        for text in ('读取快速核验', '前置进程绑定', '前置代理归属', '连接路由', '读取系统规则',
                     '打开规则引擎', '查询规则能力', '前置规则身份', '前置规则对象',
                     '后置规则对象', '后置规则身份', '关闭规则引擎', '转发规则凭据',
                     '后置进程绑定', '后置代理归属', '签发短租约', '更新转发租约'):
            self.assertIn(text, report)

    def test_stage_output_is_bounded_and_unknown_labels_are_not_collected(self):
        valid = SimpleNamespace(stage='routes', status='returned', elapsed_seconds=.1)
        report = report_for(diagnostic(steps=(valid,)*1000))
        self.assertEqual(sum(line.startswith('快速核验阶段：') for line in report.splitlines()), 24)
        self.assertIn('诊断有缺失或已截断', report)
        report = report_for(diagnostic(steps=(SimpleNamespace(stage=PRIVATE, status='returned', elapsed_seconds=.1),
            SimpleNamespace(stage='routes', status=PRIVATE, elapsed_seconds=.1), valid)))
        self.assertEqual(sum(line.startswith('快速核验阶段：') for line in report.splitlines()), 1)
        self.assertIn('诊断有缺失或已截断', report)
        self.assertNotIn('SECRET', report)

    def test_unknown_metadata_invalid_numbers_and_none_durations_are_safe(self):
        for value in (None, PRIVATE, True, -1, float('nan'), float('inf'), 10**200):
            with self.subTest(value_type=type(value).__name__):
                report = report_for(diagnostic(outcome=PRIVATE, scope=PRIVATE, error_code=PRIVATE,
                    sample_sequence=value, elapsed_seconds=value, budget_seconds=value,
                    incomplete=PRIVATE, steps=(SimpleNamespace(stage='routes', status='running', elapsed_seconds=value),)))
                self.assertIn('耗时未确认', report)
                self.assertIn('快速核验阶段诊断：未确认', report)
                for token in ('SECRET', '198.51.100.77', 'private.example', 'C:\\Users', 'nan', 'inf'):
                    self.assertNotIn(token, report)

    def test_known_outcomes_and_initialization_do_not_claim_protection(self):
        for outcome, label in (('accepted','本次采样已接受'), ('exception','发生异常'),
                               ('cancelled','已取消'), ('unavailable','不可用')):
            with self.subTest(outcome=outcome):
                report = report_for(diagnostic(outcome=outcome, scope='initialization', incomplete=True))
                self.assertIn('快速核验阶段诊断：' + label, report)
                self.assertIn('诊断范围：初始化', report)
                self.assertIn('待用户真实验收', report)
                self.assertNotIn('保护已生效', report)

    def test_guard_error_categories_use_confirmed_core_allowlist(self):
        categories = (('cancelled_or_deadline','取消或截止期限'),('timeout','超时'),
            ('http_status','HTTP 状态异常'),('http_protocol','HTTP 协议异常'),('encoding','编码异常'),
            ('process_query','进程查询异常'),('os_error','系统调用异常'),
            ('invalid_data','数据格式异常'),('unexpected_error','未分类异常'))
        for code, label in categories:
            with self.subTest(code=code):
                self.assertIn('诊断错误类别：' + label, report_for(diagnostic(error_code=code)))

    def test_real_core_immutable_snapshot_uses_the_confirmed_field_contract(self):
        from src.protection.relay_identity import GuardSampleDiagnostic, GuardStageDiagnostic
        sample = GuardSampleDiagnostic('timeout', .51, .5,
            (GuardStageDiagnostic('policy_objects_before','running', .4),),
            sample_sequence=2, scope='sample', incomplete=False, error_code='timeout')
        report = report_for(sample)
        self.assertIn('前置规则对象 · 运行中，已持续 400.0 毫秒', report)
        self.assertIn('诊断错误类别：超时', report)
        self.assertEqual(sample.steps[0].elapsed_seconds, .4)

    def test_first_forward_opening_is_shown_only_in_initialization_scope(self):
        step = SimpleNamespace(stage='relay_promote', status='returned', elapsed_seconds=.007)
        self.assertIn('首次开放转发 · 已返回，用时 7.0 毫秒',
                      report_for(diagnostic(scope='initialization', steps=(step,))))
        ordinary = report_for(diagnostic(scope='sample', steps=(step,)))
        self.assertNotIn('首次开放转发', ordinary)
        self.assertIn('诊断有缺失或已截断', ordinary)

    def test_initialization_budget_is_not_presented_as_a_whole_initialization_deadline(self):
        report = report_for(diagnostic(scope='initialization', sample_sequence=0))
        self.assertIn('初始化核验段耗时：510.0 毫秒', report)
        self.assertIn('不是整段初始化期限', report)
        self.assertIn('总耗时与阶段耗时精度不同，不相减推算其他阶段', report)

    def test_sample_sequence_obeys_the_frozen_core_saturation_limit(self):
        self.assertIn('采样序号：2147483647', report_for(diagnostic(sample_sequence=2147483647)))
        self.assertIn('采样序号：未确认', report_for(diagnostic(sample_sequence=2147483648)))


class GuardDiagnosticTkTests(unittest.TestCase):
    make_app = fixtures.ManagedLifecycleTests.make_app
    setUp = fixtures.ManagedSelectionTests.setUp
    tearDown = fixtures.ManagedSelectionTests.tearDown

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
        path = self.base/'guard-report.txt'
        with patch('ui.app.filedialog.asksaveasfilename', return_value=str(path)):
            self.app.export_report()
        self.assertEqual(path.read_text(encoding='utf-8'), report)

    def test_report_copy_and_export_read_back_safe_stage_timing(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.runtime.view = replace(self.runtime.view, phase='alarm', reason_code='guard_sample_timeout',
                                    cleanup_status='confirmed')
        detail = diagnostic(error_code=PRIVATE, steps=diagnostic().steps + (
            SimpleNamespace(stage=PRIVATE,status=PRIVATE,elapsed_seconds=PRIVATE),))
        object.__setattr__(self.runtime.view, 'guard_diagnostic', detail)
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0', 'end-1c')
        self.assertIn('运行中，已持续 501.0 毫秒', report)
        self.assertIn('已返回，用时 351.0 毫秒', report)
        self.assertIn('快速核验超时', report)
        for token in ('SECRET', '198.51.100.77', 'private.example', 'C:\\Users'):
            self.assertNotIn(token, report)
        self.assert_copy_export(report)
        self.app.full_ip.set(True)
        self.assertNotIn('SECRET', self.app._render_report(True))
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(self.app._monitor_protection, 'not_enabled')

    def test_real_core_initialization_snapshot_report_copy_and_export(self):
        from src.protection.relay_identity import GuardSampleDiagnostic, GuardStageDiagnostic
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        sample = GuardSampleDiagnostic('exception', .4, .5,
            (GuardStageDiagnostic('relay_promote','raised', .007),),
            sample_sequence=0, scope='initialization', incomplete=False, error_code='os_error')
        self.runtime.view = replace(self.runtime.view, phase='alarm', reason_code='initial_guard_failed',
                                    cleanup_status='confirmed', guard_diagnostic=sample)
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0','end-1c')
        self.assertIn('首次开放转发 · 抛出异常，用时 7.0 毫秒', report)
        self.assertIn('诊断范围：初始化', report)
        self.assertIn('诊断错误类别：系统调用异常', report)
        self.assert_copy_export(report)
        self.assertIsNone(self.app._monitor_session)
        self.assertIn('待用户真实验收', report)


class ActualGuardRuntimeTkTests(unittest.TestCase):
    setUp = fixtures.ProductionRuntimeAppTests.setUp
    tearDown = fixtures.ProductionRuntimeAppTests.tearDown
    wait_for = fixtures.ProductionRuntimeAppTests.wait_for

    def test_actual_runtime_failed_renewal_reaches_report_and_survives_stop(self):
        self.app.start_monitor()
        self.wait_for(lambda: self.app._monitor_session is not None)
        self.backend.renew = lambda *args: False
        self.wait_for(lambda: self.runtime.current().phase == 'alarm'
                      and self.runtime.current().cleanup_status == 'confirmed')
        first = self.runtime.current().guard_diagnostic
        self.assertIsNotNone(first)
        self.assertEqual(first.outcome, 'exception')
        self.app._poll_monitor()
        self.app.refresh()
        report = self.app.report.get('1.0','end-1c')
        self.assertIn('更新转发租约 · 已返回', report)
        self.assertIn('签发短租约', report)
        self.assertIn('快速核验阶段诊断：发生异常', report)
        self.assertIn('待真实验收', report)
        self.assertTrue(self.backend.revoked)
        self.assertIsNone(self.app._monitor_view)
        self.app.stop_monitor()
        self.app._poll_monitor()
        self.assertEqual(self.runtime.current().guard_diagnostic, first)
        self.assertIn('快速核验阶段诊断：发生异常', self.app._render_report())


if __name__ == '__main__':
    unittest.main()
