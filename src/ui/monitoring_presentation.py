"""Validate and redact core monitoring snapshots without running a monitor."""
from dataclasses import dataclass
from datetime import datetime, timezone
import math


_REASONS = {
    'started': '监测已开始', 'stopped': '监测已停止', 'manual_resume': '用户发起手动复检',
    'check_pass': '独立检测通过', 'exit_ip_mismatch': '独立出口与预期不一致',
    'target_exit_mismatch': '目标请求出口与预期不一致', 'owner_unconfirmed': '监听归属未确认',
    'owner_changed': '监听归属发生变化', 'proxy_unavailable': '代理入口不可用',
    'manager_unavailable': '管理器不可用', 'mapping_unconfirmed': '映射或区域未通过',
    'evidence_unconfirmed': '检测证据未确认', 'evidence_expired': '检测证据已过期',
    'check_timeout': '检测超时', 'detector_error': '检测未能完成',
    'previous_check_running': '先前检测尚未结束', 'clock_unavailable': '检测计时未确认',
    'browser_binding_changed': '专用浏览器绑定发生变化',
    'browser_check_pass': '专用浏览器本次身份、请求及代理绑定通过',
    'browser_evidence_expired': '浏览器证据已过期',
    'browser_evidence_invalid': '浏览器证据格式无效',
    'browser_evidence_unconfirmed': '浏览器证据未确认',
    'browser_exit_mismatch': '浏览器本次出口与预期不一致',
    'browser_identity_unconfirmed': '专用浏览器身份未确认',
    'browser_provider_error': '浏览器证据采集未能完成',
    'browser_provider_missing': '浏览器请求证据提供者未接入',
    'browser_proxy_mismatch': '浏览器本次代理绑定不一致',
    'browser_request_unconfirmed': '浏览器本次目标请求未确认',
    'browser_sample_mismatch': '浏览器证据与本次采样不匹配',
    'browser_profile_unconfirmed': '浏览器本次请求的配置目录未确认',
    'browser_profile_mismatch': '浏览器本次请求的配置目录不一致',
    'sample_budget_exhausted': '本会话采样额度已用完',
}
_ACTIONS = {'alert_only': '仅提示，未确认断连', 'monitor_only': '仅监测，未执行断连'}
_STATES = {'stopped': '已停止', 'checking': '正在独立检测', 'monitoring': '正在监测', 'alarm': '发现异常'}
_PROTECTION = ('not_enabled', 'unknown', 'blocked', 'protected')
_RELAY_STATES = {'unbound': '尚未绑定', 'bound': '已绑定，尚未监听',
                 'reserved': '端口已预留，未转发', 'diagnostic': '仅受控单次诊断',
                 'sealed': '诊断通道已封闭',
                 'listening': '转发器报告监听中', 'closed': '转发器报告已关闭'}
_RELAY_REASONS = {
    'not_started': '尚未启动', 'lease_active': '转发器报告租约有效',
    'lease_expired': '转发租约已过期', 'lease_invalid': '转发租约未确认',
    'lease_revoked': '转发租约已撤销', 'binding_changed': '转发绑定已变化',
    'upstream_unconfirmed': '转发上游归属未确认', 'stopped': '转发已停止',
    'start_error': '转发启动未能完成', 'acceptor_error': '转发接收未能完成',
    'watchdog_error': '转发有效期检查异常', 'worker_error': '转发处理未能完成',
    'port_reserved_no_forwarding': '端口已预留，未开放转发',
    'bounded_trace_only': '仅允许有界诊断请求',
    'diagnostic_complete_no_forwarding': '诊断已结束，未开放转发',
    'diagnostic_revoked': '诊断授权已撤销', 'diagnostic_expired': '诊断窗口已到期',
    'diagnostic_byte_limit': '诊断字节额度已达到',
    'diagnostic_connection_limit': '诊断连接额度已达到',
    'diagnostic_target_invalid': '诊断目标未确认', 'diagnostic_connect_failed': '诊断连接未能完成',
    'policy_changed': '专用规则发生变化', 'policy_expired': '专用规则证据已过期',
    'policy_unconfirmed': '专用规则证据未确认',
}

_RUNTIME_PHASES = {'idle': '尚未开始', 'preparing': '正在核验专用目标，身份和代理尚未确认',
                  'running': '正在监测所选专用 Chrome', 'alarm': '发现异常，等待手动复核',
                  'stopping': '正在停止并清理', 'blocked': '当前会话未确认，已阻止继续'}
_RUNTIME_REASONS = {
    'not_started': '尚未开始', 'user_stopped': '用户请求停止',
    'cleanup_unconfirmed': '清理未确认，请保留窗口与报告，勿重复启动',
    'cleanup_failed': '清理未确认，请保留窗口与报告，勿重复启动',
    'start_failed': '专用会话未能开始，请检查本次目标和代理配置',
    'runtime_unavailable': '生产会话接口暂不可用', 'binding_unconfirmed': '当前身份或证据未确认',
    'evidence_expired': '证据已过期', 'manager_expired': '管理器证据已过期',
    'exit_expired': '出口证据已过期', 'guard_expired': '快速核验证据已过期',
    'binding_changed': '专用浏览器身份已变化，请清理后重新选择',
    'exit_mismatch': '实际出口与预期不一致', 'guard_failed': '快速核验未通过',
    'manager_failed': '管理器核验未通过', 'exit_failed': '出口核验未通过',
    'preparation_failed': '专用会话准备未能完成',
    'dedicated_target_unconfirmed': '独立专用程序或数据目录未确认',
    'system_policy_unconfirmed': '专用系统规则未确认',
    'system_permission_denied': '系统规则权限不足，请保留失败报告',
    'browser_start_unconfirmed': '本次专用浏览器启动未确认',
    'initial_request_failed': '首次实际请求未通过', 'initial_guard_failed': '首次快速核验未通过',
    'manager_sample_failed': '管理器采样未通过', 'manager_sample_timeout': '管理器采样超时',
    'exit_sample_failed': '出口采样未通过', 'exit_sample_timeout': '出口采样超时',
    'guard_sample_failed': '快速核验未通过', 'guard_sample_timeout': '快速核验超时',
    'relay_closed': '转发器已关闭',
}


def runtime_summary(phase, reason_code=''):
    text = _RUNTIME_PHASES.get(phase, '状态未确认')
    if reason_code and reason_code not in ('not_started', 'preparing', 'monitoring'):
        text += '；' + _RUNTIME_REASONS.get(reason_code, '本次核验未通过，详见采样状态')
    return '专用 Chrome 持续监测：' + text + ' · 系统级保护：待真实验收'


_MANAGER_OUTCOMES = {'accepted': '本次采样已接受', 'rejected': '未通过', 'exception': '采样异常',
                     'timeout': '采样超时', 'cancelled': '采样已取消'}
_MANAGER_CHECKS = {'manager': '管理器接口', 'port': '本地代理端口', 'exit_ip': '独立出口',
                   'claude': 'Claude 首页（参考项）', 'target_trace': '目标出口请求',
                   'mapping': '映射与区域', 'owner': '监听归属'}
_MANAGER_STAGES = {'owner_before': '采样前监听归属', 'manager': '管理器接口',
                   'proxy_port': '本地代理端口', 'exit_ip': '独立出口',
                   'claude_home': 'Claude 首页（参考项）', 'target_trace': '目标出口请求',
                   'mapping': '映射与区域', 'owner_after': '采样后监听归属'}
_MANAGER_STATUSES = {'pass': '通过', 'fail': '未通过', 'unknown': '未确认', 'running': '执行中',
                     'completed': '已完成（未判定通过）', 'error': '执行异常'}
_MANAGER_ERRORS = {'cancelled_or_deadline': '取消或截止期限', 'timeout': '超时',
                   'http_status': 'HTTP 状态异常', 'http_protocol': 'HTTP 协议异常',
                   'encoding': '编码异常', 'process_query': '进程查询异常', 'os_error': '系统调用异常',
                   'invalid_data': '数据格式异常', 'unexpected_error': '未分类异常'}


def _diagnostic_label(labels, value):
    return labels.get(value, '未确认') if type(value) is str else '未确认'


def _diagnostic_seconds(value):
    return (f'{value:.2f} 秒' if type(value) in (int, float) and 0 <= value <= 86400
            and math.isfinite(value) else '未确认')


@dataclass(frozen=True)
class ManagerDiagnosticView:
    summary: str
    lines: tuple[str, ...]
    failed: bool
    interrupted: bool = False

    def report_lines(self):
        return self.lines


def present_manager_diagnostic(detail):
    if detail is None:
        return None
    outcome = getattr(detail, 'outcome', None)
    summary = _diagnostic_label(_MANAGER_OUTCOMES, outcome)
    lines = ['管理器采样诊断：' + summary,
             '采样耗时：' + _diagnostic_seconds(getattr(detail, 'elapsed_seconds', None))
             + '；预算：' + _diagnostic_seconds(getattr(detail, 'budget_seconds', None))]
    checks = getattr(detail, 'checks', ())
    if type(checks) in (tuple, list):
        for check in checks[:7]:
            if type(check) not in (tuple, list) or len(check) != 2:
                lines.append('检测项：未确认')
                continue
            name, status = check
            label = _diagnostic_label(_MANAGER_CHECKS, name) + '：' + _diagnostic_label(_MANAGER_STATUSES, status)
            lines.append(label)
            if status != 'pass' and summary == _diagnostic_label(_MANAGER_OUTCOMES, outcome):
                summary += ' · ' + label
    steps = getattr(detail, 'steps', ())
    if type(steps) in (tuple, list):
        for step in steps[:16]:
            label = _diagnostic_label(_MANAGER_STAGES, getattr(step, 'stage', None))
            status = _diagnostic_label(_MANAGER_STATUSES, getattr(step, 'status', None))
            line = '采样阶段：' + label + ' · ' + status + ' · ' + _diagnostic_seconds(getattr(step, 'elapsed_seconds', None))
            error = getattr(step, 'error_code', '')
            if error != '':
                line += ' · 错误类别：' + _diagnostic_label(_MANAGER_ERRORS, error)
                if summary == _diagnostic_label(_MANAGER_OUTCOMES, outcome):
                    summary += ' · ' + label + '：' + _diagnostic_label(_MANAGER_ERRORS, error)
            lines.append(line)
    error = getattr(detail, 'error_code', '')
    if error != '':
        lines.append('采样错误类别：' + _diagnostic_label(_MANAGER_ERRORS, error))
    rejection = getattr(detail, 'rejection_reason', '')
    if rejection != '':
        labels = dict(_REASONS, **_RUNTIME_REASONS, manager_sample_invalid='采样证据无效')
        lines.append('采样拒绝原因：' + _diagnostic_label(labels, rejection))
    return ManagerDiagnosticView(summary, tuple(lines), outcome != 'accepted', outcome == 'cancelled')


_GUARD_STAGES = {
    'guard_read': '读取快速核验', 'bound_before': '前置进程绑定', 'proxy_before': '前置代理归属',
    'routes': '连接路由', 'policy_read': '读取系统规则', 'policy_engine_open': '打开规则引擎',
    'policy_capabilities': '查询规则能力', 'policy_identity_before': '前置规则身份',
    'policy_objects_before': '前置规则对象', 'policy_objects_after': '后置规则对象',
    'policy_identity_after': '后置规则身份', 'policy_engine_close': '关闭规则引擎',
    'relay_policy': '转发规则凭据', 'bound_after': '后置进程绑定', 'proxy_after': '后置代理归属',
    'lease_issue': '签发短租约', 'relay_renew': '更新转发租约',
    'relay_promote': '首次开放转发',
}
_GUARD_OUTCOMES = {'accepted': '本次采样已接受', 'timeout': '已超时', 'exception': '发生异常',
                   'cancelled': '已取消', 'unavailable': '不可用'}
_GUARD_STATUSES = {'running': '运行中，已持续 ', 'returned': '已返回，用时 ', 'raised': '抛出异常，用时 '}


def _guard_milliseconds(value):
    if type(value) in (int, float) and 0 <= value <= 86400 and math.isfinite(value):
        return f'{value * 1000:.1f} 毫秒'
    return '耗时未确认'


def _guard_report_lines(detail):
    if detail is None:
        return ['快速核验阶段诊断：暂无记录']
    try:
        outcome = getattr(detail, 'outcome', None)
        scope = getattr(detail, 'scope', None)
        lines = ['快速核验阶段诊断：' + _diagnostic_label(_GUARD_OUTCOMES, outcome),
                 '诊断范围：' + _diagnostic_label({'sample': '监测采样', 'initialization': '初始化'},
                                               scope)]
        sequence = getattr(detail, 'sample_sequence', None)
        lines.append('采样序号：' + (str(sequence) if type(sequence) is int and 0 <= sequence <= 2147483647 else '未确认'))
        initialization = type(scope) is str and scope == 'initialization'
        lines.append(('初始化核验段耗时：' if initialization else '采样总耗时：')
                     + _guard_milliseconds(getattr(detail, 'elapsed_seconds', None))
                     + ('；快速核验预算：' if initialization else '；采样预算：')
                     + _guard_milliseconds(getattr(detail, 'budget_seconds', None))
                     + ('（不是整段初始化期限）' if initialization else ''))
        steps = getattr(detail, 'steps', None)
        incomplete = getattr(detail, 'incomplete', None) is not False
        if type(steps) is not tuple:
            steps, incomplete = (), True
        incomplete = incomplete or len(steps) > 24
        for step in steps[:24]:
            stage, status = getattr(step, 'stage', None), getattr(step, 'status', None)
            if (type(stage) is not str or stage not in _GUARD_STAGES
                    or type(status) is not str or status not in _GUARD_STATUSES
                    or (stage == 'relay_promote' and (type(scope) is not str or scope != 'initialization'))):
                incomplete = True
                continue
            duration = _guard_milliseconds(getattr(step, 'elapsed_seconds', None))
            timing = (_GUARD_STATUSES[status] + duration if duration != '耗时未确认' else
                      {'running': '运行中，持续耗时未确认', 'returned': '已返回，耗时未确认',
                       'raised': '抛出异常，耗时未确认'}[status])
            lines.append('快速核验阶段：' + _GUARD_STAGES[stage] + ' · ' + timing)
        error = getattr(detail, 'error_code', '')
        if type(error) is not str or error:
            lines.append('诊断错误类别：' + _diagnostic_label(_MANAGER_ERRORS, error))
        if incomplete:
            lines.append('诊断有缺失或已截断；未列出的阶段不代表未执行。')
        lines.append('父子阶段耗时有包含关系，不相加；阶段返回不代表核验通过。')
        lines.append('总耗时与阶段耗时精度不同，不相减推算其他阶段。')
        if type(outcome) is str and outcome == 'timeout':
            lines.append('超时快照是撤销后的观测，不是精确超时瞬间；运行中阶段仍可能尚未返回。')
        return lines
    except Exception:
        return ['快速核验阶段诊断：未确认', '诊断有缺失或已截断；不改变检测与保护条件。']


_WORKER_STAGES = {
    'client_identity': '客户端身份核验', 'client_setup': '客户端连接设置',
    'diagnostic_header': '受控诊断请求头读取', 'diagnostic_send': '受控诊断发送',
    'upstream_listener': '上游监听归属核验', 'upstream_socket': '创建上游连接',
    'upstream_setup': '上游连接设置', 'upstream_connect': '连接上游',
    'upstream_identity': '上游连接归属核验', 'pump': '双向转发',
    'pump_setup': '转发连接设置', 'pump_select': '等待连接读写',
    'client_recv': '读取客户端数据', 'upstream_recv': '读取上游数据',
    'client_send': '向客户端发送数据', 'upstream_send': '向上游发送数据',
    'client_half_close': '关闭客户端发送方向', 'upstream_half_close': '关闭上游发送方向',
}
_WORKER_ERRORS = {
    'connection_reset': '连接重置', 'connection_aborted': '连接中止',
    'connection_refused': '连接被拒绝', 'broken_pipe': '管道已断开',
    'timeout': '超时', 'os_error': '系统调用异常', 'invalid_data': '数据格式异常',
    'other_error': '其他异常',
}


def _worker_report_lines(view):
    missing = '转发诊断有缺失；未确认项不代表未发生。'
    if view is None:
        return ['转发异常诊断：暂无记录']
    try:
        detail = view.worker_diagnostic
        if detail is None:
            reason = getattr(getattr(view, 'relay_snapshot', None), 'reason_code', None)
            if type(reason) is not str or reason != 'worker_error':
                return ['转发异常诊断：暂无记录']
        stage = getattr(detail, 'stage', None)
        error = getattr(detail, 'error_code', None)
        lines = ['转发异常环节：' + _diagnostic_label(_WORKER_STAGES, stage),
                 '转发错误类别：' + _diagnostic_label(_WORKER_ERRORS, error)]
        if (getattr(detail, 'incomplete', None) is not False
                or type(stage) is not str or stage not in _WORKER_STAGES
                or type(error) is not str or error not in _WORKER_ERRORS):
            lines.append(missing)
        return lines
    except Exception:
        return ['转发异常诊断：未确认', missing]


def runtime_report_lines(view, now):
    lines = ['出口变化最多约 30 秒才发现；发现异常或相关证据到期即停止转发。',
             '转发短租约上限：2 秒；新短租约不延长旧出口证据。']
    if view is not None:
        sample = view.browser_evidence
        if (sample is not None and all(type(value) in (int, float) and math.isfinite(value)
                for value in (getattr(sample, 'sampled_at', None), getattr(sample, 'expires_at', None)))
                and 0 <= sample.sampled_at <= now and 0 < sample.expires_at - sample.sampled_at <= 30):
            lines.append(f'出口请求开始：{max(0.0, now - sample.sampled_at):.1f} 秒前；'
                         f'本次有效期 {sample.expires_at - sample.sampled_at:.1f} 秒（从请求开始计时）。')
        for key, label in (('manager', '管理器'), ('exit', '出口'), ('guard', '快速核验')):
            deadline = getattr(view, key + '_expires_at')
            valid = type(deadline) in (int, float) and math.isfinite(deadline)
            remaining = '未确认' if not valid else ('已到期' if deadline <= now else f'剩余 {deadline - now:.1f} 秒')
            lines.append(f'{label}证据：{remaining} · 序号 {getattr(view, key + "_sequence")}')
        cleanup = {'not_applicable': '尚无待清理会话', 'pending': '正在清理', 'confirmed': '已确认', 'unknown': '未确认'}
        lines.append('本次资源清理：' + cleanup.get(view.cleanup_status, '未确认'))
    lines.extend(_guard_report_lines(getattr(view, 'guard_diagnostic', None)))
    lines.extend(_worker_report_lines(view))
    lines.append('系统级保护：待用户真实验收；监测和转发状态不代表全面防直连。')
    return lines


@dataclass(frozen=True)
class RelayView:
    state_label: str
    reason_label: str
    mode_label: str
    active_connections: int

    def report_lines(self):
        return ('专用转发快照：' + self.state_label, '转发原因：' + self.reason_label,
                '转发运行范围：' + self.mode_label,
                '转发器报告的连接数：' + str(self.active_connections), '专用浏览器系统与路由保护：未确认')


def present_relay_snapshot(snapshot):
    from src.protection.session_relay import RelaySnapshot
    if (not isinstance(snapshot, RelaySnapshot) or snapshot.state not in _RELAY_STATES or
            not isinstance(snapshot.reason_code, str) or snapshot.protection not in _PROTECTION or
            type(snapshot.active_connections) is not int or not 0 <= snapshot.active_connections <= 16 or
            snapshot.mode not in ('local_test', 'runtime_unverified')):
        raise ValueError('转发快照不符合接口')
    return RelayView(_RELAY_STATES[snapshot.state], _RELAY_REASONS.get(snapshot.reason_code, '转发原因未确认'),
                     '本地测试，不证明系统保护' if snapshot.mode == 'local_test' else '运行路径与系统保护尚未验证',
                     snapshot.active_connections)


@dataclass(frozen=True)
class EventView:
    occurred_at: datetime
    reason_label: str
    action_label: str
    sequence: int


@dataclass(frozen=True)
class SnapshotView:
    state_label: str
    protection_label: str
    checked_at: datetime | None
    last_success_at: datetime | None
    reason_labels: tuple[str, ...]
    sequence: int
    events: tuple[EventView, ...]
    evidence_current: bool
    scope: str
    browser_status_label: str

    @property
    def scope_label(self):
        return ('所选专用浏览器的本次绑定，不证明全部连接。' if self.scope == 'dedicated_browser' else
                '独立代理请求，不证明桌面或网页的全部连接。')

    @property
    def evidence_label(self):
        if any('已过期' in reason for reason in self.reason_labels):
            return '已过期'
        if not self.evidence_current:
            return '未确认'
        return '当前浏览器本次绑定有效' if self.scope == 'dedicated_browser' else '当前独立检测有效'

    def report_lines(self):
        def stamp(value):
            return value.astimezone().strftime('%Y-%m-%d %H:%M:%S %z') if value else '未确认'
        protection = '阻断未启用' if self.protection_label == '未启用' else '阻断效果未确认'
        lines = [f'持续监测：{self.state_label}，{protection}',
                 '监测范围：' + self.scope_label,
                 '浏览器本次绑定：' + self.browser_status_label,
                 '监测最近检测：' + stamp(self.checked_at),
                 '监测最近成功：' + stamp(self.last_success_at),
                 '监测证据：' + self.evidence_label]
        lines.extend('监测原因：' + label for label in self.reason_labels)
        lines.extend(stamp(event.occurred_at) + ' · ' + event.reason_label + ' · ' + event.action_label for event in self.events)
        if self.state_label == '发现异常':
            lines.append('未确认已断开专用浏览器的连接；恢复须手动复检。')
        return tuple(lines)


def _utc(value):
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('监测时间不符合接口')
    return value.astimezone(timezone.utc)


def present_snapshot(snapshot, *, previous_sequence=0):
    """Map a core snapshot to fixed labels; reject malformed or regressing input."""
    try:
        state, protection = snapshot.state, snapshot.protection
        checked, last = _utc(snapshot.checked_at), _utc(snapshot.last_success_at)
        reasons, sequence, events = snapshot.reason_codes, snapshot.sequence, snapshot.events
        scope = getattr(snapshot, 'scope', 'independent_proxy')
        browser_status = getattr(snapshot, 'browser_status', 'unknown')
        if (state not in _STATES or protection not in _PROTECTION or
                scope not in ('independent_proxy', 'dedicated_browser') or
                browser_status not in ('unknown', 'pass', 'fail') or
                (scope == 'independent_proxy' and browser_status != 'unknown') or
                type(previous_sequence) is not int or previous_sequence < 0 or
                type(sequence) is not int or sequence < previous_sequence or
                not isinstance(reasons, tuple) or len(reasons) > 128 or
                not all(isinstance(reason, str) for reason in reasons) or
                not isinstance(events, tuple) or len(events) > 128):
            raise ValueError('监测快照不符合接口')
        result = []
        previous_event = 0
        for event in events:
            when, reason, action, event_sequence = event.occurred_at, event.reason_code, event.action_code, event.sequence
            if (when is None or not isinstance(reason, str) or not isinstance(action, str) or
                    type(event_sequence) is not int or not previous_event < event_sequence <= sequence):
                raise ValueError('监测事件不符合接口')
            previous_event = event_sequence
            result.append(EventView(_utc(when), _REASONS.get(reason, '监测异常，原因未确认'),
                                    _ACTIONS.get(action, '处理结果未确认'), event_sequence))
        evidence = (state == 'monitoring' and checked is not None and last == checked and not reasons and
                    (scope == 'independent_proxy' or browser_status == 'pass'))
        state_label = ('监测已停止，异常仍需手动复检' if state == 'stopped' and reasons else
                       '监测状态未确认' if state == 'monitoring' and not evidence else _STATES[state])
        return SnapshotView(state_label, '未启用' if protection == 'not_enabled' else '未确认',
                            checked, last, tuple(_REASONS.get(reason, '监测异常，原因未确认') for reason in reasons),
                            sequence, tuple(result[-100:]), evidence, scope,
                            '通过' if scope == 'dedicated_browser' and browser_status == 'pass' and evidence else
                            '未通过' if browser_status == 'fail' else '未确认')
    except (AttributeError, TypeError, OverflowError):
        raise ValueError('监测快照不符合接口') from None
