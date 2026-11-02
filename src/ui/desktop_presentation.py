"""Text for the protected desktop launch (R33); reads a DesktopView only."""
import math


_PHASES = {'idle': '未启动', 'preparing': '正在准备（检测、加规则、启动）', 'running': '正在保护桌面端（只走本机代理端口）',
           'fused': '已熔断，桌面端已断网', 'desktop_exited': '桌面端已退出，转发已停止',
           'stopping': '正在停止', 'waiting_exit': '等待桌面端退出后撤除规则', 'failed': '未能启动保护',
           'blocked': '有未撤除的桌面端规则', 'abandoned': '助手关闭，桌面端保持断网'}
_REASONS = {
    'preparing': '已开始', 'protecting': '核验正常', 'launching': '正在启动桌面端', 'user_stopped': '用户停止',
    'desktop_running': '桌面端或其自带 Claude Code 仍在运行，请先从托盘退出',
    'desktop_executables_unconfirmed': '桌面端程序位置未确认',
    'manager_sample_failed': '管理器检测未完成', 'manager_sample_timeout': '管理器检测超时',
    'manager_owner_unconfirmed': '代理监听归属未确认', 'manager_unconfirmed': '管理器检测未全部通过',
    'exit_ip_mismatch': '出口 IP 与预期不一致', 'target_exit_mismatch': 'Claude 目标请求出口与预期不一致',
    'manager_unavailable': 'Proxy Manager 不可用', 'proxy_unavailable': '代理端口不可用',
    'mapping_unconfirmed': '映射或区域未通过', 'system_policy_unconfirmed': '系统规则未确认',
    'system_permission_denied': '没有添加系统规则的权限（需要管理员）',
    'desktop_launch_failed': '桌面端未能启动', 'desktop_binding_unconfirmed': '桌面端进程身份未确认',
    'initial_guard_failed': '首轮快速核验未通过', 'preparation_failed': '准备未完成',
    'desktop_exited': '桌面端已退出', 'unknown_desktop_executable': '桌面端出现规则外的新程序（可能自动更新了）',
    'proxy_owner_unconfirmed': '代理监听归属未确认', 'proxy_owner_changed': 'Proxy Manager 监听归属发生变化',
    'desktop_route_changed': '桌面端出现不经转发口的连接', 'guard_timeout': '快速核验超时',
    'guard_failed': '快速核验未通过', 'relay_not_authorized': '转发授权未确认',
    'guard_timeout_overdue': '快速核验超时', 'manager_timeout': '管理器检测超时',
    'exit_evidence_expired': '出口证据已过期', 'exit_timeout': '快速出口核验超时',
    'exit_check_failed': '快速出口核验异常', 'manager_evidence_expired': '完整检测证据已过期', 'resume_checking': '正在复检',
    'cleanup_pending': '上次的桌面端规则尚未撤除，退出桌面端后点“停止桌面端保护”清理',
    'recovering_rules': '正在清理上次的规则', 'removing_rules': '正在撤除规则',
    'desktop_still_running': '桌面端仍在运行，请从托盘退出', 'desktop_state_unknown': '桌面端进程状态未确认',
    'cleanup_unconfirmed': '规则撤除未确认', 'assistant_closed': '助手已关闭'}
_RELAY = {'reserved': '已预留，未转发', 'forwarding': '转发中', 'paused': '已停止转发（端口保留）',
          'closed': '已关闭', 'unbound': '未建立'}
_CLEANUP = {'not_applicable': '无需清理', 'pending': '规则仍在（未撤除）', 'confirmed': '已撤除并确认',
            'unknown': '未确认'}


def reason_label(code):
    if not isinstance(code, str):
        return '未确认'
    if code.startswith('resume_rejected_'):
        return '复检未通过：' + reason_label(code[len('resume_rejected_'):])
    if code == 'relay_not_authorized':
        return '转发授权未确认'
    if code.startswith('relay_'):
        return '转发已停止（' + {'relay_lease_expired': '授权到期', 'relay_upstream_unconfirmed': '上游未确认',
                                 'relay_worker_error': '转发异常', 'relay_proxy_owner_changed': '监听归属变化',
                                 'relay_acceptor_error': '接收异常', 'relay_watchdog_error': '计时异常'
                                 }.get(code, '原因未确认') + '）'
    return _REASONS.get(code, '原因未确认')


def desktop_summary(view):
    if view is None:
        return '桌面端保护：未接入'
    text = '桌面端保护：' + _PHASES.get(view.phase, '状态未确认')
    if view.reason_code not in ('not_started', 'preparing', 'protecting'):
        text += '；' + reason_label(view.reason_code)
    return text


def _remaining(deadline, now):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        return '未确认'
    return '已到期' if deadline <= now else f'剩余 {deadline - now:.1f} 秒'


def desktop_report_lines(view, now, time_text):
    lines = ['', desktop_summary(view)]
    if view is None or view.phase == 'idle' and not view.events:
        lines.append('桌面端保护说明：点“保护启动桌面端”后，桌面端只能连助手转发口，再经本机代理端口出去；出口或核验异常即断网，不关闭桌面端。')
        return lines
    lines.append('作用对象：本次由助手保护启动的桌面端（包内 Claude.exe 与自带 Claude Code）；手动打开的桌面端不受保护。')
    lines.append('桌面端拉起的其他子程序（PowerShell、MCP 工具等）不受系统规则限制，不保证不直连。')
    lines.append('出口证据：助手经同一个本机代理端口独立请求取得，不是桌面端每条连接的逐条证明。')
    lines.append('转发口：' + (_RELAY.get(view.relay_state, '未建立') if view.relay_state else '未建立')
                 + f' · 连接 {view.active_connections} · 已拒绝 {view.rejected_connections}')
    lines.append(f'系统规则：{_CLEANUP.get(view.cleanup_status, "未确认")} · 受限程序 {view.executables} 个')
    lines.append(f'受保护进程：{view.protected_processes} · 其他子程序：{view.other_children}')
    lines.append(f'出口证据：{_remaining(view.exit_expires_at, now)} · 出口核验 {view.exit_sequence} 次'
                 f' · 管理器采样 {view.manager_sequence} 次')
    lines.append(f'快速核验：{_remaining(view.guard_expires_at, now)} · 序号 {view.guard_sequence}')
    lines.append('IP 变化最长约 30 秒发现；发现后 2 秒内停止转发。')
    if view.events:
        lines.append('桌面端保护事件（本次运行，最多 100 条）：')
        for when, text in view.events:
            phase, _, reason = text.partition(':')
            lines.append(time_text(when) + ' · ' + _PHASES.get(phase, '状态未确认') + ' · ' + reason_label(reason))
    return lines
