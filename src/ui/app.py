import os
import queue
import re
import threading
import time
import math
import ntpath
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .model import Config, Result, Status, load_config, render_report, save_config
from .adapters import LiveBackend, Probe
from .monitoring_presentation import (present_snapshot, present_relay_snapshot, runtime_summary,
                                     runtime_report_lines, present_manager_diagnostic)
from .monitor_binding import BindingEvidence, ManagedMonitorBinding, _config_key
from .desktop_presentation import desktop_summary, desktop_report_lines

MAPPING_LABELS = {'unknown': '未确认', 'required': '需要目标映射', 'not_required': '明确不需要目标映射'}
MONITOR_REASONS = {'started': '监测已开始', 'stopped': '监测已停止', 'manual_resume': '用户发起手动复检', 'check_pass': '独立检测通过', 'exit_ip_mismatch': '独立出口与预期不一致', 'ip_mismatch': '出口与预期不一致', 'target_exit_mismatch': '目标请求出口与预期不一致', 'owner_unconfirmed': '监听归属未确认', 'owner_changed': '监听归属发生变化', 'proxy_unavailable': '代理入口不可用', 'manager_unavailable': '管理器不可用', 'mapping_unconfirmed': '映射或区域未通过', 'evidence_unconfirmed': '检测证据未确认', 'evidence_expired': '检测证据已过期', 'check_timeout': '检测超时', 'detector_error': '检测未能完成', 'previous_check_running': '先前检测尚未结束', 'clock_unavailable': '检测计时未确认'}
MONITOR_ACTIONS = {'alert_only': '仅提示，未确认断连', 'monitor_only': '仅监测，未执行断连'}
_BROWSER_MONITOR_BLOCKED = object()


def _default_monitor_factory(config):
    raise RuntimeError('专用浏览器身份和代理绑定未确认')


class UnconnectedBackend:
    """Safe default: no checks or launches are performed."""
    def detect(self, config, app_id):
        return Probe(Result(reason_codes=('backend_unavailable',)))

    def discover_desktop(self):
        return ()

    def launch_desktop(self, config, app_id):
        raise RuntimeError('检测与启动后端未接入。')

    def launch_browser(self, config):
        raise RuntimeError('检测与启动后端未接入。')


class App:
    def __init__(self, root, backend=None, config_path=None, clock=time.monotonic, monitor_factory=None,
                 monitor_binding_provider=None, monitor_relay_snapshot=None, relay_max_lease_seconds=None,
                 monitor_max_samples=None, monitor_runtime=None, desktop_runtime=None):
        self._monitor_runtime = monitor_runtime
        self._desktop_runtime = desktop_runtime
        self._desktop_view = None
        self._desktop_request_id = ''
        self._managed_adapter = None
        self._managed_request_id = ''
        self._managed_phase = 'idle'
        self._managed_cleanup = 'not_applicable'
        self._managed_view = None
        self._managed_diagnostic = None
        self._managed_error = ''
        self._managed_stop_requested = False
        self._managed_closing = self._managed_closed = False
        if monitor_runtime is not None:
            if any(value is not None for value in (monitor_factory, monitor_binding_provider,
                    monitor_relay_snapshot, relay_max_lease_seconds, monitor_max_samples)):
                raise ValueError('生产运行时不能混用外部监测提供者')
            self._managed_adapter = ManagedMonitorBinding(monitor_runtime, clock=clock)
            monitor_factory = self._managed_adapter.session_for
            monitor_binding_provider = self._managed_adapter
            monitor_relay_snapshot = self._managed_adapter.relay_snapshot
            relay_max_lease_seconds = monitor_runtime.current().sampling_budget.relay_max_lease_seconds
        if monitor_max_samples is not None and (type(monitor_max_samples) is not int or monitor_max_samples != 1
                                                or monitor_binding_provider is None):
            raise ValueError('单轮诊断须显式绑定身份提供者且额度为一次')
        if monitor_relay_snapshot is not None:
            try:
                valid_relay = (callable(monitor_relay_snapshot) and monitor_binding_provider is not None and
                               type(relay_max_lease_seconds) in (int, float) and
                               math.isfinite(relay_max_lease_seconds) and 0 < relay_max_lease_seconds <= 10)
            except OverflowError:
                valid_relay = False
            if not valid_relay:
                raise ValueError('转发快照须绑定身份提供者和明确的租约上限')
        self.root = root
        self.backend = backend or UnconnectedBackend()
        default_dir = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ClaudeLaunchCenter'
        self.config_path = Path(config_path) if config_path else default_dir / 'settings.json'
        self.config = Config()
        self.result = Result()
        self.history = []
        self._last_detection = None
        self._last_launch = None
        self._launch_target = ''
        self.saved = False
        self.clock = clock
        self.busy = False
        self._operation = ''
        self._generation = 0
        self._evidence_started = None
        self._applications = ()
        self._selected_app = None
        self._queue = queue.Queue()
        self._candidate_dialog = None
        self._release_dialog = None
        self._port_dialog = None
        self._shortcut_dialog = None
        self._guide_dialog = None
        self._first_setup_dialog = None
        self._candidate_previous = None
        self._candidate_recheck = None
        self._pending_save_config = None
        self._monitor_factory = monitor_factory or _default_monitor_factory
        self._monitor_binding_provider = monitor_binding_provider
        self._monitor_config = None
        self._monitor_selection = None
        self._monitor_max_samples = monitor_max_samples
        self._diagnostic_started = False
        self._monitor_relay_snapshot = monitor_relay_snapshot
        self._relay_max_lease = relay_max_lease_seconds
        self._relay_view = None
        self._relay_error = False
        self._monitor_binding_key = None
        self._monitor_session = None
        self._monitor_state = 'stopped'
        self._monitor_protection = 'not_enabled'
        self._monitor_latched = False
        self._monitor_resume_pending = False
        self._monitor_resume_baseline = None
        self._monitor_checked_at = None
        self._monitor_last_success_at = None
        self._monitor_reasons = ()
        self._monitor_events = []
        self._monitor_event_cursor = 0
        self._monitor_sequence = 0
        self._monitor_error = ''
        self._monitor_view = None
        self._monitor_invalid = False
        self._monitor_resume_sequence = 0
        self.trust_status = tk.StringVar(value='可信基准未确认；可选择安装包核验。')
        self.monitor_summary = tk.StringVar(value='持续监测：专用浏览器身份未确认，未启动 · 阻断保护：未启用')
        if monitor_max_samples == 1:
            self.monitor_summary.set('单轮诊断：尚未开始，最多采样一次 · 阻断保护：未确认')
        root.title('Claude 专用启动中心')
        root.geometry('900x840')
        root.minsize(760, 700)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(4, weight=1)

        header = ttk.Frame(root, padding=(18, 15, 18, 8))
        header.grid(row=0, column=0, sticky='ew')
        title_row = ttk.Frame(header)
        title_row.pack(fill='x')
        ttk.Label(title_row, text='Claude 专用启动中心', font=('Microsoft YaHei UI', 17, 'bold')).pack(side='left')
        self.summary = tk.StringVar(value='等待配置与检测 · 桌面端：未确认 · 网页端：未确认')
        ttk.Label(header, textvariable=self.summary, wraplength=780).pack(anchor='w', pady=(8, 0))
        ttk.Label(header, textvariable=self.monitor_summary, wraplength=780).pack(anchor='w', pady=(4, 0))
        self.desktop_protect_summary = tk.StringVar(value=desktop_summary(None))
        if desktop_runtime is not None:
            ttk.Label(header, textvariable=self.desktop_protect_summary, wraplength=780).pack(anchor='w', pady=(4, 0))
        self.monitor_target_text = tk.StringVar(value='本次专用 Chrome：未选择；原浏览器配置保持不变。')
        self.monitor_target_button = ttk.Button(title_row, text='选择本次专用 Chrome', command=self.choose_monitor_target)
        self.monitor_target_button.pack(side='right')

        actions = ttk.Frame(root, padding=(18, 0, 18, 6))
        actions.grid(row=1, column=0, sticky='ew')
        self.detect_button = ttk.Button(actions, text='重新检测', command=self.detect)
        self.detect_button.pack(side='left', padx=(0, 8))
        self.desktop_button = ttk.Button(actions, text='启动桌面端', command=self.launch_desktop, state='disabled')
        self.desktop_button.pack(side='left', padx=(0, 8))
        self.browser_button = ttk.Button(actions, text='打开网页端', command=self.launch_browser, state='disabled')
        self.browser_button.pack(side='left')
        self.desktop_protect_button = ttk.Button(actions, text='保护启动桌面端', command=self.protect_desktop, state='disabled')
        self.desktop_stop_button = ttk.Button(actions, text='停止桌面端保护', command=self.stop_desktop_protection, state='disabled')
        self.desktop_resume_button = ttk.Button(actions, text='恢复桌面端保护', command=self.resume_desktop_protection, state='disabled')
        if desktop_runtime is not None:
            for button in (self.desktop_protect_button, self.desktop_stop_button, self.desktop_resume_button):
                button.pack(side='left', padx=(8, 0))
        ttk.Button(actions, text='使用步骤', command=self.open_guide).pack(side='right')
        ttk.Button(actions, text='首次配置向导', command=self.open_first_setup).pack(side='right', padx=(0, 8))

        settings = ttk.LabelFrame(root, text='首次配置 / 代理与浏览器设置', padding=10)
        settings.grid(row=2, column=0, sticky='ew', padx=18, pady=6)
        settings.columnconfigure(1, weight=1)
        self.fields = {}
        self.entries = []
        self.settings_tabs = ttk.Notebook(settings)
        self.settings_tabs.grid(row=0, column=0, columnspan=2, sticky='ew')
        proxy_settings = ttk.Frame(self.settings_tabs, padding=4)
        trust_settings = ttk.Frame(self.settings_tabs, padding=4)
        browser_settings = ttk.Frame(self.settings_tabs, padding=4)
        proxy_settings.columnconfigure(1, weight=1)
        trust_settings.columnconfigure(1, weight=1)
        browser_settings.columnconfigure(1, weight=1)
        self.settings_tabs.add(proxy_settings, text='代理配置')
        self.settings_tabs.add(trust_settings, text='可信基准与映射')
        self.settings_tabs.add(browser_settings, text='网页与浏览器')
        fields = [('port', '本机代理端口'), ('manager_port', 'Proxy Manager 管理端口'), ('manager_executable', '管理器程序路径（核验后填入）'), ('manager_sha256', '程序指纹（核验后填入）'), ('expected_ip', '预期出口 IP'), ('ip_url', '出口 IP 检测服务 HTTPS 地址'), ('mapping_mode', '目标映射要求'), ('expected_zone', '预期 Bright Data 区域'), ('mapping_targets', '预期映射（IPv4 域名；多项以分号隔开）'), ('url', 'Claude 网页地址'), ('chrome_path', 'Chrome 可执行文件绝对路径'), ('user_data_dir', 'Chrome 用户数据目录绝对路径'), ('chrome_profile', '用户数据目录下的配置目录名称')]
        web_fields = {'url', 'chrome_path', 'user_data_dir', 'chrome_profile'}
        trust_fields = {'manager_executable', 'manager_sha256', 'mapping_mode', 'expected_zone', 'mapping_targets'}
        row_by_tab = {proxy_settings: 0, trust_settings: 0, browser_settings: 0}
        for row, (key, label) in enumerate(fields):
            group = browser_settings if key in web_fields else trust_settings if key in trust_fields else proxy_settings
            row = row_by_tab[group]
            row_by_tab[group] += 1
            ttk.Label(group, text=label).grid(row=row, column=0, sticky='w', padx=(0, 12), pady=3)
            var = tk.StringVar()
            self.fields[key] = var
            entry = ttk.Combobox(group, textvariable=var, state='readonly', values=tuple(MAPPING_LABELS.values())) if key == 'mapping_mode' else ttk.Entry(group, textvariable=var, show='●' if key in ('expected_ip', 'manager_sha256') else '')
            entry.grid(row=row, column=1, sticky='ew', pady=3)
            self.entries.append(entry)
            var.trace_add('write', self._invalidate)
        ttk.Button(proxy_settings, text='查找已有端口', command=self.open_port_candidates).grid(row=row_by_tab[proxy_settings], column=1, sticky='e', pady=(5, 0))
        ttk.Button(browser_settings, text='选择已有 Chrome 快捷方式', command=self.open_shortcut).grid(row=row_by_tab[browser_settings], column=1, sticky='e', pady=(5, 0))
        ttk.Label(settings, text='已发现的桌面应用（手动选择）').grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.desktop_choice = ttk.Combobox(settings, state='readonly')
        self.desktop_choice.grid(row=1, column=1, sticky='ew', pady=(6, 0))
        self.desktop_choice.bind('<<ComboboxSelected>>', self._select_desktop)
        self.find_desktop_button = ttk.Button(settings, text='查找桌面端', command=self.find_desktop)
        self.find_desktop_button.grid(row=1, column=2, padx=(8, 0), pady=(6, 0))
        self.desktop_lookup = tk.StringVar(value='尚未查找')
        ttk.Label(settings, textvariable=self.desktop_lookup).grid(row=1, column=3, padx=(8, 0), pady=(6, 0), sticky='w')
        ttk.Button(settings, text='核验管理器安装来源', command=self.open_release_setup).grid(row=2, column=0, sticky='w', pady=(7, 0))
        self.save_button = ttk.Button(settings, text='保存本机配置', command=self.save_settings)
        self.save_button.grid(row=2, column=1, sticky='e', pady=(7, 0))
        ttk.Label(settings, text='可信路径和指纹需来自独立核验，不能把现场运行程序的指纹自动当作可信基准。', wraplength=700).grid(row=3, column=0, columnspan=2, sticky='w')
        ttk.Label(settings, text='点击检测将经指定代理访问您选择的出口检测服务及 Claude。', wraplength=700).grid(row=4, column=0, columnspan=2, sticky='w')
        ttk.Label(settings, textvariable=self.trust_status, wraplength=700).grid(row=5, column=0, columnspan=2, sticky='w')

        report_actions = ttk.Frame(root, padding=(18, 4, 18, 4))
        report_actions.grid(row=3, column=0, sticky='ew')
        self.full_ip = tk.BooleanVar(value=False)
        ttk.Checkbutton(report_actions, text='报告包含完整 IP（主动选择）', variable=self.full_ip, command=self.refresh).pack(side='left')
        self.start_monitor_button = ttk.Button(report_actions, text='开始单轮诊断' if monitor_max_samples == 1 else '开始监测', command=self.start_monitor)
        self.start_monitor_button.pack(side='left', padx=(4, 0))
        self.stop_monitor_button = ttk.Button(report_actions, text='停止诊断' if monitor_max_samples == 1 else '停止监测', command=self.stop_monitor)
        self.stop_monitor_button.pack(side='left', padx=(4, 0))
        self.resume_monitor_button = ttk.Button(report_actions, text='单轮诊断不可重试' if monitor_max_samples == 1 else '手动复检恢复', command=self.resume_monitor)
        self.resume_monitor_button.pack(side='left', padx=(4, 0))
        ttk.Button(report_actions, text='复制报告', command=self.copy_report).pack(side='right')
        ttk.Button(report_actions, text='导出报告', command=self.export_report).pack(side='right', padx=8)

        details = ttk.LabelFrame(root, text='检测详情与报告', padding=8)
        details.grid(row=4, column=0, sticky='nsew', padx=18, pady=(4, 6))
        details.columnconfigure(0, weight=1)
        details.rowconfigure(0, weight=1)
        self.report = tk.Text(details, height=10, wrap='word', state='disabled')
        self.report.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(details, command=self.report.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        self.report.configure(yscrollcommand=scroll.set)
        history_bar = ttk.Frame(root, padding=(18, 0, 18, 10))
        history_bar.grid(row=5, column=0, sticky='ew')
        self.history_text = tk.StringVar(value='本次运行历史：暂无检测')
        ttk.Label(history_bar, textvariable=self.history_text, wraplength=600).pack(side='left')
        ttk.Button(history_bar, text='查看历史', command=self.show_history).pack(side='right')
        try:
            self.config = load_config(self.config_path)
            self.saved = True
        except FileNotFoundError:
            pass
        except (ValueError, TypeError, OSError):
            messagebox.showwarning('配置未读取', '配置文件无法读取或格式不正确，请重新填写。', parent=root)
        self._put_config(self.config)
        try:
            self.config.validate_common()
            self.config.validate_browser_fields()
            self.saved = True
            if self.config.manager_executable and self.config.manager_sha256:
                self.trust_status.set('已保存管理器基准；当前监听和程序是否匹配仍待检测。')
        except ValueError:
            self.saved = False
        self.refresh()
        self._poll_id = self.root.after(50, self._poll)
        self.root.bind('<Destroy>', self._on_destroy, add='+')
        if self._monitor_runtime is not None or self._desktop_runtime is not None:
            self.root.protocol('WM_DELETE_WINDOW', self.request_close)
        if self._desktop_runtime is not None:
            self._poll_desktop()
        if self._monitor_runtime is not None:
            self._poll_managed()
            self.refresh()

    def _managed_can_select(self):
        return (not self._managed_closing and self._managed_phase in ('idle', 'alarm', 'blocked')
                and self._managed_cleanup in ('confirmed', 'not_applicable'))

    def _start_managed(self, resume=False):
        if self.busy or not self.saved or self._monitor_config is None or not self._managed_can_select():
            return
        if resume and (self._managed_phase != 'alarm' or self._managed_cleanup != 'confirmed'
                       or self._monitor_binding_key is None):
            return
        from .adapters import to_core_config
        previous_key = self._monitor_binding_key
        self._managed_request_id = uuid.uuid4().hex
        self._managed_phase, self._managed_cleanup = 'preparing', 'pending'
        self._managed_stop_requested = False
        self._managed_error = ''
        self._managed_view = self._monitor_view = self._relay_view = None
        self._managed_diagnostic = None
        self._monitor_session = self._monitor_binding_key = None
        self._monitor_state = 'checking'
        self._monitor_invalid = False
        self._monitor_sequence = self._monitor_event_cursor = 0
        self.monitor_summary.set(runtime_summary('preparing'))
        try:
            if resume:
                self._monitor_runtime.request_resume(previous_key, self._managed_request_id)
            else:
                self._monitor_runtime.request_start(to_core_config(self._monitor_config), self._monitor_selection,
                    config_fingerprint=_config_key(self._monitor_config), request_id=self._managed_request_id)
        except Exception:
            self._managed_failure('runtime_unavailable')
        self.refresh()

    def _request_managed_stop(self):
        if self._managed_stop_requested:
            return
        self._managed_stop_requested = True
        self._managed_phase, self._managed_cleanup = 'stopping', 'pending'
        self._monitor_view = self._relay_view = None
        try:
            # The runtime owns this request and every resource; the UI never stops
            # a sampler separately or waits for a detector on the Tk thread.
            self._monitor_runtime.request_stop(request_id=self._managed_request_id)
        except Exception:
            self._managed_phase, self._managed_cleanup = 'blocked', 'unknown'
            self._managed_error = 'cleanup_unconfirmed'
        self.monitor_summary.set(runtime_summary(self._managed_phase, self._managed_error))

    def _managed_failure(self, reason):
        self._managed_error = reason
        self._monitor_latched = True
        self._monitor_view = self._relay_view = None
        self._request_managed_stop()

    def _desktop_active(self):
        view = self._desktop_view
        return view is not None and view.phase not in ('idle', 'failed')

    def _chrome_active(self):
        return self._monitor_runtime is not None and not (
            self._managed_phase in ('idle', 'alarm') and self._managed_cleanup in ('confirmed', 'not_applicable'))

    def _desktop_can_start(self):
        # D4: the protected desktop and the dedicated Chrome monitor never run at the same time.
        return (self._desktop_runtime is not None and not self._desktop_active() and not self._chrome_active()
                and self.saved and not self.busy and self._fresh() and self.result.can_start_desktop
                and self._selected_app in self._applications)

    def protect_desktop(self):
        self._poll_desktop()
        if not self._desktop_can_start():
            self.refresh()
            return
        from .adapters import to_core_config
        self._desktop_request_id = uuid.uuid4().hex
        try:
            started = self._desktop_runtime.request_start(to_core_config(self.config), self._selected_app,
                                                          self._desktop_request_id)
        except Exception:
            started = False
        self._record_launch('桌面端（保护启动）', '已请求开始保护' if started else '桌面端保护未能开始')
        # The pre-launch detection is consumed, as with the original launch button.
        self.result = Result()
        self._evidence_started = None
        if not started:
            messagebox.showwarning('未启动桌面端保护', '桌面端保护未能开始；请确认没有残留规则并重新检测。', parent=self.root)
        self._poll_desktop()
        self.refresh()

    def stop_desktop_protection(self):
        if self._desktop_runtime is None:
            return
        try:
            stopping = self._desktop_runtime.request_stop()
        except Exception:
            stopping = False
        if stopping:
            messagebox.showinfo('停止桌面端保护', '已停止转发。请从托盘退出桌面端；确认桌面端已退出后，助手会自动撤除系统规则。', parent=self.root)
        self._poll_desktop()
        self.refresh()

    def resume_desktop_protection(self):
        if self._desktop_runtime is None:
            return
        try:
            self._desktop_runtime.request_resume()
        except Exception:
            pass
        self._poll_desktop()
        self.refresh()

    def _poll_desktop(self):
        if self._desktop_runtime is None:
            return False
        try:
            view = self._desktop_runtime.current()
        except Exception:
            view = None
        changed = view != self._desktop_view
        self._desktop_view = view
        self.desktop_protect_summary.set(desktop_summary(view))
        return changed

    def request_close(self):
        if self._desktop_active() and self._desktop_view.phase not in ('blocked', 'abandoned'):
            # D2: closing the assistant leaves the protected desktop offline until the next cleanup.
            if not messagebox.askyesno('桌面端保护仍在运行',
                    '请先从托盘退出桌面端，再点“停止桌面端保护”。\n\n仍要关闭助手吗？关闭后桌面端会保持断网；'
                    '下次打开助手，退出桌面端后点“停止桌面端保护”即可清理规则。', parent=self.root):
                return
            try:
                self._desktop_runtime.abandon()
            except Exception:
                pass
        if self._monitor_runtime is None:
            self.root.destroy()
            return
        self._managed_closing = True
        if (self._managed_phase in ('idle', 'alarm', 'blocked')
                and self._managed_cleanup in ('confirmed', 'not_applicable')):
            self._managed_closed = True
            self.root.destroy()
        else:
            self._request_managed_stop()
            self.refresh()

    def _poll_managed(self):
        if self._managed_closed:
            return False
        try:
            view = self._monitor_runtime.current()
            if view.request_id != self._managed_request_id:
                return False  # A completed older request cannot change the new UI.
            self._managed_adapter.observe(view, self._monitor_config, self._managed_request_id)
            detail = present_manager_diagnostic(getattr(view, 'manager_diagnostic', None))
            if detail is not None and (self._managed_diagnostic is None or not self._managed_diagnostic.failed):
                self._managed_diagnostic = detail
                if detail.failed:
                    # R31: a sample cancelled by a stop is not the cause of that stop.
                    title, note = (('管理器采样被停止打断（界面记录时间，不是故障）：', '监测停止后中断的采样，本身不代表故障')
                                   if detail.interrupted else
                                   ('管理器首次异常（界面记录时间）：', '诊断记录；断连效果待真实验收'))
                    self._monitor_events.append((datetime.now().astimezone(),
                        title + '\n' + '\n'.join(detail.report_lines()), note))
                    self._monitor_events = self._monitor_events[-100:]
                    self.history_text.set(f'本次运行：{len(self.history)} 次检测，{len(self._monitor_events)} 条监测事件；关闭后不保留。')
            self._managed_view = view
            self._managed_cleanup = view.cleanup_status
            if self._managed_stop_requested:
                self._monitor_view = self._relay_view = None
                if view.phase in ('idle', 'alarm', 'blocked') and view.cleanup_status == 'confirmed':
                    self._managed_phase = view.phase
                    self._monitor_session = None
                    self._monitor_state = 'stopped'
                elif view.cleanup_status == 'unknown':
                    self._managed_phase = 'blocked'
                    self._managed_error = 'cleanup_unconfirmed'
                else:
                    self._managed_phase = 'stopping'
            else:
                self._managed_phase = view.phase
                if view.phase == 'running':
                    evidence = self._managed_adapter.current()
                    if evidence is None:
                        raise ValueError('生产证据未确认')
                    if self._monitor_binding_key is not None and evidence.key != self._monitor_binding_key:
                        raise ValueError('生产身份已变化')
                    from .adapters import to_core_config
                    session = self._managed_adapter.session_for(to_core_config(self._monitor_config), evidence,
                        relay_max_lease_seconds=view.sampling_budget.relay_max_lease_seconds)
                    if self._monitor_session is not None and session is not self._monitor_session:
                        raise ValueError('同一请求不能替换监测会话')
                    self._monitor_session, self._monitor_binding_key = session, evidence.key
                    self._monitor_latched = False
                    self._accept_monitor_snapshot(session.snapshot())
                    if self._monitor_state == 'alarm' or self._monitor_latched:
                        self._managed_failure('binding_unconfirmed')
                else:
                    self._monitor_view = None
                    if view.phase in ('idle', 'alarm', 'blocked'):
                        self._monitor_state = 'stopped'
                        self._monitor_latched = view.phase != 'idle'
                self._relay_view = (present_relay_snapshot(view.relay_snapshot)
                                    if view.relay_snapshot is not None else None)
            reason = self._managed_error or view.reason_code
            summary = runtime_summary(self._managed_phase, reason)
            if self._managed_diagnostic is not None:
                summary += '；管理器诊断：' + self._managed_diagnostic.summary
            self.monitor_summary.set(summary)
            if (self._managed_closing and self._managed_phase in ('idle', 'alarm', 'blocked')
                    and self._managed_cleanup == 'confirmed'):
                self._managed_closed = True
                self.root.destroy()
                return False
        except Exception:
            self._managed_failure('binding_unconfirmed')
        return True

    def select_monitor_target(self, selection):
        from src.browser.inspection import BrowserSelection
        if self.busy or (not self._managed_can_select() if self._monitor_runtime is not None
                         else self._monitor_session is not None):
            return False
        try:
            if not isinstance(selection, BrowserSelection):
                return False
            candidate = replace(self.config, url=selection.url, chrome_path=selection.chrome_executable,
                                user_data_dir=selection.user_data_dir, chrome_profile=selection.profile_directory)
            candidate.validate_browser()
            normalize = lambda value: ntpath.normcase(ntpath.normpath(value))
            if self.config.chrome_path and normalize(candidate.chrome_path) == normalize(self.config.chrome_path):
                return False
            if self.config.user_data_dir:
                old, new = normalize(self.config.user_data_dir), normalize(candidate.user_data_dir)
                try:
                    if ntpath.commonpath((old, new)) in (old, new):
                        return False
                except ValueError:
                    pass  # Different drives cannot share the saved user-data directory.
        except (TypeError, ValueError, AttributeError):
            return False
        self._monitor_config, self._monitor_selection = candidate, selection
        if self._monitor_runtime is not None:
            self._monitor_session = self._monitor_binding_key = None
        self.monitor_target_text.set('本次目标已选择（仅内存）：' + selection.profile_directory + '；身份和代理仍待核验。')
        self.refresh()
        return True

    def choose_monitor_target(self):
        executable = filedialog.askopenfilename(parent=self.root, title='选择独立专用 Chrome 程序',
                                               filetypes=[('Chrome 程序', 'chrome.exe')])
        if not executable:
            return
        directory = filedialog.askdirectory(parent=self.root, title='选择本次专用数据目录（不能使用原目录）')
        if not directory:
            return
        profile = simpledialog.askstring('本次专用配置', '该目录下的 Profile 名称：', initialvalue='Default', parent=self.root)
        if profile is None:
            return
        from src.browser.inspection import BrowserSelection
        if not self.select_monitor_target(BrowserSelection(self.config.url, executable, directory, profile.strip())):
            messagebox.showwarning('本次目标未选择', '请先核对代理配置，并选择与原程序、原数据目录隔离的专用 Chrome。运行中请先停止并等待清理。', parent=self.root)

    def _on_destroy(self, event):
        if event.widget is self.root and self._poll_id is not None:
            if self._monitor_runtime is not None:
                if not self._managed_closed and self._managed_cleanup not in ('confirmed', 'not_applicable'):
                    self._request_managed_stop()
            elif self._monitor_session is not None:
                try:
                    self._monitor_session.stop()
                except Exception:
                    pass
                self._monitor_session = None
            self.root.after_cancel(self._poll_id)
            self._poll_id = None

    def _put_config(self, config):
        for key, var in self.fields.items():
            value = getattr(config, key)
            if key == 'mapping_mode':
                value = MAPPING_LABELS.get(value, MAPPING_LABELS['unknown'])
            var.set('' if key in ('port', 'manager_port') and value == 0 else str(value))

    def _monitor_fault(self, text):
        self._monitor_view = None
        self._monitor_error = text
        self._monitor_state = 'error'
        self._monitor_latched = True
        self._monitor_resume_pending = False
        prefix = '单轮诊断：' if self._monitor_max_samples == 1 else '专用浏览器监测：'
        self.monitor_summary.set(prefix + '未确认（' + text + '） · 阻断效果：未确认')

    def _accept_monitor_snapshot(self, snapshot):
        view = present_snapshot(snapshot, previous_sequence=self._monitor_sequence)
        if self._monitor_binding_provider is not None and view.scope != 'dedicated_browser':
            raise ValueError('monitor scope unconfirmed')
        state, protection = snapshot.state, snapshot.protection
        checked, last = view.checked_at, view.last_success_at
        reasons, sequence = snapshot.reason_codes, view.sequence
        if state == 'monitoring' and not view.evidence_current:
            raise ValueError('monitoring evidence unconfirmed')
        before = (self._monitor_state, self._monitor_protection, self._monitor_checked_at,
                  self._monitor_last_success_at, self._monitor_reasons, self._monitor_latched,
                  self._monitor_sequence, len(self._monitor_events), self._monitor_error, self._monitor_view)
        self._monitor_view = view
        self._monitor_state, self._monitor_protection = state, protection
        self._monitor_checked_at, self._monitor_last_success_at = checked, last
        self._monitor_reasons = view.reason_labels
        self._monitor_sequence = sequence
        self._monitor_error = ''
        if any(event.sequence > self._monitor_event_cursor and event.action_code == 'alert_only'
               for event in snapshot.events):
            self._monitor_latched = True
        for event in view.events:
            when, event_seq = event.occurred_at, event.sequence
            if event_seq <= self._monitor_event_cursor:
                continue
            self._monitor_event_cursor = event_seq
            self._monitor_events.append((when, event.reason_label, event.action_label))
            self._monitor_events = self._monitor_events[-100:]
        if hasattr(self, 'history_text'):
            self.history_text.set(f'本次运行：{len(self.history)} 次检测，{len(self._monitor_events)} 条监测事件；关闭后不保留。')
        if state == 'alarm' or (state == 'stopped' and reasons):
            self._monitor_latched = True
            self._monitor_resume_pending = False
        if state == 'stopped':
            self._monitor_resume_pending = False
        if self._monitor_resume_pending and state == 'monitoring' and sequence > self._monitor_resume_sequence:
            try:
                fresh = last is not None and (self._monitor_resume_baseline is None or last > self._monitor_resume_baseline)
            except TypeError:
                fresh = False
            if fresh:
                self._monitor_latched = False
                self._monitor_resume_pending = False
        if self._monitor_latched:
            prefix = '发现异常，阻断未启用；' if protection == 'not_enabled' else '发现异常，阻断效果未确认；'
            status = prefix + ('异常锁存，手动复检中' if self._monitor_resume_pending else '异常锁存，需手动复检恢复')
        else:
            status = {'stopped': '已停止', 'checking': '正在检测', 'monitoring': '正在监测', 'alarm': '异常'}[state]
        protection_text = '未启用' if protection == 'not_enabled' else '未确认'
        scope_text = '专用浏览器监测：' if view.scope == 'dedicated_browser' else '独立代理检测：'
        if self._monitor_max_samples == 1:
            status = {'stopped': '已停止，单轮额度不重置', 'checking': '正在诊断，最多采样一次',
                      'monitoring': '本次采样完成，不再采样',
                      'alarm': '本次诊断异常，不自动重试'}[state]
            if state == 'alarm' and last is not None:
                status = '本次诊断证据失效，不自动重试'
            self.monitor_summary.set('单轮诊断：' + status + ' · 阻断保护：' + protection_text)
        else:
            self.monitor_summary.set(scope_text + status + ' · 阻断保护：' + protection_text)
        after = (self._monitor_state, self._monitor_protection, self._monitor_checked_at,
                 self._monitor_last_success_at, self._monitor_reasons, self._monitor_latched,
                 self._monitor_sequence, len(self._monitor_events), self._monitor_error, self._monitor_view)
        return before != after

    def _poll_monitor(self):
        if self._monitor_runtime is not None:
            return self._poll_managed()
        relay_changed = self._poll_relay()
        if self._monitor_session is None or self._monitor_invalid:
            return relay_changed
        if self._monitor_binding_provider is not None and not self._monitor_browser_bound():
            self._binding_lost()
            return True
        try:
            return self._accept_monitor_snapshot(self._monitor_session.snapshot()) or relay_changed
        except Exception:
            if not self._monitor_error:
                self._monitor_fault('核心监测接口不可用或不匹配')
                return True
            return relay_changed

    def _poll_relay(self):
        before = (self._relay_view, self._relay_error)
        self._relay_view, self._relay_error = None, False
        if (self._monitor_relay_snapshot is not None and self._monitor_session is not None and
                not self._monitor_invalid and self._monitor_browser_bound()):
            try:
                self._relay_view = present_relay_snapshot(self._monitor_relay_snapshot(self._monitor_binding_key))
            except Exception:
                self._relay_error = True
        return before != (self._relay_view, self._relay_error)

    def _retire_monitor(self):
        if self._monitor_runtime is not None:
            if self._managed_phase in ('preparing', 'running', 'stopping') or self._managed_cleanup == 'pending':
                self._request_managed_stop()
            self._monitor_config = self._monitor_selection = None
            self.monitor_target_text.set('配置已变化，请清理后重新选择本次专用 Chrome。')
            return
        if self._monitor_session is None:
            return
        session = self._monitor_session
        snapshot_error = False
        try:
            self._accept_monitor_snapshot(session.snapshot())
        except Exception:
            snapshot_error = True
        try:
            session.stop()
        except Exception:
            self._monitor_invalid = True
            self._monitor_fault('配置变化后监测停止未确认')
            return
        try:
            self._accept_monitor_snapshot(session.snapshot())
        except Exception:
            snapshot_error = True
        self._monitor_session = None
        self._monitor_binding_key = None
        self._monitor_view = None
        self._monitor_state = 'stopped'
        self._monitor_checked_at = self._monitor_last_success_at = None
        self._monitor_reasons = ()
        self._monitor_sequence = self._monitor_event_cursor = 0
        if snapshot_error:
            self._monitor_fault('核心监测接口不匹配；旧会话已停止')
            return
        status = '配置已变化，监测已停止；异常仍需手动复检' if self._monitor_latched else '配置已变化，监测已停止'
        self.monitor_summary.set('专用浏览器监测：' + status + ' · 阻断保护：未启用')
        if self._monitor_max_samples == 1:
            self.monitor_summary.set('单轮诊断：配置已变化，会话已停止；额度不重置 · 阻断保护：未确认')

    def _binding_evidence(self):
        # 提供者只返回已缓存快照，不得在 Tk 线程做 I/O。
        if self._monitor_binding_provider is None:
            return None
        try:
            evidence = self._monitor_binding_provider.current()
            config = self._monitor_config if self._monitor_runtime is not None else self.config
            if isinstance(evidence, BindingEvidence) and evidence.valid_for(config, self.clock()):
                return evidence
        except Exception:
            pass
        return None

    def _monitor_browser_bound(self):
        try:
            evidence = self._binding_evidence()
            return evidence is not None and (self._monitor_session is None or
                   evidence.key == self._monitor_binding_key == getattr(self._monitor_session, 'binding_key', None))
        except Exception:
            return False

    def _binding_lost(self):
        if self._monitor_runtime is not None:
            self._managed_failure('binding_unconfirmed')
            return
        self._monitor_view = None
        session = self._monitor_session
        self._monitor_latched = True
        self._monitor_resume_pending = False
        try:
            session.stop()
        except Exception:
            self._monitor_invalid = True
            self._monitor_fault('专用浏览器绑定失效，监测停止未确认')
            return
        self._monitor_session = None
        self._monitor_binding_key = None
        self._monitor_state = 'stopped'
        self._monitor_checked_at = self._monitor_last_success_at = None
        self._monitor_reasons = ()
        self._monitor_sequence = self._monitor_event_cursor = 0
        self.monitor_summary.set('专用浏览器身份或代理绑定已失效；监测已停止，异常须手动复检 · 阻断保护：未启用')
        if self._monitor_max_samples == 1:
            self.monitor_summary.set('单轮诊断：绑定失效，会话已停止；不自动重试 · 阻断保护：未确认')

    def _abort_monitor(self, text):
        if self._monitor_runtime is not None:
            self._managed_failure('runtime_unavailable')
            return
        if self._monitor_session is not None:
            try:
                self._monitor_session.stop()
            except Exception:
                self._monitor_invalid = True
                self._monitor_fault(text + '；监测停止未确认')
                return
            self._monitor_session = None
            self._monitor_binding_key = None
        self._monitor_fault(text)

    def start_monitor(self):
        if self._monitor_runtime is not None:
            self._start_managed()
            return
        if self._monitor_max_samples == 1 and self._diagnostic_started:
            self.refresh()
            return
        if not self._monitor_browser_bound():
            prefix = '单轮诊断：' if self._monitor_max_samples == 1 else '持续监测：'
            self.monitor_summary.set(prefix + '专用浏览器身份未确认，未启动 · 阻断保护：未启用')
            self.refresh()
            return
        if self.busy or not self.saved or self._monitor_invalid:
            return
        try:
            if self._monitor_session is None:
                from .adapters import to_core_config
                if self._monitor_binding_provider is None:
                    self._monitor_session = self._monitor_factory(to_core_config(replace(self.config)))
                else:
                    binding = self._binding_evidence()
                    if binding is None:
                        raise ValueError('浏览器绑定已失效')
                    options = ({'relay_max_lease_seconds': self._relay_max_lease}
                               if self._monitor_relay_snapshot is not None else {})
                    if self._monitor_max_samples == 1:
                        options['max_samples'] = 1
                    session = self._monitor_factory(to_core_config(replace(self.config)), binding, **options)
                    self._monitor_session = session
                    sample_limit = getattr(session, 'relay_sample_limit', None)
                    if ((self._monitor_max_samples is None and sample_limit is not None) or
                            (self._monitor_max_samples == 1 and (type(sample_limit) is not int or sample_limit != 1))):
                        raise ValueError('会话采样额度与界面模式不一致')
                    self._monitor_binding_key = binding.key
                    if not self._monitor_browser_bound():
                        self._binding_lost()
                        self.refresh()
                        return
                self._monitor_sequence = self._monitor_event_cursor = 0
            if self._monitor_max_samples == 1:
                self._diagnostic_started = True
            self._monitor_session.start()
            if self._monitor_binding_provider is not None and not self._monitor_browser_bound():
                self._binding_lost()
                self.refresh()
                return
            self._accept_monitor_snapshot(self._monitor_session.snapshot())
        except Exception:
            self._abort_monitor('核心监测接口不可用或不匹配')
        self.refresh()

    def attach_completed_diagnostic(self, session):
        """Adopt a completed coordinator-owned sample on the Tk thread; never start it."""
        from src.core.monitoring import MonitorSession
        from .adapters import to_core_config
        if (self._monitor_max_samples != 1 or self.busy or not self.saved or self._monitor_invalid or
                self._diagnostic_started or self._monitor_session is not None):
            return False
        try:
            binding = self._binding_evidence()
            if (binding is None or not isinstance(session, MonitorSession) or
                    type(session.relay_sample_limit) is not int or session.relay_sample_limit != 1 or
                    session.binding_key != binding.key):
                return False
            selected = session.relay_binding
            if (session.relay_config != to_core_config(self.config) or
                    ntpath.normcase(ntpath.normpath(selected.executable)) !=
                    ntpath.normcase(ntpath.normpath(self.config.chrome_path)) or
                    ntpath.normcase(ntpath.normpath(selected.user_data_dir)) !=
                    ntpath.normcase(ntpath.normpath(self.config.user_data_dir)) or
                    selected.profile_directory != self.config.chrome_profile):
                return False
            snapshot = session.snapshot()
            view = present_snapshot(snapshot)
            if snapshot.state != 'monitoring' or view.scope != 'dedicated_browser' or not view.evidence_current:
                return False
            # 读快照期间绑定可能失效，挂接前再次核对。
            current = self._binding_evidence()
            if current is None or current.key != binding.key:
                return False
        except Exception:
            return False
        self._diagnostic_started = True
        self._monitor_session, self._monitor_binding_key = session, binding.key
        self._monitor_sequence = self._monitor_event_cursor = 0
        self._accept_monitor_snapshot(snapshot)
        self._poll_relay()
        self.refresh()
        return True

    def stop_monitor(self):
        if self._monitor_runtime is not None:
            if self._managed_phase in ('preparing', 'running', 'alarm') or self._managed_cleanup == 'pending':
                self._request_managed_stop()
            self.refresh()
            return
        if self._monitor_session is None:
            return
        snapshot_error = False
        if not self._monitor_invalid:
            try:
                self._accept_monitor_snapshot(self._monitor_session.snapshot())
            except Exception:
                snapshot_error = True
        try:
            self._monitor_session.stop()
            if self._monitor_invalid:
                self._monitor_session = None
                self._monitor_invalid = False
                self._monitor_state = 'stopped'
                self.monitor_summary.set('专用浏览器监测：已停止；异常仍需手动复检 · 阻断保护：未启用')
                if self._monitor_max_samples == 1:
                    self.monitor_summary.set('单轮诊断：已停止，额度不重置 · 阻断保护：未确认')
            else:
                try:
                    self._accept_monitor_snapshot(self._monitor_session.snapshot())
                except Exception:
                    snapshot_error = True
            if snapshot_error:
                self._monitor_fault('核心监测接口不匹配；监测已停止')
        except Exception:
            self._monitor_invalid = True
            self._monitor_fault('监测停止未确认')
        self.refresh()

    def resume_monitor(self):
        if self._monitor_runtime is not None:
            self._start_managed(resume=True)
            return
        if self._monitor_max_samples == 1:
            return
        if not self._monitor_browser_bound() or self.busy or not self.saved or not self._monitor_latched or self._monitor_session is None or self._monitor_invalid:
            return
        try:
            session = self._monitor_session
            before = session.snapshot()
            self._accept_monitor_snapshot(before)
            self._monitor_resume_baseline = before.last_success_at
            self._monitor_resume_sequence = before.sequence
            self._monitor_resume_pending = True
            session.resume()
            if self._monitor_binding_provider is not None and not self._monitor_browser_bound():
                self._binding_lost()
                self.refresh()
                return
            after = session.snapshot()
            if after.state == before.state and before.state in ('stopped', 'checking', 'monitoring'):
                session.stop()
                session.start()
                if self._monitor_binding_provider is not None and not self._monitor_browser_bound():
                    self._binding_lost()
                    self.refresh()
                    return
                after = session.snapshot()
            self._accept_monitor_snapshot(after)
        except Exception:
            self._abort_monitor('手动复检未能开始')
        self.refresh()

    def _monitor_allows_launch(self):
        if self._monitor_relay_snapshot is not None or self._monitor_max_samples == 1:
            return False  # 仅准备快照展示；真实保护证据审查后另行接通测试入口。
        if not self._monitor_browser_bound() or self._monitor_latched or self._monitor_error or self._monitor_invalid:
            return False
        return self._monitor_session is None or self._monitor_state in ('stopped', 'monitoring')

    def _monitor_worker_allows_launch(self, session):
        if self._monitor_relay_snapshot is not None or self._monitor_max_samples == 1:
            return False
        if (not self._monitor_browser_bound() or self._monitor_session is not session or self._monitor_latched or
                self._monitor_error or self._monitor_invalid):
            return False
        if session is None:
            return True
        try:
            snapshot = session.snapshot()
            view = present_snapshot(snapshot, previous_sequence=self._monitor_sequence)
            if self._monitor_binding_provider is not None and view.scope != 'dedicated_browser':
                return False
            if (snapshot.state not in ('stopped', 'monitoring') or snapshot.reason_codes or
                    (snapshot.state == 'monitoring' and not view.evidence_current)):
                return False
            for event in snapshot.events:
                if event.sequence > self._monitor_event_cursor and event.action_code == 'alert_only':
                    return False
            return not (self._monitor_latched or self._monitor_error or self._monitor_invalid)
        except Exception:
            return False

    @staticmethod
    def _monitor_time(value):
        return value.astimezone().strftime('%Y-%m-%d %H:%M:%S %z') if isinstance(value, datetime) else '未确认'

    def _record_launch(self, target, text):
        self._last_launch = (datetime.now().astimezone(), target, text)

    def _record_lines(self):
        # P2: a record only; it never feeds can_start_* or the 60-second evidence window.
        lines = ['最近一次检测与启动记录（只是记录，不能作为启动依据；关闭助手后不保留）：']
        if self._last_detection is None:
            lines.append('最近一次检测：本次运行暂无')
        else:
            when, started, text = self._last_detection
            if started is not None:
                text += ' · ' + ('当前仍有效' if self._evidence_started == started and self._fresh() else '当前已过期')
            lines.append('最近一次检测：' + self._monitor_time(when) + ' · ' + text)
        if self._last_launch is None:
            lines.append('最近一次启动：本次运行暂无')
        else:
            when, target, text = self._last_launch
            lines.append('最近一次启动：' + self._monitor_time(when) + ' · ' + target + ' · ' + text)
        return lines

    def _render_report(self, include_full_ip=False):
        view = self._monitor_view
        lines = [render_report(self.result, self.config, include_full_ip), '', *self._record_lines(), '', self.monitor_summary.get(),
                 '监测对象：用户选中的专用浏览器；独立代理请求不证明其身份或实际代理。',
                 '监测范围：' + (view.scope_label if view else '未确认'),
                 '浏览器本次绑定：' + (view.browser_status_label if view and not self._monitor_latched else '未确认'),
                 '监测最近检测：' + self._monitor_time(self._monitor_checked_at),
                 '监测最近成功：' + self._monitor_time(self._monitor_last_success_at)]
        validity = ('已过期' if any('已过期' in reason for reason in self._monitor_reasons) else
                    view.evidence_label if view and not self._monitor_latched and not self._monitor_error else '未确认')
        lines.append('监测证据：' + validity)
        if self._monitor_max_samples == 1:
            lines.append('采样模式：单轮诊断，最多一次；不持续采样、不自动重试。')
        if self._relay_view is not None and (self._monitor_runtime is not None or
                (self._monitor_session is not None and self._monitor_browser_bound())):
            lines.extend(self._relay_view.report_lines())
        else:
            lines.extend(('专用转发快照：' + ('转发快照不可用' if self._relay_error else '未接入或当前绑定未确认'),
                          '专用浏览器系统与路由保护：未确认'))
        for reason in self._monitor_reasons:
            lines.append('监测原因：' + reason)
        if self._monitor_latched:
            lines.append('异常已提示；单轮诊断不重试，断连效果未确认。' if self._monitor_max_samples == 1 else
                         '异常已提示；未确认已断开专用浏览器的连接，须手动复检恢复。')
        if self._monitor_events:
            lines.append('监测事件（本次运行，最多 100 条）：')
            lines.extend(self._monitor_time(when) + ' · ' + reason + ' · ' + action for when, reason, action in self._monitor_events)
        if self._monitor_runtime is not None:
            lines.append(self.monitor_target_text.get())
            lines.extend(runtime_report_lines(self._managed_view, self.clock()))
            if self._managed_diagnostic is not None:
                lines.extend(self._managed_diagnostic.report_lines())
            else:
                lines.append('管理器采样诊断：暂无记录')
        if self._desktop_runtime is not None:
            lines.extend(desktop_report_lines(self._desktop_view, self.clock(), self._monitor_time))
        return '\n'.join(lines)

    def _invalidate(self, *_):
        self._retire_monitor()
        previous = self._candidate_previous
        self._candidate_previous = None
        self._candidate_recheck = None
        if previous is not None:
            self.fields['manager_executable'].set(previous[0])
            self.fields['manager_sha256'].set(previous[1])
            self.trust_status.set('配置已变化，未保存的候选已撤销；请重新核验。')
        self.saved = False
        self._generation += 1
        self._evidence_started = None
        self.result = Result()
        if hasattr(self, 'report'):
            self.refresh()

    def save_settings(self):
        if self.busy:
            return False
        try:
            values = {k: int(v.get()) if k in ('port', 'manager_port') else v.get().strip() for k, v in self.fields.items()}
            values['mapping_mode'] = next((key for key, label in MAPPING_LABELS.items() if label == values['mapping_mode']), 'unknown')
            config = Config(**values)
            config.validate()
        except (ValueError, OSError) as exc:
            messagebox.showerror('配置未保存', str(exc) if isinstance(exc, ValueError) and not str(exc).startswith('invalid literal') else '请检查输入与配置文件写入权限。', parent=self.root)
            return False
        if self._candidate_previous is not None and self._candidate_recheck is not None:
            self._pending_save_config = config
            self._generation += 1
            self.trust_status.set('正在保存前重新核验所选安装来源，请稍候。')
            self._start_worker('save_trust', self._generation, self.clock(), self._candidate_recheck)
            return True
        try:
            save_config(self.config_path, config)
        except OSError:
            messagebox.showerror('配置未保存', '无法保存配置，请检查写入权限。', parent=self.root)
            return False
        self._saved_config(config)
        return True

    def _saved_config(self, config):
        self.config = config
        self.saved = True
        self._candidate_previous = None
        self._candidate_recheck = None
        if config.manager_executable and config.manager_sha256:
            self.trust_status.set('已保存管理器基准；当前监听和程序是否匹配仍待检测。')
        self._generation += 1
        self._evidence_started = None
        self.result = Result()
        self.refresh()
        messagebox.showinfo('配置已保存', '已保存本机配置，请重新检测。', parent=self.root)

    def _select_desktop(self, _event=None):
        index = self.desktop_choice.current()
        self._selected_app = self._applications[index] if 0 <= index < len(self._applications) else None
        self._generation += 1
        self._evidence_started = None
        self.result = Result()
        self.refresh()

    def _fresh(self):
        return self._evidence_started is not None and 0 <= self.clock() - self._evidence_started < 60

    def _start_worker(self, operation, token, started, work):
        self.busy = True
        self._operation = operation
        self.refresh()
        def run():
            try:
                if operation == 'launch' and not (0 <= self.clock() - started < 60):
                    raise ValueError('expired')
                value = work()
                self._queue.put((operation, token, started, True, value))
            except Exception:
                self._queue.put((operation, token, started, False, None))
        threading.Thread(target=run, daemon=True).start()

    def detect(self):
        if self.busy:
            return
        if not self.saved:
            messagebox.showwarning('尚未保存配置', '请先填写并保存配置，再进行检测。', parent=self.root)
            return
        self._generation += 1
        token = self._generation
        self._evidence_started = None
        self.result = Result()
        config = replace(self.config)
        app_id = self._selected_app
        started = self.clock()
        self._start_worker('detect', token, started, lambda: self.backend.detect(config, app_id))

    def find_desktop(self):
        if self.busy:
            return
        discover = getattr(self.backend, 'discover_desktop', None)
        if not callable(discover):
            self.desktop_lookup.set('未发现或未确认')
            return
        self._generation += 1
        self._evidence_started = None
        self.result = Result()
        self.desktop_lookup.set('正在查找')
        self._start_worker('discover', self._generation, self.clock(), discover)

    def _poll(self):
        try:
            while True:
                operation, token, started, ok, value = self._queue.get_nowait()
                self.busy = False
                self._operation = ''
                valid = token == self._generation and self.saved
                if operation == 'discover':
                    if token == self._generation:
                        applications = value if ok and isinstance(value, (tuple, list)) else ()
                        self._applications = tuple(dict.fromkeys(app for app in applications if isinstance(app, str) and re.fullmatch(r'[A-Za-z0-9._!+-]{1,256}', app)))
                        self.desktop_choice['values'] = self._applications
                        if self._selected_app in self._applications:
                            self.desktop_choice.current(self._applications.index(self._selected_app))
                        else:
                            self._selected_app = None
                            self.desktop_choice.set('')
                        self.desktop_lookup.set('请选择' if self._applications else '未发现或未确认')
                    else:
                        self.desktop_lookup.set('配置已变，请重新查找')
                elif operation == 'detect' and valid:
                    if ok and isinstance(value, Probe) and isinstance(value.result, Result) and 0 <= self.clock() - started < 60:
                        self._applications = tuple(dict.fromkeys(app for app in value.applications if isinstance(app, str) and re.fullmatch(r'[A-Za-z0-9._!+-]{1,256}', app)))
                        self.desktop_choice['values'] = self._applications
                        self.desktop_lookup.set('请选择' if self._applications else '未发现或未确认')
                        if self._selected_app in self._applications:
                            self.desktop_choice.current(self._applications.index(self._selected_app))
                        else:
                            self._selected_app = None
                            self.desktop_choice.set('')
                        owner = value.result.owner if self.config.manager_executable and self.config.manager_sha256 else Status.UNKNOWN
                        self.result = replace(value.result, mapping_mode=self.config.mapping_mode, owner=owner)
                        self._evidence_started = started
                        checked = self.result.checked_at if isinstance(self.result.checked_at, datetime) else datetime.now().astimezone()
                        self._last_detection = (checked, started, '共同检测：' + self.result.common_status.value
                                                + ' · 桌面启动前条件：' + self.result.desktop.value
                                                + ' · 网页端：' + self.result.browser_status.value)
                        self.history.insert(0, self._render_report())
                        self.history = self.history[:10]
                        self.history_text.set(f'本次运行历史：{len(self.history)} 次；关闭程序后不保留。')
                    else:
                        self.result = Result()
                        self._evidence_started = None
                        late = ok and isinstance(value, Probe) and isinstance(value.result, Result)
                        self._last_detection = (datetime.now().astimezone(), None, '检测结果超时未采用' if late else '检测未能完成')
                        if not ok:
                            messagebox.showerror('检测未确认', '检测未能完成；请检查后端和代理环境后重试。', parent=self.root)
                elif operation == 'launch':
                    from src.core.backend import LaunchResult
                    known = ok and isinstance(value, LaunchResult)
                    has_pid = known and type(value.pid) is int and value.pid > 0
                    monitor_blocked = ok and value is _BROWSER_MONITOR_BLOCKED
                    if not monitor_blocked:
                        self.result = Result()
                        self._evidence_started = None
                    if known and value.status == 'fail' and value.pid is None:
                        self._record_launch(self._launch_target, '未能启动（启动前检查或启动未通过）')
                        messagebox.showerror('未能启动', '启动前检查或启动未通过；请重新检测并检查相关程序状态。', parent=self.root)
                    elif known and value.status == 'unknown' and value.pid is None and value.message == '启动前代理监听归属发生变化或无法确认':
                        self._record_launch(self._launch_target, '已阻止启动（启动前代理监听归属变化或无法确认）')
                        messagebox.showinfo('启动已阻止', '启动前代理监听归属发生变化或无法确认，已阻止启动；请重新检测。', parent=self.root)
                    elif monitor_blocked:
                        self._record_launch(self._launch_target, '已阻止网页启动（专用浏览器监测异常或状态未确认）')
                        self._monitor_latched = True
                        self.monitor_summary.set('专用浏览器监测：异常或状态未确认，需手动复检恢复 · 阻断效果：未确认')
                        messagebox.showinfo('启动已阻止', '专用浏览器监测异常或状态未确认，已阻止本次网页启动；请检查并手动复检。', parent=self.root)
                    elif known and value.status == 'unknown' and has_pid:
                        self._record_launch(self._launch_target, '已发起应用激活；实际出口和代理参数是否生效尚未确认')
                        messagebox.showinfo('启动结果未确认', '已发起应用激活；应用实际出口和代理参数是否生效尚未确认。', parent=self.root)
                    elif known and value.status == 'pass' and has_pid:
                        self._record_launch(self._launch_target, '应用激活请求已成功返回；实际出口和代理参数是否生效仍需确认')
                        messagebox.showinfo('启动请求已处理', '应用激活请求已成功返回；实际出口和代理参数是否生效仍需确认。', parent=self.root)
                    else:
                        self._record_launch(self._launch_target, '无法确认应用是否已启动')
                        messagebox.showinfo('启动状态未确认', '无法确认应用是否已启动；请先检查应用状态，再重新检测。', parent=self.root)
                elif operation == 'save_trust':
                    config = self._pending_save_config
                    self._pending_save_config = None
                    if token == self._generation and self._candidate_previous is not None:
                        if ok and value is True and config is not None:
                            try:
                                save_config(self.config_path, config)
                            except OSError:
                                self.trust_status.set('配置未保存，请检查写入权限。')
                                messagebox.showerror('配置未保存', '无法保存配置，请检查写入权限。', parent=self.root)
                            else:
                                self._saved_config(config)
                        else:
                            self._invalidate()
                            self.trust_status.set('保存前核验未通过，候选已撤销；原配置未改变。')
                            messagebox.showerror('配置未保存', '安装来源或监听状态未确认，请重新核验。', parent=self.root)
                self.refresh()
        except queue.Empty:
            pass
        if self._poll_monitor():
            self.refresh()
        if self._poll_desktop():
            self.refresh()
        if self._managed_closed:
            return
        if self._evidence_started is not None and not self._fresh():
            self._evidence_started = None
            self.result = Result()
            self.refresh()
        self._poll_id = self.root.after(50, self._poll)

    def _launch(self, desktop):
        if not desktop:
            self._poll_monitor()
        if self.busy or not self.saved or not self._fresh():
            self._evidence_started = None
            self.result = Result()
            self.refresh()
            return
        if not desktop and not self._monitor_allows_launch():
            self.refresh()
            return
        if desktop:
            if not self.result.can_start_desktop or self._selected_app not in self._applications:
                return
            config, app_id = replace(self.config), self._selected_app
            work = lambda: self.backend.launch_desktop(config, app_id)
        else:
            if not self.result.can_start_browser:
                return
            config = replace(self.config)
            work = lambda: self.backend.launch_browser(config)
        started = self._evidence_started
        self._launch_target = '桌面端（普通启动）' if desktop else '网页端（普通启动）'
        self._generation += 1
        monitor_session = self._monitor_session
        def guarded_work():
            if not desktop and not self._monitor_worker_allows_launch(monitor_session):
                return _BROWSER_MONITOR_BLOCKED
            return work()
        self._start_worker('launch', self._generation, started, guarded_work)

    def launch_desktop(self):
        self._launch(True)

    def launch_browser(self):
        self._launch(False)

    def refresh(self):
        if self._managed_closed:
            return
        def text(value):
            return value.value if isinstance(value, Status) else Status.UNKNOWN.value
        self.summary.set(f'启动前共同检测：{text(self.result.common_status)} · 桌面启动前条件：{text(self.result.desktop)} · 网页端：{text(self.result.browser_status)}')
        fresh = self._fresh()
        monitor_allows = self._monitor_allows_launch()
        self.desktop_button.configure(state='normal' if self.saved and not self.busy and fresh and self.result.can_start_desktop and self._selected_app in self._applications else 'disabled')
        self.browser_button.configure(state='normal' if self.saved and not self.busy and fresh and monitor_allows and self.result.can_start_browser else 'disabled')
        can_start_monitor = self._monitor_browser_bound() and self.saved and not self.busy and not self._monitor_invalid and (self._monitor_session is None or (self._monitor_state == 'stopped' and not self._monitor_latched))
        can_stop_monitor = self._monitor_session is not None and (self._monitor_state != 'stopped' or self._monitor_invalid)
        can_resume_monitor = self._monitor_browser_bound() and self.saved and not self.busy and self._monitor_session is not None and self._monitor_latched and not self._monitor_invalid
        if self._monitor_max_samples == 1:
            can_start_monitor = can_start_monitor and not self._diagnostic_started
            can_resume_monitor = False
        if self._monitor_runtime is not None:
            can_start_monitor = (self._managed_can_select() and self.saved and not self.busy
                                 and self._monitor_config is not None)
            can_stop_monitor = (not self._managed_stop_requested and
                                (self._managed_phase in ('preparing', 'running', 'alarm')
                                 or self._managed_cleanup == 'pending'))
            can_resume_monitor = (can_start_monitor and self._managed_phase == 'alarm'
                                  and self._managed_cleanup == 'confirmed' and self._monitor_binding_key is not None)
            self.start_monitor_button.configure(text='核验并开始监测')
            self.monitor_target_button.configure(state='normal' if self._managed_can_select() and not self.busy else 'disabled')
        if self._desktop_active():
            can_start_monitor = can_resume_monitor = False
            self.monitor_target_button.configure(state='disabled')
        self.start_monitor_button.configure(state='normal' if can_start_monitor else 'disabled')
        if self._desktop_runtime is not None:
            view = self._desktop_view
            self.desktop_protect_button.configure(state='normal' if self._desktop_can_start() else 'disabled')
            self.desktop_stop_button.configure(state='normal' if view is not None and view.phase in
                ('preparing', 'running', 'fused', 'desktop_exited', 'blocked') else 'disabled')
            self.desktop_resume_button.configure(state='normal' if view is not None and view.phase == 'fused'
                                                 and view.resumable else 'disabled')
        self.stop_monitor_button.configure(state='normal' if can_stop_monitor else 'disabled')
        self.resume_monitor_button.configure(state='normal' if can_resume_monitor else 'disabled')
        self.detect_button.configure(state='disabled' if self.busy else 'normal')
        self.find_desktop_button.configure(state='disabled' if self.busy else 'normal')
        self.save_button.configure(state='disabled' if self.busy else 'normal')
        self.desktop_choice.configure(state='disabled' if self._operation == 'launch' else 'readonly')
        for index, entry in enumerate(self.entries):
            entry.configure(state='disabled' if self._operation == 'launch' else ('readonly' if isinstance(entry, ttk.Combobox) or index in (2, 3) else 'normal'))
        if self._first_setup_dialog is not None and self._first_setup_dialog.window.winfo_exists():
            self._first_setup_dialog.sync_state()
        self.report.configure(state='normal')
        self.report.delete('1.0', 'end')
        self.report.insert('1.0', self._render_report(self.full_ip.get()))
        self.report.configure(state='disabled')

    def copy_report(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._render_report(self.full_ip.get()))

    def open_candidate(self):
        from .candidate import CandidateDialog
        if self._candidate_dialog is not None and self._candidate_dialog.window.winfo_exists():
            self._candidate_dialog.window.lift()
            return
        self._candidate_dialog = CandidateDialog(self.root)

    def open_port_candidates(self):
        from .onboarding import PortDialog
        if self._port_dialog is not None and self._port_dialog.window.winfo_exists():
            self._port_dialog.window.lift()
            return
        self._port_dialog = PortDialog(self)

    def open_shortcut(self):
        from .shortcut_setup import ShortcutDialog
        if self._operation == 'launch':
            return
        if self._shortcut_dialog is not None and self._shortcut_dialog.window.winfo_exists():
            self._shortcut_dialog.window.lift()
            return
        self._shortcut_dialog = ShortcutDialog(self)

    def open_guide(self):
        from .onboarding import GuideDialog
        if self._guide_dialog is not None and self._guide_dialog.window.winfo_exists():
            self._guide_dialog.window.lift()
            return
        self._guide_dialog = GuideDialog(self.root)

    def open_first_setup(self):
        from .onboarding import FirstSetupDialog
        if self._operation == 'launch':
            return
        if self._first_setup_dialog is not None and self._first_setup_dialog.window.winfo_exists():
            self._first_setup_dialog.window.lift()
            return
        self._first_setup_dialog = FirstSetupDialog(self, tuple(MAPPING_LABELS.values()))

    def open_release_setup(self):
        from .release_setup import ReleaseDialog
        if self._operation == 'launch':
            return
        if self._release_dialog is not None and self._release_dialog.window.winfo_exists():
            self._release_dialog.window.lift()
            return
        self._release_dialog = ReleaseDialog(self)

    def apply_release_candidate(self, baseline, recheck):
        if self._operation == 'launch':
            return False
        previous = self._candidate_previous or (self.fields['manager_executable'].get(), self.fields['manager_sha256'].get())
        self._candidate_previous = None
        self.fields['manager_executable'].set(baseline.manager_executable)
        self.fields['manager_sha256'].set(baseline.manager_sha256)
        self._candidate_previous = previous
        self._candidate_recheck = recheck
        self.trust_status.set('候选已填入但尚未保存；修改其他配置会撤销候选。')
        return True

    def show_history(self):
        window = tk.Toplevel(self.root)
        window.title('本次运行的检测历史（脱敏）')
        window.geometry('700x450')
        text = tk.Text(window, wrap='word')
        text.pack(fill='both', expand=True)
        history = '\n\n--------------------\n\n'.join(self.history) if self.history else '暂无启动前检测记录。'
        if self._monitor_events:
            history += '\n\n监测事件（本次运行，最多 100 条）：\n' + '\n'.join(self._monitor_time(when) + ' · ' + reason + ' · ' + action for when, reason, action in self._monitor_events)
        text.insert('1.0', history)
        text.configure(state='disabled')

    def export_report(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='导出检测报告', defaultextension='.txt', filetypes=[('文本文件', '*.txt')])
        if not path:
            return
        try:
            Path(path).write_text(self._render_report(self.full_ip.get()), encoding='utf-8')
        except OSError:
            messagebox.showerror('导出失败', '无法写入所选位置，请检查权限后重试。', parent=self.root)


def main():
    from src.protection.managed_session import ManagedSessionRuntime
    root = tk.Tk()
    App(root, backend=LiveBackend(), monitor_runtime=ManagedSessionRuntime())
    root.mainloop()


if __name__ == '__main__':
    main()
