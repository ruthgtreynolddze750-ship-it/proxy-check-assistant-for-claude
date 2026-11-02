"""Independent monitoring panel; it never modifies the existing assistant or network settings."""
import hashlib
import os
from collections import deque
from dataclasses import replace
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .adapters import to_core_config
from .model import load_config
from .monitoring_presentation import present_snapshot


def _default_session_factory(config):
    from src.core.monitoring import MonitorSession
    return MonitorSession(config)


class MonitorWindow:
    def __init__(self, root, *, config_path=None, session_factory=None, poll_interval_ms=250):
        self.root = root
        local = Path(os.environ.get('LOCALAPPDATA', str(Path.home())))
        self.config_path = Path(config_path) if config_path is not None else local / 'ClaudeLaunchCenter' / 'settings.json'
        self.session_factory = session_factory or _default_session_factory
        self.poll_interval_ms = poll_interval_ms
        self._session = None
        self._core_config = None
        self._signature = None
        self._session_signature = None
        self._view = None
        self._sequence = 0
        self._event_cursor = 0
        self._events = deque(maxlen=100)
        self._alarm_latched = False
        self._resume_pending = False
        self._resume_baseline = None
        self._resume_sequence = 0
        self._fault = ''
        self._closed = False
        self._poll_id = None
        self.config_status = tk.StringVar(value='正在检查本机配置。')
        self.status = tk.StringVar(value='持续监测：未启动，阻断未启用')
        root.title('独立持续监测（不含断连保护）')
        root.geometry('780x600')
        root.minsize(640, 480)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(3, weight=1)
        ttk.Label(root, text='独立持续监测', font=('Microsoft YaHei UI', 15, 'bold')).grid(row=0, column=0, sticky='w', padx=14, pady=(12, 3))
        ttk.Label(root, textvariable=self.config_status, wraplength=740).grid(row=1, column=0, sticky='w', padx=14)
        controls = ttk.Frame(root, padding=(14, 8))
        controls.grid(row=2, column=0, sticky='ew')
        self.start_button = ttk.Button(controls, text='开始监测', command=self.start)
        self.start_button.pack(side='left', padx=(0, 6))
        self.stop_button = ttk.Button(controls, text='停止监测', command=self.stop)
        self.stop_button.pack(side='left', padx=(0, 6))
        self.resume_button = ttk.Button(controls, text='手动复检恢复', command=self.resume)
        self.resume_button.pack(side='left')
        ttk.Label(controls, textvariable=self.status, wraplength=430).pack(side='left', padx=12)
        body = ttk.Frame(root, padding=(14, 0))
        body.grid(row=3, column=0, sticky='nsew')
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.report = tk.Text(body, wrap='word', state='disabled')
        self.report.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(body, command=self.report.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        self.report.configure(yscrollcommand=scroll.set)
        actions = ttk.Frame(root, padding=14)
        actions.grid(row=4, column=0, sticky='ew')
        self.copy_button = ttk.Button(actions, text='复制脱敏报告', command=self.copy_report)
        self.copy_button.pack(side='left')
        self.export_button = ttk.Button(actions, text='导出脱敏报告', command=self.export_report)
        self.export_button.pack(side='left', padx=8)
        ttk.Button(actions, text='关闭', command=self.close).pack(side='right')
        self._load_configuration()
        self._render()
        self._poll_id = root.after(self.poll_interval_ms, self._poll)
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.bind('<Destroy>', self._on_destroy, add='+')

    def _fingerprint(self):
        try:
            with self.config_path.open('rb') as stream:
                content = stream.read(262145)
            if len(content) > 262144:
                return None
            return hashlib.sha256(content).digest()
        except OSError:
            return None

    def _load_configuration(self):
        before = self._fingerprint()
        self._signature = before
        self._core_config = None
        try:
            if before is None:
                raise ValueError('missing')
            config = load_config(self.config_path)
            core_config = to_core_config(config)
            if (not config.manager_executable or not config.manager_sha256 or not config.expected_zone or
                    config.mapping_mode not in ('required', 'not_required') or
                    (config.mapping_mode == 'required' and not config.required_mappings()) or
                    self._fingerprint() != before):
                raise ValueError('incomplete')
        except (OSError, ValueError, TypeError):
            self.config_status.set('本机配置缺失、无效或未确认；请回旧助手核对并保存后重试。')
            return False
        self._core_config = core_config
        self.config_status.set('本机配置已读取；请核对旧助手中的独立预期和可信基准。')
        return True

    def _fail(self, text):
        self._fault = text
        self._alarm_latched = True
        self._resume_pending = False
        self.status.set('持续监测：未确认（' + text + '），阻断效果未确认')

    def _accept(self, snapshot):
        view = present_snapshot(snapshot, previous_sequence=self._sequence)
        self._sequence = view.sequence
        for event in view.events:
            if event.sequence <= self._event_cursor:
                continue
            self._event_cursor = event.sequence
            self._events.append(event)
            if event.action_label == '仅提示，未确认断连':
                self._alarm_latched = True
        if snapshot.state == 'alarm' or (snapshot.state == 'stopped' and snapshot.reason_codes):
            self._alarm_latched = True
            self._resume_pending = False
        if snapshot.state == 'monitoring' and not view.evidence_current:
            self._alarm_latched = True
            self._resume_pending = False
        if snapshot.state == 'stopped':
            self._resume_pending = False
        if self._resume_pending and snapshot.state == 'monitoring' and view.evidence_current and view.sequence > self._resume_sequence:
            try:
                fresh = self._resume_baseline is None or view.last_success_at > self._resume_baseline
            except TypeError:
                fresh = False
            if fresh:
                self._alarm_latched = False
                self._resume_pending = False
        self._view = view
        self._fault = ''
        protection = '阻断未启用' if view.protection_label == '未启用' else '阻断效果未确认'
        if self._alarm_latched:
            state = '异常锁存，手动复检中' if self._resume_pending else '发现异常，需手动复检恢复'
        else:
            state = view.state_label
        self.status.set('持续监测：' + state + '，' + protection)

    def _sample(self):
        if self._session is None:
            return
        try:
            self._accept(self._session.snapshot())
        except Exception:
            self._fail('核心监测接口不可用或不匹配')

    def _configuration_changed(self):
        if self._session is None:
            self._load_configuration()
            return
        try:
            self._accept(self._session.snapshot())
            self._session.stop()
            self._accept(self._session.snapshot())
        except Exception:
            self._fail('配置变化后旧会话停止未确认')
            self._core_config = None
            return
        self._session = None
        self._session_signature = None
        self._core_config = None
        self._signature = self._fingerprint()
        self._sequence = self._event_cursor = 0
        self._view = None
        self._resume_pending = False
        suffix = '；异常仍须手动复检恢复' if self._alarm_latched else ''
        self.status.set('配置已变化，旧会话已停止调度' + suffix + '；阻断未启用')
        self.config_status.set('配置已变化；请回旧助手核对并保存，再主动开始监测。')

    def start(self):
        if self._session is not None and (self._alarm_latched or self._view is None or self._view.state_label != '已停止'):
            return
        if not self._load_configuration():
            self._render()
            return
        try:
            if self._session is None:
                self._session = self.session_factory(self._core_config)
                self._session_signature = self._signature
                self._sequence = self._event_cursor = 0
            elif self._session_signature != self._signature:
                self._configuration_changed()
                self._render()
                return
            if self._fingerprint() != self._session_signature:
                self._configuration_changed()
                self._render()
                return
            self._session.start()
            if self._fingerprint() != self._session_signature:
                self._configuration_changed()
            else:
                self._sample()
        except Exception:
            self._fail('无法启动监测或核心接口不匹配')
        self._render()

    def stop(self):
        if self._session is None:
            return
        try:
            self._accept(self._session.snapshot())
            self._session.stop()
            self._accept(self._session.snapshot())
        except Exception:
            self._fail('监测停止未确认')
        self._render()

    def resume(self):
        if self._session is None or not self._alarm_latched or self._fault:
            return
        if self._fingerprint() != self._session_signature:
            self._configuration_changed()
            self._render()
            return
        try:
            before = self._session.snapshot()
            before_view = present_snapshot(before, previous_sequence=self._sequence)
            self._resume_baseline = before_view.last_success_at
            self._resume_sequence = before_view.sequence
            self._resume_pending = True
            self._session.resume()
            after = self._session.snapshot()
            if after.state == before.state and before.state in ('stopped', 'checking', 'monitoring'):
                self._session.stop()
                self._session.start()
                after = self._session.snapshot()
            self._accept(after)
        except Exception:
            self._fail('手动复检未能开始')
        self._render()

    def _report_text(self):
        lines = [self.status.get(), '本面板不控制旧助手启动，也不阻断正在运行的 Claude。']
        if self._view is not None:
            lines.extend(replace(self._view, events=()).report_lines()[1:])
        else:
            lines.extend(('监测范围：独立代理请求，不证明桌面或网页的全部连接。',
                          '监测最近检测：未确认', '监测最近成功：未确认', '监测证据：未确认'))
        if self._alarm_latched:
            lines.append('异常仍需手动复检恢复；未确认已断开正在运行的 Claude。')
        if self._events:
            lines.append('监测事件（本次运行，最多 100 条）：')
            for event in self._events:
                stamp = event.occurred_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %z')
                lines.append(stamp + ' · ' + event.reason_label + ' · ' + event.action_label)
        return '\n'.join(lines)

    def _render(self):
        state = self._view.state_label if self._view is not None else '已停止'
        can_start = self._core_config is not None and (self._session is None or (state == '已停止' and not self._alarm_latched)) and not self._fault
        can_stop = self._session is not None and (state != '已停止' or bool(self._fault))
        can_resume = self._session is not None and self._alarm_latched and not self._fault and self._core_config is not None
        self.start_button.configure(state='normal' if can_start else 'disabled')
        self.stop_button.configure(state='normal' if can_stop else 'disabled')
        self.resume_button.configure(state='normal' if can_resume else 'disabled')
        self.report.configure(state='normal')
        self.report.delete('1.0', 'end')
        self.report.insert('1.0', self._report_text())
        self.report.configure(state='disabled')

    def _poll(self):
        if self._closed:
            return
        current = self._fingerprint()
        if current != self._signature:
            self._configuration_changed()
        elif self._session is not None:
            self._sample()
            if self._fingerprint() != self._session_signature:
                self._configuration_changed()
        self._render()
        self._poll_id = self.root.after(self.poll_interval_ms, self._poll)

    def copy_report(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._report_text())
        except tk.TclError:
            messagebox.showerror('复制失败', '无法复制报告，请检查剪贴板。', parent=self.root)

    def export_report(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='导出脱敏监测报告', defaultextension='.txt', filetypes=[('文本文件', '*.txt')])
        if path:
            try:
                Path(path).write_text(self._report_text(), encoding='utf-8')
            except OSError:
                messagebox.showerror('导出失败', '无法写入所选位置，请检查权限。', parent=self.root)

    def _shutdown(self):
        if self._closed:
            return
        self._closed = True
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        if self._session is not None:
            try:
                self._session.stop()
            except Exception:
                pass
            self._session = None

    def _on_destroy(self, event):
        if event.widget is self.root:
            self._shutdown()

    def close(self):
        self._shutdown()
        self.root.destroy()


def main():
    root = tk.Tk()
    MonitorWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
