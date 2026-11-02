"""Read-only local port candidates and task guidance."""
from dataclasses import dataclass
import json
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import ttk


THIRD_PARTY_CHECK_URL = 'https://ip.net.coffee/claude/'

GUIDE_TEXT = f'''请根据这台 Windows 电脑的实际配置填写端口、预期 IP、区域和 Chrome 路径。若沿用了其他电脑的配置，请逐项重新核对。

使用前需要已安装 Proxy Manager；网页端还需已有专用 Chrome 及其 LPM 扩展，桌面端需已安装 Claude 桌面端。本软件不会安装或修改这些程序及扩展。

配置将明文保存在本机，包含您填写的 IP、区域和路径等信息。不要填写账号、密码、令牌或聊天内容，检测服务地址路径中也不要放凭据。

1. 确认 Proxy Manager 已由您正常打开。可用“查找已有端口”读取本机监听端口候选；请对照 Proxy Manager 界面分别确认管理端口和代理端口。候选不表示程序可信，也不会读取代理密码。

2. 网页端：可在“网页与浏览器”中选择已有 Chrome 快捷方式，只读查看程序和配置目录，核对后主动填入表单并保存。在已有的 Claude 专用 Chrome 中，确认 LPM 扩展选择的是您实际使用的代理端口。

可复制第三方辅助检测地址，在已选专用 Chrome 中手动打开并核对页面当次结果：{THIRD_PARTY_CHECK_URL}。第三方页面仅供辅助核对，不能证明桌面端每条连接的出口，也不能替代本软件的浏览器身份与实际代理核验。

3. 本软件目前不能自动确认所选浏览器的真实身份和实际代理，网页端显示“未确认”，自动打开入口保持禁用。此前任何人工观察都不代表当前状态。

4. 桌面端可单独使用：填写并保存代理配置和独立核验的管理器基准；点击“查找桌面端”，选择已发现的应用，再点击“重新检测”。如已有桌面实例，请自行正常退出后再检测。满足启动条件后可点击“启动桌面端”，再由您在真实应用中确认消息收发。

桌面端实际出口和消息收发需要单独确认。启动前检测不能证明运行中断连保护。'''


@dataclass(frozen=True)
class PortCandidates:
    status: str = 'unknown'
    ports: tuple[int, ...] = ()


_PORT_SCRIPT = r"""$ErrorActionPreference = 'Stop'
$ids = @(Get-Process -Name 'Proxy Manager' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
if ($ids.Count -eq 0) { '[]'; exit 0 }
$ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
  Where-Object { $_.OwningProcess -in $ids -and $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::') } |
  Select-Object -ExpandProperty LocalPort -Unique)
ConvertTo-Json -InputObject $ports -Compress
"""


def discover_port_candidates():
    try:
        options = {'capture_output': True, 'text': True, 'encoding': 'utf-8', 'errors': 'strict', 'timeout': 20, 'check': True}
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            options['creationflags'] = subprocess.CREATE_NO_WINDOW
        completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', _PORT_SCRIPT], **options)
        if len(completed.stdout) > 10000:
            return PortCandidates()
        values = json.loads(completed.stdout)
        if not isinstance(values, list) or any(type(value) is not int or not 1 <= value <= 65535 for value in values):
            return PortCandidates()
        ports = tuple(sorted(set(values)))
        return PortCandidates('observed' if ports else 'unknown', ports)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, UnicodeError):
        return PortCandidates()


class GuideDialog:
    def __init__(self, root):
        self.window = tk.Toplevel(root)
        self.window.title('本机使用步骤')
        self.window.geometry('780x570')
        self.copy_status = tk.StringVar(value='')
        actions = ttk.Frame(self.window, padding=(12, 0, 12, 12))
        actions.pack(side='bottom', fill='x')
        self.copy_button = ttk.Button(actions, text='复制第三方检测地址', command=self.copy_address)
        self.copy_button.pack(side='left')
        ttk.Label(actions, textvariable=self.copy_status).pack(side='left', padx=10)
        frame = ttk.Frame(self.window, padding=12)
        frame.pack(fill='both', expand=True)
        text = tk.Text(frame, wrap='word', padx=8, pady=8)
        self.text = text
        scrollbar = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        text.pack(side='left', fill='both', expand=True)
        text.insert('1.0', GUIDE_TEXT)
        text.configure(state='disabled')

    def copy_address(self):
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(THIRD_PARTY_CHECK_URL)
            self.copy_status.set('已复制；请在专用 Chrome 中手动打开。')
        except tk.TclError:
            self.copy_status.set('复制失败，请手动复制上方地址。')


class FirstSetupDialog:
    """One place to review independent inputs and open the existing candidate dialogs."""
    def __init__(self, app, mapping_labels):
        self.app = app
        self.window = tk.Toplevel(app.root)
        self.window.title('首次配置向导')
        self.window.geometry('850x760')
        self.window.columnconfigure(1, weight=1)
        self._editors = []
        self._candidate_buttons = []
        ttk.Label(self.window, text='按顺序核对当前电脑配置。预期 IP 和区域请从服务商等独立依据核对；不能把本次观测结果当成预期。候选需自行确认。', wraplength=810).grid(row=0, column=0, columnspan=3, sticky='w', padx=12, pady=8)
        entries = (
            ('expected_ip', '1. 独立预期出口 IP'),
            ('ip_url', '出口检测服务 HTTPS 地址'),
            ('expected_zone', '独立预期区域'),
            ('mapping_mode', '目标映射要求'),
            ('mapping_targets', '预期映射（如需要）'),
            ('url', 'Claude 网页地址'),
        )
        for row, (key, label) in enumerate(entries, 1):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=12, pady=3)
            if key == 'mapping_mode':
                entry = ttk.Combobox(self.window, textvariable=app.fields[key], values=mapping_labels, state='readonly')
            else:
                entry = ttk.Entry(self.window, textvariable=app.fields[key], show='●' if key == 'expected_ip' else '')
            entry.grid(row=row, column=1, columnspan=2, sticky='ew', padx=(0, 12), pady=3)
            self._editors.append((entry, 'readonly' if key == 'mapping_mode' else 'normal'))
            if key == 'expected_ip':
                self.expected_ip_entry = entry
        ttk.Label(self.window, text='2. 代理 / 管理端口').grid(row=7, column=0, sticky='w', padx=12, pady=5)
        port_frame = ttk.Frame(self.window)
        port_frame.grid(row=7, column=1, sticky='ew')
        self.port_entry = ttk.Entry(port_frame, textvariable=app.fields['port'], state='readonly', width=12)
        self.port_entry.pack(side='left')
        ttk.Label(port_frame, text=' / ').pack(side='left')
        ttk.Entry(port_frame, textvariable=app.fields['manager_port'], state='readonly', width=12).pack(side='left')
        self.port_button = ttk.Button(self.window, text='查找并选择端口', command=app.open_port_candidates)
        self.port_button.grid(row=7, column=2, padx=12, pady=5)
        ttk.Label(self.window, text='3. Chrome 程序（网页可选）').grid(row=8, column=0, sticky='w', padx=12, pady=4)
        self.chrome_entry = ttk.Entry(self.window, textvariable=app.fields['chrome_path'], state='readonly')
        self.chrome_entry.grid(row=8, column=1, sticky='ew', pady=4)
        self.shortcut_button = ttk.Button(self.window, text='选择已有快捷方式', command=app.open_shortcut)
        self.shortcut_button.grid(row=8, column=2, padx=12, pady=4)
        for row, key, label in ((9, 'user_data_dir', '用户数据目录'), (10, 'chrome_profile', '配置目录')):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=12, pady=4)
            ttk.Entry(self.window, textvariable=app.fields[key], state='readonly').grid(row=row, column=1, columnspan=2, sticky='ew', padx=(0, 12), pady=4)
        ttk.Label(self.window, text='4. 最后核验管理器基准').grid(row=11, column=0, sticky='w', padx=12, pady=6)
        ttk.Label(self.window, textvariable=app.trust_status, wraplength=480).grid(row=11, column=1, sticky='w', pady=6)
        self.release_button = ttk.Button(self.window, text='选择安装包并核验', command=app.open_release_setup)
        self.release_button.grid(row=11, column=2, padx=12, pady=6)
        self._candidate_buttons.extend((self.port_button, self.shortcut_button, self.release_button))
        guidance = ('确认 Proxy Manager 已运行；在已有专用 Chrome 的 Bright Data LPM 扩展中核对同一代理端口。'
                    '在主窗口“使用步骤”中可复制第三方地址，在专用 Chrome 手动核对当次结果。浏览器身份与实际代理未确认，网页启动仍禁用。\n'
                    '桌面端：保存后返回主窗口，点击“查找桌面端”并选择；如已有实例请正常退出，再重新检测。满足条件后启动并由您确认消息收发；桌面端实际出口仍未确认。\n'
                    '查找不到端口或快捷方式时，可返回主窗口手动填写；缺少安装包或无法核验时，管理器基准保持未确认。\n'
                    '修改表单会撤销未保存的管理器候选，请最后核验。配置明文保存，不要填写凭据或聊天内容；点击检测才会联网。')
        self.guide_label = ttk.Label(self.window, text=guidance, wraplength=810, style='Muted.TLabel')
        self.guide_label.grid(row=12, column=0, columnspan=3, sticky='w', padx=12, pady=8)
        ttk.Label(self.window, textvariable=app.summary, wraplength=810).grid(row=13, column=0, columnspan=3, sticky='w', padx=12, pady=4)
        buttons = ttk.Frame(self.window)
        buttons.grid(row=14, column=0, columnspan=3, sticky='e', padx=12, pady=8)
        self.save_button = ttk.Button(buttons, text='保存本机配置', command=app.save_settings, style='Accent.TButton')
        self.save_button.pack(side='left', padx=4)
        self.detect_button = ttk.Button(buttons, text='重新检测（联网）', command=app.detect)
        self.detect_button.pack(side='left', padx=4)
        ttk.Button(buttons, text='关闭', command=self.window.destroy).pack(side='left', padx=4)
        self.sync_state()

    def sync_state(self):
        launching = self.app._operation == 'launch'
        for widget, state in self._editors:
            widget.configure(state='disabled' if launching else state)
        for button in self._candidate_buttons:
            button.configure(state='disabled' if launching else 'normal')
        for button in (self.save_button, self.detect_button):
            button.configure(state='disabled' if self.app.busy else 'normal')


class PortDialog:
    def __init__(self, app, discover=discover_port_candidates):
        self.app = app
        self.discover = discover
        self.window = tk.Toplevel(app.root)
        self.window.title('查找已有端口')
        self.window.geometry('720x330')
        self.window.columnconfigure(1, weight=1)
        self.manager = tk.StringVar()
        self.proxy = tk.StringVar()
        self.status = tk.StringVar(value='只查询本机监听端口，不读取代理密码；尚未开始。')
        self.busy = False
        self._generation = None
        self._ports = ()
        self._queue = queue.Queue()
        self._closed = False
        self._lock = threading.Lock()
        ttk.Label(self.window, text='候选仅按进程名发现，不能证明可信身份或端口用途。\n请对照 Proxy Manager 界面自行选择；此操作不会修改代理设置。', wraplength=690).grid(row=0, column=0, columnspan=2, sticky='w', padx=16, pady=12)
        self.start_button = ttk.Button(self.window, text='查找本机候选端口', command=self.start)
        self.start_button.grid(row=1, column=1, sticky='e', padx=16)
        for row, label, variable in ((2, '管理端口', self.manager), (3, '代理端口', self.proxy)):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=16, pady=6)
            widget = ttk.Combobox(self.window, textvariable=variable, state='readonly')
            widget.grid(row=row, column=1, sticky='ew', padx=(0, 16), pady=6)
            if row == 2:
                self.manager_choice = widget
            else:
                self.proxy_choice = widget
        ttk.Label(self.window, textvariable=self.status, wraplength=690).grid(row=4, column=0, columnspan=2, sticky='w', padx=16, pady=8)
        self.apply_button = ttk.Button(self.window, text='填入所选端口（不保存）', command=self.apply, state='disabled')
        self.apply_button.grid(row=5, column=1, sticky='e', padx=16, pady=6)
        self._poll_id = self.window.after(50, self._poll)
        self.window.bind('<Destroy>', self._destroy, add='+')

    def start(self):
        if self.busy or self.app._operation == 'launch':
            return
        self.busy = True
        self._generation = self.app._generation
        self._ports = ()
        self.manager.set('')
        self.proxy.set('')
        self.start_button.configure(state='disabled')
        self.apply_button.configure(state='disabled')
        self.status.set('正在只读查询本机监听端口。')
        generation = self._generation
        def work():
            try:
                result = self.discover()
            except Exception:
                result = PortCandidates()
            with self._lock:
                if not self._closed:
                    self._queue.put((generation, result))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                generation, result = self._queue.get_nowait()
                self.busy = False
                self.start_button.configure(state='normal')
                if generation != self.app._generation or not isinstance(result, PortCandidates) or result.status != 'observed':
                    self._ports = ()
                    self.status.set('端口未确认或配置已变化，请核对程序后重试。')
                    continue
                self._ports = tuple(port for port in result.ports if type(port) is int and 1 <= port <= 65535)
                self.manager_choice['values'] = self._ports
                self.proxy_choice['values'] = self._ports
                self.apply_button.configure(state='normal' if self._ports else 'disabled')
                self.status.set('请选择端口用途；候选不代表可信身份或实际代理状态。')
        except queue.Empty:
            pass
        self._poll_id = self.window.after(50, self._poll)

    def apply(self):
        if self.busy or self._generation != self.app._generation or self.app._operation == 'launch':
            self.apply_button.configure(state='disabled')
            self.status.set('配置已变化，请重新查询。')
            return
        try:
            manager = int(self.manager.get()) if self.manager.get() else None
            proxy = int(self.proxy.get()) if self.proxy.get() else None
        except ValueError:
            manager = proxy = None
        if (manager is None and proxy is None) or (manager is not None and manager not in self._ports) or (proxy is not None and proxy not in self._ports) or (manager is not None and manager == proxy):
            self.status.set('请从候选中选择用途；两个端口不能相同。')
            return
        if manager is not None:
            self.app.fields['manager_port'].set(str(manager))
        if proxy is not None:
            self.app.fields['port'].set(str(proxy))
        self._generation = None
        self.apply_button.configure(state='disabled')
        self.status.set('已填入表单，尚未保存；请核对后保存并重新检测。')

    def _destroy(self, event):
        if event.widget is self.window:
            with self._lock:
                self._closed = True
                while not self._queue.empty():
                    self._queue.get_nowait()
            self.window.after_cancel(self._poll_id)
