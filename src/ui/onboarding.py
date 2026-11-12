"""Read-only local port candidates and task guidance."""
from dataclasses import dataclass, field
import json
import ntpath
import os
import queue
import re
import subprocess
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import ttk


THIRD_PARTY_CHECK_URL = 'https://ip.net.coffee/claude/'
DEFAULT_IP_URL = 'https://api.ipify.org'

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


MANAGER_EXE = 'Proxy Manager.exe'
MANAGER_DIR = '@luminati-ioluminati-proxy'
# Proxy Manager's own defaults file; the assistant source keeps no machine port numbers (packaging audit).
MANAGER_DEFAULTS = ('resources', 'app', 'util', 'lpm_config_static.js')
INSTALLER_NAME = 'brightdata-proxy-manager-v1.679.135-setup.exe'
# The 1.679.135 installer is 133451208 bytes; only a file of exactly this size is hashed.
INSTALLER_SIZE = 133451208
_SEARCH_DEPTH = 7
_SEARCH_ENTRIES = 400000
_SEARCH_SECONDS = 25
_SKIPPED_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'site-packages'}

_MANAGER_PATH_SCRIPT = r"""$ErrorActionPreference = 'Stop'
$paths = @(Get-Process -Name 'Proxy Manager' -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -Unique)
ConvertTo-Json -InputObject $paths -Compress
"""


@dataclass(frozen=True)
class AutoSetup:
    installer: str = field(default='', repr=False)
    executable: str = field(default='', repr=False)
    manager_port: int | None = None
    proxy_port: int | None = None
    notes: tuple[str, ...] = ()

    @property
    def complete(self):
        return bool(self.installer and self.executable and self.manager_port and self.proxy_port)


def running_manager_paths():
    """Program paths of running Proxy Manager processes; None when they cannot be read."""
    try:
        options = {'capture_output': True, 'text': True, 'encoding': 'utf-8', 'errors': 'strict', 'timeout': 20, 'check': True}
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            options['creationflags'] = subprocess.CREATE_NO_WINDOW
        completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', _MANAGER_PATH_SCRIPT], **options)
        if len(completed.stdout) > 20000:
            return None
        values = json.loads(completed.stdout)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            return None
        return tuple(values)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, UnicodeError):
        return None


def find_manager_executable(running, environ=os.environ):
    """Return (path, note): the one running Proxy Manager, else the default per-user install."""
    found = {}
    for path in running or ():
        if ntpath.isabs(path) and ntpath.basename(path).casefold() == MANAGER_EXE.casefold():
            found.setdefault(ntpath.normcase(ntpath.normpath(path)), ntpath.normpath(path))
    if len(found) == 1:
        return next(iter(found.values())), ''
    if len(found) > 1:
        return '', '找到不止一个正在运行的代理管理器（装在不同文件夹）：请只保留一个，或在核验窗口里手动选择文件夹。'
    local = environ.get('LOCALAPPDATA', '')
    default = ntpath.join(local, 'Programs', MANAGER_DIR, MANAGER_EXE) if local else ''
    if default and os.path.isfile(default):
        return default, ''
    return '', '没找到代理管理器的安装文件夹：请确认已经安装，或在核验窗口里手动选择。'


def installer_roots(environ=os.environ):
    roots = []
    for base, names in ((environ.get('USERPROFILE', ''), ('Downloads', 'Desktop', 'Documents')),
                        (environ.get('OneDrive', ''), ('Desktop', 'Documents'))):
        if base:
            roots.extend(ntpath.join(base, name) for name in names)
    unique = {}
    for root in roots:
        unique.setdefault(ntpath.normcase(ntpath.normpath(root)), root)
    return tuple(root for root in unique.values() if os.path.isdir(root))


def find_installer(roots, digest=None, hash_file=None, size=INSTALLER_SIZE, clock=time.monotonic):
    """Find the 1.679.135 installer by exact size, then fingerprint; links and junctions are skipped."""
    if digest is None or hash_file is None:
        from src.core.release_trust import INSTALLER_SHA256, _file_sha256
        digest = digest or INSTALLER_SHA256
        hash_file = hash_file or _file_sha256
    deadline = clock() + _SEARCH_SECONDS
    visited = 0
    # Breadth first, so shallow places such as Downloads are reached before deep project folders.
    pending = deque((root, 0) for root in roots)
    while pending:
        directory, depth = pending.popleft()
        try:
            with os.scandir(directory) as entries:
                items = sorted(entries, key=lambda entry: entry.name.casefold())
        except OSError:
            continue
        for entry in items:
            visited += 1
            if visited > _SEARCH_ENTRIES or clock() > deadline:
                return ''
            try:
                if entry.is_symlink() or getattr(entry, 'is_junction', lambda: False)():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < _SEARCH_DEPTH and entry.name.casefold() not in _SKIPPED_DIRS:
                        pending.append((entry.path, depth + 1))
                elif (entry.name.casefold().endswith('.exe') and entry.is_file(follow_symlinks=False)
                        and entry.stat(follow_symlinks=False).st_size == size
                        and hash_file(entry.path).lower() == digest):
                    return entry.path
            except OSError:
                continue
    return ''


def read_manager_defaults(executable):
    """Return (management port, Proxy Manager's self-created proxy port) from its installed defaults file."""
    try:
        path = ntpath.join(ntpath.dirname(executable), *MANAGER_DEFAULTS)
        if os.path.getsize(path) > 1048576:
            return None, None
        with open(path, encoding='utf-8') as stream:
            text = stream.read()
    except (OSError, ValueError, TypeError, UnicodeError):
        return None, None
    manager = re.search(r'conf\.manager_default\s*=\s*Object\.assign\([^{]*\{(.*?)\n\}\)', text, re.S)
    www = re.search(r'^\s*www:\s*(\d{1,5}),', manager.group(1), re.M) if manager else None
    server = re.search(r'^\s*port:\s*(\d{1,5}),', text[:manager.start()] if manager else '', re.M)
    def number(match):
        value = int(match.group(1)) if match else 0
        return value if 1 <= value <= 65535 else None
    return number(www), number(server)


def choose_ports(observed, proxies, expected_zone, manager_port, default_port=None):
    """Pick the management port and the one running proxy port whose zone is the expected one."""
    if manager_port is None:
        return None, None, '认不出代理管理器的管理端口：请点“查找并选择端口”手动选择。'
    if manager_port not in observed:
        return None, None, f'没找到代理管理器的管理端口 {manager_port}：请确认代理管理器正常打开。'
    running = [item for item in proxies or () if isinstance(item, dict) and type(item.get('port')) is int
               and item['port'] in observed and item['port'] != manager_port]
    zone = expected_zone.strip()
    names = '、'.join(sorted({item['zone'] for item in running if isinstance(item.get('zone'), str)})) or '无'
    hint = '（代理管理器里现有的代理名称：' + names + '）'
    if not zone:
        return manager_port, None, '请先在上面填好“独立预期区域”（官网上的代理名称），助手才能认出该用哪个代理端口' + hint + '。'
    matched = sorted({item['port'] for item in running if item.get('zone') == zone})
    if len(matched) > 1 and default_port in matched:
        # Proxy Manager creates its default port by itself; the port the user built for Claude is the other one.
        matched.remove(default_port)
    if len(matched) == 1:
        return manager_port, matched[0], ''
    if not matched:
        return manager_port, None, '代理管理器里没有使用这个代理名称的端口' + hint + '：请核对“独立预期区域”是否和官网一致，或在代理管理器里新建端口。'
    return manager_port, None, '有多个代理端口用的是同一个代理名称：请点“查找并选择端口”手动选择。'


def probe_manager_ports(ports):
    """R44: ports accepted by Proxy Manager, found by connecting when the listen table leaves them out."""
    wanted = sorted({port for port in ports if type(port) is int and 1 <= port <= 65535})
    if not wanted:
        return ()
    try:
        from src.core.backend import _PORT_ROWS_PS
        script = ("$ErrorActionPreference='Stop'; " + _PORT_ROWS_PS
                  + "$ids = @(Get-Process -Name 'Proxy Manager' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id); "
                  + "$found = @(foreach ($port in @(" + ','.join(str(port) for port in wanted) + ")) { "
                  + "$o = @(rows $port | Select-Object -ExpandProperty OwningProcess -Unique); "
                  + "if ($o.Count -gt 0 -and @($o | Where-Object { $ids -notcontains $_ }).Count -eq 0) { $port } }); "
                  + "ConvertTo-Json -InputObject $found -Compress")
        options = {'capture_output': True, 'text': True, 'encoding': 'utf-8', 'errors': 'strict', 'timeout': 20, 'check': True}
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            options['creationflags'] = subprocess.CREATE_NO_WINDOW
        values = json.loads(subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], **options).stdout)
        if not isinstance(values, list):
            return ()
        return tuple(sorted({value for value in values if type(value) is int and value in wanted}))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, UnicodeError):
        return ()


def complete_ports(observed, www, fetch, probe):
    """Ports the listen table left out are confirmed one by one by connecting (R44; per port since 0.3.6).

    Returns (ports, whether any port needed the fallback)."""
    ports = set(observed)
    found = set()
    if www and www not in ports:
        found |= set(probe([www]))
        ports |= found
    if www in ports:
        try:
            proxies = fetch(www)
        except Exception:
            proxies = ()
        missing = [item['port'] for item in proxies or () if isinstance(item, dict)
                   and type(item.get('port')) is int and item['port'] not in ports]
        if missing:
            extra = set(probe(missing))
            found |= extra
            ports |= extra
    return tuple(sorted(ports)), bool(found)


def _proxies_running(port):
    from src.core.backend import _fetch_manager_json
    return _fetch_manager_json(port, '/api/proxies_running', 5)


def _executable_digest(path):
    from src.core.release_trust import _file_sha256
    return _file_sha256(path)


def collect_auto_setup(expected_zone, *, discover=discover_port_candidates, running=running_manager_paths,
                       fetch=_proxies_running, roots=installer_roots, find=find_installer,
                       digest=_executable_digest, defaults=read_manager_defaults, probe=probe_manager_ports,
                       environ=os.environ):
    """Read-only local lookup; nothing is saved, trusted or sent anywhere."""
    from src.core.release_trust import EXECUTABLE_SHA256
    notes = []
    paths = running()
    candidates = discover()
    observed = candidates.ports if isinstance(candidates, PortCandidates) and candidates.status == 'observed' else ()
    executable, executable_note = find_manager_executable(paths, environ)
    www, default_port = defaults(executable) if executable else (None, None)
    if paths:
        observed = complete_ports(observed, www, fetch, probe)[0]
    manager_port = proxy_port = None
    if not observed:
        if paths == ():
            notes.append('没检测到正在运行的代理管理器：请先打开它，等 1 分钟后再点一次。')
        elif paths is None:
            notes.append('读不到代理管理器的运行状态：请确认它已经打开，再点一次。')
        else:
            notes.append('代理管理器开着，但端口没在工作：请重启电脑，开机后只打开一次代理管理器，等 1 分钟后再点一次。')
    else:
        try:
            proxies = fetch(www) if www in observed else ()
        except Exception:
            proxies = ()
        manager_port, proxy_port, note = choose_ports(observed, proxies, expected_zone, www, default_port)
        if note:
            notes.append(note)
    if executable_note:
        notes.append(executable_note)
    elif executable:
        try:
            if digest(executable).lower() != EXECUTABLE_SHA256:
                executable = ''
                notes.append('装的代理管理器不是 1.679.135 版本（可能自动升级过）：需要用 1.679.135 的安装包重新安装。')
        except OSError:
            executable = ''
            notes.append('读不到代理管理器的程序文件：请确认它没有被移动或删除。')
    try:
        installer = find(roots(environ))
    except Exception:
        installer = ''
    if not installer:
        notes.append('在“下载、桌面、文档”里没找到 1.679.135 版安装包：请从主电脑拷一份 '
                     + INSTALLER_NAME + ' 到“下载”文件夹，再点一次。')
    return AutoSetup(installer, executable, manager_port, proxy_port, tuple(notes))


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
        self.window.geometry('850x800')
        self.window.columnconfigure(1, weight=1)
        self._editors = []
        self._candidate_buttons = []
        self._auto_queue = queue.Queue()
        self._auto_closed = False
        self._auto_lock = threading.Lock()
        self.auto_busy = False
        self.collect = collect_auto_setup
        if not app.fields['ip_url'].get().strip() and app._operation != 'launch':
            app.fields['ip_url'].set(DEFAULT_IP_URL)
        ttk.Label(self.window, text='按顺序核对当前电脑配置。预期 IP 和区域请从服务商等独立依据核对；不能把本次观测结果当成预期。候选需自行确认。', wraplength=810).grid(row=0, column=0, columnspan=3, sticky='w', padx=12, pady=8)
        entries = (
            ('expected_ip', '1. 独立预期出口 IP'),
            ('ip_url', '出口检测服务 HTTPS 地址'),
            ('expected_zone', '独立预期区域'),
            ('mapping_mode', '目标映射要求（固定）'),
            ('url', 'Claude 网页地址'),
        )
        for row, (key, label) in enumerate(entries, 1):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=12, pady=3)
            if key == 'mapping_mode':
                entry = ttk.Combobox(self.window, textvariable=app.fields[key], values=mapping_labels, state='disabled')
            else:
                entry = ttk.Entry(self.window, textvariable=app.fields[key], show='●' if key == 'expected_ip' else '')
            entry.grid(row=row, column=1, columnspan=2, sticky='ew', padx=(0, 12), pady=3)
            self._editors.append((entry, 'disabled' if key == 'mapping_mode' else 'normal'))
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
        self.auto_button = ttk.Button(buttons, text='一键查找并填入', command=self.auto_fill, style='Accent.TButton')
        self.auto_button.pack(side='left', padx=4)
        self.health_button = ttk.Button(buttons, text='环境体检', command=app.open_health_check)
        self.health_button.pack(side='left', padx=4)
        self.save_button = ttk.Button(buttons, text='保存本机配置', command=app.save_settings, style='Accent.TButton')
        self.save_button.pack(side='left', padx=4)
        self.detect_button = ttk.Button(buttons, text='重新检测（联网）', command=app.detect)
        self.detect_button.pack(side='left', padx=4)
        ttk.Button(buttons, text='关闭', command=self.window.destroy).pack(side='left', padx=4)
        self.auto_status = tk.StringVar(value='先填好预期 IP、检测地址和区域，再点“一键查找并填入”：自动选端口、找安装包和管理器文件夹并核验，最后由您点“保存本机配置”。')
        ttk.Label(self.window, textvariable=self.auto_status, wraplength=810).grid(row=15, column=0, columnspan=3, sticky='w', padx=12, pady=(0, 8))
        self._auto_poll_id = self.window.after(50, self._auto_poll)
        self.window.bind('<Destroy>', self._auto_destroy, add='+')
        self.sync_state()

    def sync_state(self):
        launching = self.app._operation == 'launch'
        for widget, state in self._editors:
            widget.configure(state='disabled' if launching else state)
        for button in self._candidate_buttons:
            button.configure(state='disabled' if launching else 'normal')
        for button in (self.save_button, self.detect_button):
            button.configure(state='disabled' if self.app.busy else 'normal')
        self.auto_button.configure(state='disabled' if self.app.busy or self.auto_busy else 'normal')

    def auto_fill(self):
        if self.auto_busy or self.app.busy or self.app._operation == 'launch':
            return
        zone = self.app.fields['expected_zone'].get()
        self.auto_busy = True
        self.sync_state()
        self.auto_status.set('正在查找本机的代理管理器、端口和安装包，最多约半分钟，请稍候。')
        def work():
            try:
                result = self.collect(zone)
            except Exception:
                result = AutoSetup(notes=('查找时出错，请再点一次；仍不行就按图解手动选择。',))
            with self._auto_lock:
                if not self._auto_closed:
                    self._auto_queue.put((zone, result))
        threading.Thread(target=work, daemon=True).start()

    def _auto_poll(self):
        try:
            while True:
                zone, result = self._auto_queue.get_nowait()
                self.auto_busy = False
                self.sync_state()
                self._apply_auto(zone, result)
        except queue.Empty:
            pass
        self._auto_poll_id = self.window.after(50, self._auto_poll)

    def _apply_auto(self, zone, result):
        app = self.app
        if app.busy or app._operation == 'launch' or app.fields['expected_zone'].get() != zone:
            self.auto_status.set('查找期间配置有变化，结果没有填入，请再点一次。')
            return
        if result.manager_port:
            app.fields['manager_port'].set(str(result.manager_port))
        if result.proxy_port:
            app.fields['port'].set(str(result.proxy_port))
        notes = '\n'.join('· ' + note for note in result.notes)
        if not result.complete:
            self.auto_status.set('没有全部找到，请按提示处理后再点一次：\n' + notes)
            return
        app.open_release_setup()
        dialog = app._release_dialog
        if dialog is None or not dialog.prefill(result.installer, ntpath.dirname(result.executable)):
            self.auto_status.set('核验窗口正忙，请等它完成后再点一次。')
            return
        text = '已选好端口、安装包和管理器文件夹，正在核验；通过后会自动填入程序路径和指纹，然后请点“保存本机配置”。'
        self.auto_status.set(text + ('\n' + notes if notes else ''))

    def _auto_destroy(self, event):
        if event.widget is self.window:
            with self._auto_lock:
                self._auto_closed = True
                while not self._auto_queue.empty():
                    self._auto_queue.get_nowait()
            self.window.after_cancel(self._auto_poll_id)


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
