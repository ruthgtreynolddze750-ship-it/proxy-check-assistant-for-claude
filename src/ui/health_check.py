"""Environment check (R43, R45): walk the chain and say in plain words what blocks it.

The check itself saves, changes and starts nothing; its requests leave only through the proxy port (Claude and
Cloudflare trace pages, the user's exit-IP service and a mainland IP site). The only change is the one-click repair,
run after the user confirms it: restart this Proxy Manager install, never Claude. Full IPs, paths and fingerprints
never enter the report.
"""
from dataclasses import dataclass
from datetime import datetime
import csv
import ipaddress
import json
import ntpath
import os
import re
import subprocess
import time

from .onboarding import (DEFAULT_IP_URL, PortCandidates, choose_ports, complete_ports, discover_port_candidates,
                         find_manager_executable, probe_manager_ports, read_manager_defaults, running_manager_paths)

TRACE_URL = 'https://claude.ai/cdn-cgi/trace'
LABELS = {'ok': '通过', 'fail': '有问题', 'warn': '注意', 'skip': '跳过'}
_CLOCK_LIMIT_SECONDS = 300
_INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'


@dataclass(frozen=True)
class HealthItem:
    name: str
    status: str
    detail: str
    fix: str = ''


@dataclass(frozen=True)
class HealthInput:
    port: int | None
    manager_port: int | None
    expected_ip: str
    ip_url: str
    expected_zone: str
    manager_executable: str
    manager_sha256: str


def mask_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return '无法识别'
    if address.version == 4:
        return '.'.join(str(address).split('.')[:2]) + '.*.*'
    return ':'.join(address.exploded.split(':')[:2]) + ':*'


def _process_names():
    options = {'capture_output': True, 'text': True, 'errors': 'replace', 'timeout': 15, 'check': True}
    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
        options['creationflags'] = subprocess.CREATE_NO_WINDOW
    result = subprocess.run(['tasklist', '/fo', 'csv', '/nh'], **options)
    return tuple(row[0] for row in csv.reader(result.stdout.splitlines()) if row)


def _system_proxy():
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS) as key:
        def value(name, default):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except OSError:
                return default
        return bool(value('ProxyEnable', 0)), str(value('ProxyServer', '') or ''), bool(value('AutoConfigURL', ''))


def _proxy_request(port, url, allow_redirects=False):
    from src.core.backend import _request_via_proxy
    return _request_via_proxy(port, url, 8, allow_same_host_redirects=allow_redirects)


def _manager_json(port, path):
    from src.core.backend import _fetch_manager_json
    return _fetch_manager_json(port, path, 5)


def _executable_digest(path):
    from src.core.release_trust import _file_sha256
    return _file_sha256(path)


def _desktop():
    from src.core.backend import desktop_status, discover_desktop
    return discover_desktop(), desktop_status().status


def _parse_ip(body):
    raw = body.decode('utf-8').strip()
    if raw.startswith('{'):
        payload = json.loads(raw)
        raw = payload.get('ip', '') if isinstance(payload, dict) else ''
    return str(ipaddress.ip_address(raw))


def _parse_trace(body, host='claude.ai'):
    """Return (ip, ts, loc) from a Cloudflare trace page served for the given host."""
    fields = {}
    for line in body.decode('utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            fields.setdefault(key.strip(), value.strip())
    if fields.get('h', '').lower() != host:
        raise ValueError('not the expected trace page')
    return str(ipaddress.ip_address(fields.get('ip', ''))), fields.get('ts', ''), fields.get('loc', '').upper()


def _first_ipv4(body):
    for match in re.finditer(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])', body.decode('utf-8', 'replace')):
        try:
            return str(ipaddress.IPv4Address(match.group()))
        except ValueError:
            continue
    raise ValueError('no IPv4 address')


def _windows_locale():
    """(time zone id, display language, format locale) read from Windows; read-only."""
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\TimeZoneInformation') as key:
        zone = str(winreg.QueryValueEx(key, 'TimeZoneKeyName')[0]).strip('\x00 ')
    kernel = ctypes.windll.kernel32
    def name_of(lcid):
        buffer = ctypes.create_unicode_buffer(85)
        return buffer.value if kernel.LCIDToLocaleName(lcid, buffer, 85, 0) else ''
    ui = name_of(kernel.GetUserDefaultUILanguage())
    buffer = ctypes.create_unicode_buffer(85)
    fmt = buffer.value if kernel.GetUserDefaultLocaleName(buffer, 85) else ''
    return zone, ui, fmt


# Country of the Claude exit (trace loc=) -> Windows time zone ids and language prefixes that match it.
_COUNTRY = {
    'US': ('美国', {'Eastern Standard Time', 'Central Standard Time', 'Mountain Standard Time', 'US Mountain Standard Time',
                    'Pacific Standard Time', 'Alaskan Standard Time', 'Hawaiian Standard Time', 'US Eastern Standard Time'},
           ('en',), '(UTC-08:00) 太平洋时间(美国和加拿大) 等美国时区', '英语(美国)'),
    'CA': ('加拿大', {'Eastern Standard Time', 'Central Standard Time', 'Mountain Standard Time', 'Pacific Standard Time',
                      'Atlantic Standard Time', 'Newfoundland Standard Time', 'Canada Central Standard Time'},
           ('en', 'fr'), '加拿大所在的时区', '英语'),
    'GB': ('英国', {'GMT Standard Time'}, ('en',), '(UTC+00:00) 都柏林，爱丁堡，里斯本，伦敦', '英语(英国)'),
    'JP': ('日本', {'Tokyo Standard Time'}, ('ja', 'en'), '(UTC+09:00) 大阪，札幌，东京', '日语或英语'),
    'SG': ('新加坡', {'Singapore Standard Time'}, ('en', 'zh'), '(UTC+08:00) 吉隆坡，新加坡', '英语'),
    'KR': ('韩国', {'Korea Standard Time'}, ('ko', 'en'), '(UTC+09:00) 首尔', '韩语或英语'),
    'TW': ('台湾', {'Taipei Standard Time'}, ('zh', 'en'), '(UTC+08:00) 台北', '中文(台湾)或英语'),
    'DE': ('德国', {'W. Europe Standard Time'}, ('de', 'en'), '(UTC+01:00) 阿姆斯特丹，柏林…', '德语或英语'),
    'FR': ('法国', {'Romance Standard Time'}, ('fr', 'en'), '(UTC+01:00) 布鲁塞尔，哥本哈根，马德里，巴黎', '法语或英语'),
    'NL': ('荷兰', {'W. Europe Standard Time'}, ('nl', 'en'), '(UTC+01:00) 阿姆斯特丹，柏林…', '荷兰语或英语'),
    'AU': ('澳大利亚', {'AUS Eastern Standard Time', 'E. Australia Standard Time', 'Cen. Australia Standard Time',
                         'AUS Central Standard Time', 'W. Australia Standard Time', 'Tasmania Standard Time'},
           ('en',), '澳大利亚所在的时区', '英语(澳大利亚)'),
}


def _manager_processes():
    """[(pid, path)] of running Proxy Manager processes."""
    script = ("[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
              "ConvertTo-Json -Compress -InputObject @(Get-Process -Name 'Proxy Manager' -ErrorAction SilentlyContinue "
              "| ForEach-Object { [PSCustomObject]@{id=$_.Id; path=$_.Path} })")
    options = {'capture_output': True, 'text': True, 'encoding': 'utf-8', 'errors': 'strict', 'timeout': 20, 'check': True}
    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
        options['creationflags'] = subprocess.CREATE_NO_WINDOW
    values = json.loads(subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], **options).stdout)
    return tuple((item['id'], item.get('path') or '') for item in values if isinstance(item, dict) and type(item.get('id')) is int)


def _taskkill(pids):
    options = {'capture_output': True, 'timeout': 30, 'check': False}
    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
        options['creationflags'] = subprocess.CREATE_NO_WINDOW
    command = ['taskkill', '/F', '/T']
    for pid in pids:
        command += ['/PID', str(pid)]
    subprocess.run(command, **options)


def restart_manager(executable, *, desktop=_desktop, processes=_manager_processes, kill=_taskkill,
                    start=None, ports_ready=None, sleep=time.sleep, clock=time.monotonic):
    """R45 repair: stop only this Proxy Manager install, start it once, wait for its ports. Never touches Claude.

    Ending the processes (not a normal exit) also keeps a downloaded Proxy Manager update from installing itself."""
    if not executable:
        return False, '没找到代理管理器的安装位置，无法重启。'
    try:
        apps, state = desktop()
    except Exception:
        state = None
    if state != 'pass':
        return False, 'Claude 桌面端开着（或无法确认已关闭）：请先在 Claude 里正常退出，再点一键修复。助手不会强制关闭 Claude。'
    try:
        running = processes()
    except Exception:
        return False, '读不到代理管理器的进程，没有做任何改动。'
    target = ntpath.normcase(ntpath.normpath(executable))
    mine = [pid for pid, path in running if path and ntpath.normcase(ntpath.normpath(path)) == target]
    others = [pid for pid, path in running if not path or ntpath.normcase(ntpath.normpath(path)) != target]
    if others:
        return False, '有别的位置（或身份不明）的代理管理器在运行，助手不去动它：请在任务管理器里自己处理后再试。'
    if mine:
        kill(mine)
        deadline = clock() + 20
        while clock() < deadline:
            try:
                if not any(pid in mine for pid, _ in processes()):
                    break
            except Exception:
                pass
            sleep(1)
        else:
            return False, '代理管理器没能在 20 秒内结束，没有重新启动：请在任务管理器里结束 Proxy Manager 后再试。'
    (start or os.startfile)(executable)
    deadline = clock() + 90
    while clock() < deadline:
        sleep(3)
        try:
            if ports_ready is None or ports_ready():
                return True, '代理管理器已重新启动，端口正在工作。'
        except Exception:
            pass
    return False, '代理管理器已重新启动，但 90 秒内端口还没好：请再等 1 分钟后重新体检；仍不行就重启电脑。'


CF_TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace'
CN_IP_URLS = ('https://2026.ip138.com/', 'https://my.ip.cn/')


def _three_exits(port, claude_ip, expected, proxy_request):
    """R45: the exits Cloudflare and a mainland IP site see through the same proxy port, next to Claude's."""
    seen = {'Claude 检查页': claude_ip}
    try:
        seen['Cloudflare'] = _parse_trace(proxy_request(port, CF_TRACE_URL, True), 'one.one.one.one')[0]
    except Exception:
        seen['Cloudflare'] = None
    seen['国内测 IP 网站'] = None
    for url in CN_IP_URLS:
        try:
            seen['国内测 IP 网站'] = _first_ipv4(proxy_request(port, url, True))
            break
        except Exception:
            continue
    text = '，'.join(f'{name} {mask_ip(ip) if ip else "没回应"}' for name, ip in seen.items())
    note = '（这是经代理端口测的；浏览器里看到不一致，是浏览器没把请求交给代理端口，见图解）'
    values = {ip for ip in seen.values() if ip}
    if None in seen.values():
        return HealthItem('三个出口是否一致', 'warn', text + '。' + note, '没回应的那个网站可能暂时打不开，稍后再体检一次。')
    if len(values) == 1 and (not expected or expected in values):
        return HealthItem('三个出口是否一致', 'ok', '三个都一样：' + text + '。' + note)
    return HealthItem('三个出口是否一致', 'fail', '不一致：' + text + '。' + note,
                      '在代理管理器里确认这个端口用的是“长期固定一个 IP”，并到“请求日志”里看这几个网站的请求走的是不是同一个端口。')


def _locale_item(country, locale):
    """R45: Windows time zone and language next to the Claude exit country. Advice only; never changed here."""
    try:
        zone, ui, fmt = locale()
    except Exception:
        return HealthItem('时区和语言', 'warn', '读不到电脑的时区和语言设置。')
    known = _COUNTRY.get(country or '')
    if known is None:
        return HealthItem('时区和语言', 'skip', f'出口所在地区（{country or "未知"}）不在对照表里，没有比较。电脑时区 {zone}，显示语言 {ui}，区域格式 {fmt}。')
    name, zones, languages, zone_hint, language_hint = known
    problems, fixes = [], []
    if zone not in zones:
        problems.append(f'时区是 {zone}，不是{name}的时区')
        fixes.append(f'Windows 设置 → 时间和语言 → 日期和时间，关掉“自动设置时区”，把时区改成 {zone_hint}')
    if not any(value.lower().startswith(languages) for value in (ui, fmt) if value):
        problems.append(f'显示语言 {ui}、区域格式 {fmt}，都不是{name}常用的语言')
        fixes.append(f'Windows 设置 → 时间和语言 → 语言和区域，把“区域格式”（或显示语言）改成 {language_hint}')
    if not problems:
        return HealthItem('时区和语言', 'ok', f'出口在{name}；时区 {zone}、显示语言 {ui}、区域格式 {fmt} 和出口所在地相符。')
    return HealthItem('时区和语言', 'warn', f'出口在{name}，但' + '；'.join(problems) + '。是否影响 Claude 官方没有说明，仅供参考。',
                      '；'.join(fixes) + '（请你自己改，可以点下面的设置按钮直接打开）。')


def _compare(name, observed, expected, where):
    if not expected:
        return HealthItem(name, 'warn', f'{where}看到的出口是 {mask_ip(observed)}，但还没填预期 IP，无法对比。',
                          '在首次配置向导里填好 Bright Data 官网上那个固定 IP。')
    try:
        same = ipaddress.ip_address(expected) == ipaddress.ip_address(observed)
    except ValueError:
        return HealthItem(name, 'fail', '填的预期 IP 格式不对。', '照抄 Bright Data 官网“已分配的 IP”里的那个地址。')
    if same:
        return HealthItem(name, 'ok', f'{where}看到的出口和预期 IP 一致（{mask_ip(observed)}）。')
    return HealthItem(name, 'fail', f'{where}看到的是 {mask_ip(observed)}，和预期 IP（{mask_ip(expected)}）不一样。',
                      '先别登录 Claude。核对预期 IP 是否照抄官网；在代理管理器里确认这个端口用的是“长期固定一个 IP”，'
                      '并到“请求日志”里看请求有没有经过这个端口。')


def run_health_check(data, *, running=running_manager_paths, discover=discover_port_candidates,
                     defaults=read_manager_defaults, digest=_executable_digest, processes=_process_names,
                     system_proxy=_system_proxy, manager_json=_manager_json, proxy_request=_proxy_request,
                     desktop=_desktop, probe=probe_manager_ports, locale=_windows_locale, now=time.time, environ=None):
    """Return the checklist; every step is read-only and failures become plain-language items."""
    from src.core.release_trust import EXECUTABLE_SHA256
    environ = os.environ if environ is None else environ
    items = []
    add = items.append

    try:
        names = processes()
    except (OSError, subprocess.SubprocessError, ValueError):
        names = None
    if names is None:
        add(HealthItem('Clash（翻墙软件）', 'warn', '读不到正在运行的程序列表。', '确认 Clash 已经打开。'))
    elif any('clash' in name.casefold() or 'mihomo' in name.casefold() for name in names):
        add(HealthItem('Clash（翻墙软件）', 'ok', '正在运行。'))
    else:
        add(HealthItem('Clash（翻墙软件）', 'warn', '没找到正在运行的 Clash。',
                       '先打开 Clash，代理管理器要靠它连到 Bright Data。如果你用的是别的翻墙软件，可以忽略这一条。'))

    paths = running()
    executable, note = find_manager_executable(paths, environ)
    if paths == ():
        add(HealthItem('代理管理器在运行吗', 'fail', '没检测到正在运行的代理管理器。',
                       '双击打开代理管理器（Proxy Manager），等 1 分钟后再体检。它没有托盘图标，是在后台运行的。'))
    elif paths is None:
        add(HealthItem('代理管理器在运行吗', 'warn', '读不到它的运行状态。', '确认代理管理器已经打开后再体检。'))
    else:
        add(HealthItem('代理管理器在运行吗', 'ok', '正在后台运行。'))

    if not executable:
        add(HealthItem('代理管理器版本', 'fail', note or '没找到代理管理器的安装文件夹。', '安装 1.679.135 版代理管理器。'))
    else:
        try:
            right = digest(executable).lower() == EXECUTABLE_SHA256
        except OSError:
            right = None
        if right is None:
            add(HealthItem('代理管理器版本', 'warn', '读不到它的程序文件。', '确认程序没有被移动或删除。'))
        elif right:
            add(HealthItem('代理管理器版本', 'ok', '是 1.679.135，和助手核验用的版本一致。'))
        else:
            add(HealthItem('代理管理器版本', 'fail', '不是 1.679.135（可能自动升级过）。', '用 1.679.135 的安装包重新安装代理管理器。'))
        if data.manager_executable or data.manager_sha256:
            same_path = ntpath.normcase(ntpath.normpath(data.manager_executable)) == ntpath.normcase(ntpath.normpath(executable))
            if not same_path or (right is False):
                add(HealthItem('保存的管理器基准', 'fail', '助手里保存的程序路径或指纹，和这台电脑上的代理管理器对不上。',
                               '在首次配置向导里点“一键查找并填入”重新核验，然后保存。'))
            else:
                add(HealthItem('保存的管理器基准', 'ok', '和这台电脑上的代理管理器一致。'))
        else:
            add(HealthItem('保存的管理器基准', 'fail', '还没有核验并保存管理器基准，检测会一直卡在“监听归属未确认”。',
                           '在首次配置向导里点“一键查找并填入”，通过后点“保存本机配置”。'))

    candidates = discover()
    observed = candidates.ports if isinstance(candidates, PortCandidates) and candidates.status == 'observed' else ()
    www, default_port = defaults(executable) if executable else (None, None)
    manager_port = data.manager_port or www
    hidden = False
    if paths:
        observed, hidden = complete_ports(observed, manager_port, lambda port: manager_json(port, '/api/proxies_running'), probe)
    if hidden:
        add(HealthItem('系统端口列表', 'warn', '这台电脑的 Windows 端口列表里漏掉了代理管理器的（部分）端口，已改用直接连接逐个确认。',
                       '不影响使用，助手会自动用直接连接的方法核对。'))
    if not observed:
        add(HealthItem('代理管理器的端口', 'fail', '代理管理器没有在监听任何端口，助手和 Claude 都连不上它。',
                       '重启电脑，开机后只双击一次代理管理器，等 1 分钟再体检。'))
    elif manager_port not in observed:
        add(HealthItem('代理管理器的端口', 'fail', f'管理端口 {manager_port} 没在工作。',
                       '确认代理管理器正常打开；助手里的管理端口要和代理管理器的一致。'))
    else:
        add(HealthItem('代理管理器的端口', 'ok', f'管理端口 {manager_port} 正在工作。'))

    proxies = None
    if manager_port in observed:
        try:
            proxies = manager_json(manager_port, '/api/proxies_running')
            add(HealthItem('助手连得上代理管理器吗', 'ok', '管理接口有回应。'))
        except Exception:
            add(HealthItem('助手连得上代理管理器吗', 'fail', '管理接口没有回应。',
                           '重启代理管理器（实在不行就重启电脑），再用浏览器打开管理页面确认能打开。'))

    port = data.port
    if not port and proxies is not None:
        port = choose_ports(observed, proxies, data.expected_zone, manager_port, default_port)[1]
    zone_names = sorted({item.get('zone') for item in proxies or () if isinstance(item, dict) and isinstance(item.get('zone'), str)})
    if not port:
        add(HealthItem('代理端口', 'fail', '还不知道该用哪个代理端口。',
                       '在向导里填好区域名后点“一键查找并填入”；代理管理器里现有的代理名称：' + ('、'.join(zone_names) or '无') + '。'))
    elif port not in observed:
        add(HealthItem('代理端口', 'fail', f'代理端口 {port} 没在工作。', '在代理管理器里确认这个端口还在；没有就按图解第 6–7 步新建。'))
    else:
        entry = next((item for item in proxies or () if isinstance(item, dict) and item.get('port') == port), None)
        zone = entry.get('zone') if entry else None
        if proxies is not None and entry is None:
            add(HealthItem('代理端口', 'fail', f'端口 {port} 不是代理管理器里的代理端口。', '点“一键查找并填入”重新选端口。'))
        elif data.expected_zone and zone and zone != data.expected_zone.strip():
            add(HealthItem('代理端口', 'fail', f'端口 {port} 用的代理名称和你填的区域名不一样。',
                           '核对区域名是否照抄官网；代理管理器里现有的代理名称：' + '、'.join(zone_names) + '。'))
        else:
            add(HealthItem('代理端口', 'ok', f'端口 {port} 正在工作' + ('，代理名称和你填的一致。' if zone and data.expected_zone else '。')))
        if zone and proxies is not None:
            try:
                zones = manager_json(manager_port, '/api/zones').get('zones', [])
                plan = next((z.get('plan') or {} for z in zones if isinstance(z, dict) and z.get('name') == zone), None)
            except Exception:
                plan = None
            if plan is None:
                add(HealthItem('代理类型', 'warn', '读不到这个代理的类型。', '在 Bright Data 官网确认它是 ISP（固定 IP）类型。'))
            elif plan.get('disable'):
                add(HealthItem('代理类型', 'fail', '这个代理在 Bright Data 已被停用。', '到 Bright Data 官网检查账户和这个代理的状态。'))
            elif plan.get('type') == 'static_res' or (plan.get('type') == 'static' and plan.get('pool_ip_type') == 'static_res'):
                add(HealthItem('代理类型', 'ok', '是 ISP（固定 IP）类型。'))
            else:
                add(HealthItem('代理类型', 'fail', '不是 ISP（固定 IP）类型。', '在 Bright Data 官网新建 ISP 类型的代理。'))

    try:
        enabled, server, pac = system_proxy()
    except (OSError, ImportError):
        enabled, server, pac = None, '', False
    server_port = re.findall(r':(\d{1,5})\b', server)
    if enabled is None:
        add(HealthItem('Windows 系统代理', 'warn', '读不到系统代理设置。'))
    elif enabled and port and str(port) in server_port:
        add(HealthItem('Windows 系统代理', 'fail', f'系统代理被设成了代理管理器的端口 {port}：整台电脑都会走它，和 Clash 冲突。',
                       '打开 Windows 设置 → 网络和 Internet → 代理，把“使用代理服务器”改回 Clash 或关掉（请你自己改）。'))
    elif enabled:
        add(HealthItem('Windows 系统代理', 'ok', '已开启，指向端口 ' + ('、'.join(server_port) or '未识别') + '（一般是 Clash），不是代理管理器的端口。'))
    else:
        add(HealthItem('Windows 系统代理', 'ok', '没开' + ('（有自动配置脚本）' if pac else '') + '；Clash 用 TUN 模式时这是正常的。'))

    can_request = bool(port) and port in observed
    if not can_request:
        add(HealthItem('经代理上网', 'skip', '代理端口不可用，没有发请求。'))
        add(HealthItem('Claude 看到的 IP', 'skip', '代理端口不可用，没有发请求。'))
    else:
        url = data.ip_url.strip() or DEFAULT_IP_URL
        try:
            add(_compare('经代理上网', _parse_ip(proxy_request(port, url)), data.expected_ip.strip(), '出口检测服务'))
        except Exception:
            add(HealthItem('经代理上网', 'fail', f'经端口 {port} 连不上外网。',
                           '先确认 Clash 开着、能正常上网；再在代理管理器的“请求日志”里看有没有报错；Bright Data 账户余额是否充足。'))
        trace_ip = country = None
        try:
            trace_ip, stamp, country = _parse_trace(proxy_request(port, TRACE_URL, True))
            add(_compare('Claude 看到的 IP', trace_ip, data.expected_ip.strip(), 'Claude 检查页'))
            try:
                drift = abs(float(stamp) - now())
            except ValueError:
                drift = None
            if drift is None:
                add(HealthItem('电脑时间', 'warn', '没拿到 Claude 服务器的时间。'))
            elif drift > _CLOCK_LIMIT_SECONDS:
                add(HealthItem('电脑时间', 'fail', f'电脑时间和 Claude 服务器差了约 {int(drift // 60)} 分钟。',
                               '打开 Windows 设置 → 时间和语言，打开“自动设置时间”并点“立即同步”（请你自己改）。'))
            else:
                add(HealthItem('电脑时间', 'ok', '和 Claude 服务器时间一致（差 5 分钟以内）。'))
        except Exception:
            add(HealthItem('Claude 看到的 IP', 'fail', f'经端口 {port} 打不开 Claude 检查页。',
                           '先确认上一项能通；再在代理管理器的“请求日志”里看 claude.ai 的请求有没有报错。'))
        add(_three_exits(port, trace_ip, data.expected_ip.strip(), proxy_request))
        add(_locale_item(country, locale))

    try:
        apps, state = desktop()
    except Exception:
        apps, state = None, None
    if apps is None:
        add(HealthItem('Claude 桌面端', 'warn', '读不到桌面端的安装情况。', '在助手主窗口点“查找桌面端”试试。'))
    elif not apps:
        add(HealthItem('Claude 桌面端', 'fail', '没找到已安装的 Claude 桌面端。', '从 Claude 官网下载安装桌面端（装好先别打开）。'))
    elif state == 'fail':
        add(HealthItem('Claude 桌面端', 'warn', '已安装，但现在开着。', '启动前请在 Claude 里正常退出，不要强制结束。'))
    else:
        add(HealthItem('Claude 桌面端', 'ok', '已安装，现在没开着。'))
    return tuple(items)


def summary(items):
    problems = [item for item in items if item.status == 'fail']
    if not problems:
        warns = sum(1 for item in items if item.status == 'warn')
        return '体检完成：没发现会挡住启动的问题' + (f'，另有 {warns} 项需要留意。' if warns else '。')
    first = problems[0]
    return f'体检完成：发现 {len(problems)} 个问题。先处理“{first.name}”：{first.fix or first.detail}'


_RESTART_FIXES = {'代理管理器在运行吗', '代理管理器的端口', '助手连得上代理管理器吗'}


def repair_plan(items):
    """R45: which one-click repairs apply. A wrong Proxy Manager version is never 'repaired' by restarting."""
    failed = {item.name: item for item in items if item.status == 'fail'}
    plan = []
    port_dead = '代理端口' in failed and '没在工作' in failed['代理端口'].detail
    if (set(failed) & _RESTART_FIXES or port_dead) and '代理管理器版本' not in failed:
        plan.append('restart')
    if '保存的管理器基准' in failed:
        plan.append('reverify')
    return plan


def repair_manager(data, *, restart=restart_manager, running=running_manager_paths, discover=discover_port_candidates,
                   defaults=read_manager_defaults, probe=probe_manager_ports, manager_json=_manager_json):
    executable, _ = find_manager_executable(running())
    www = defaults(executable)[0] if executable else None
    manager_port = data.manager_port or www
    def ready():
        found = discover()
        ports = found.ports if isinstance(found, PortCandidates) and found.status == 'observed' else ()
        ports, _ = complete_ports(ports, manager_port, lambda port: manager_json(port, '/api/proxies_running'), probe)
        return manager_port in ports and (not data.port or data.port in ports)
    return restart(executable, ports_ready=ready)


_PLAN_TEXT = {
    'restart': ['确认 Claude 桌面端已经关闭（开着就停下，不会强制关闭 Claude）',
                '结束这台电脑上的代理管理器（只结束安装文件夹里那一个；直接结束不会触发“退出时安装新版本”）',
                '重新打开一次代理管理器，最多等 90 秒让端口恢复',
                '自动重新体检'],
    'reverify': ['打开首次配置向导，自动“一键查找并填入”并核验管理器基准；最后由你点“保存本机配置”'],
}


class HealthDialog:
    """Runs the check in a worker thread; the only change it can make is the confirmed one-click repair (R45)."""

    def __init__(self, root, data, check=run_health_check, repair=repair_manager, reverify=None, open_settings=None):
        import queue
        import threading
        import tkinter as tk
        from tkinter import ttk
        self._threading = threading
        self._queue, self._lock, self._closed = queue.Queue(), threading.Lock(), False
        self._data, self._check, self._repair, self._reverify = data, check, repair, reverify
        self._open_settings = open_settings or os.startfile
        self.items, self.plan = (), []
        self.window = tk.Toplevel(root)
        self.window.title('环境体检')
        self.window.geometry('780x600')
        frame = ttk.Frame(self.window, padding=12)
        frame.pack(fill='both', expand=True)
        self.status = tk.StringVar(value='')
        ttk.Label(frame, textvariable=self.status, wraplength=740).pack(anchor='w')
        actions = ttk.Frame(frame)
        actions.pack(side='bottom', fill='x', pady=(8, 0))
        self.repair_button = ttk.Button(actions, text='一键修复', command=self.repair, state='disabled', style='Accent.TButton')
        self.repair_button.pack(side='left')
        self.recheck_button = ttk.Button(actions, text='重新体检', command=self.run_check, state='disabled')
        self.recheck_button.pack(side='left', padx=(6, 0))
        self.copy_button = ttk.Button(actions, text='复制体检报告', command=self.copy, state='disabled')
        self.copy_button.pack(side='left', padx=(6, 0))
        self.zone_button = ttk.Button(actions, text='打开时区设置', state='disabled',
                                      command=lambda: self._settings('ms-settings:dateandtime'))
        self.zone_button.pack(side='left', padx=(6, 0))
        self.language_button = ttk.Button(actions, text='打开语言设置', state='disabled',
                                          command=lambda: self._settings('ms-settings:regionlanguage'))
        self.language_button.pack(side='left', padx=(6, 0))
        ttk.Button(actions, text='关闭', command=self.window.destroy).pack(side='right')
        self.text = tk.Text(frame, wrap='word', height=20, state='disabled')
        self.text.pack(fill='both', expand=True, pady=(8, 0))
        self.busy = False
        self._poll_id = self.window.after(50, self._poll)
        self.window.bind('<Destroy>', self._destroy, add='+')
        self.run_check()

    def _set_buttons(self):
        idle = not self.busy
        self.repair_button.configure(state='normal' if idle and self.plan else 'disabled')
        for button in (self.recheck_button, self.copy_button):
            button.configure(state='normal' if idle and self.items else 'disabled')
        locale_warn = any(item.name == '时区和语言' and item.status == 'warn' for item in self.items)
        for button in (self.zone_button, self.language_button):
            button.configure(state='normal' if locale_warn else 'disabled')

    def _start(self, kind, work):
        self.busy = True
        self._set_buttons()
        def run():
            try:
                result = work()
            except Exception:
                result = None
            with self._lock:
                if not self._closed:
                    self._queue.put((kind, result))
        self._threading.Thread(target=run, daemon=True).start()

    def run_check(self):
        if self.busy:
            return
        self.status.set('正在逐项检查代理管理器、端口、Clash、系统代理、三个出口、Claude 检查页、时间、时区语言和桌面端，约 10–40 秒。')
        self._start('check', lambda: self._check(self._data))

    def repair(self):
        from tkinter import messagebox
        if self.busy or not self.plan:
            return
        steps = [step for kind in self.plan for step in _PLAN_TEXT[kind]]
        text = '一键修复会按顺序做这些事：\n\n' + '\n'.join(f'{n}. {step}' for n, step in enumerate(steps, 1)) + '\n\n继续吗？'
        if not messagebox.askokcancel('一键修复', text, parent=self.window):
            return
        if 'restart' in self.plan:
            self.status.set('正在重启代理管理器，最多约 2 分钟，请不要关闭这个窗口。')
            self._start('repair', lambda: self._repair(self._data))
        else:
            self._after_repair()

    def _after_repair(self):
        if 'reverify' in self.plan and self._reverify is not None:
            self._reverify()

    def _settings(self, uri):
        try:
            self._open_settings(uri)
        except OSError:
            self.status.set('打不开设置页面，请手动打开 Windows 设置 → 时间和语言。')

    def _poll(self):
        import queue
        try:
            kind, result = self._queue.get_nowait()
        except queue.Empty:
            self._poll_id = self.window.after(50, self._poll)
            return
        self.busy = False
        if kind == 'check':
            items = result or (HealthItem('体检', 'fail', '体检过程中出错。', '点“重新体检”再试一次。'),)
            self.items, self.plan = items, repair_plan(items)
            self.status.set(summary(items) + ('  可以点“一键修复”。' if self.plan else ''))
            self.text.configure(state='normal')
            self.text.delete('1.0', 'end')
            self.text.insert('1.0', report(items))
            self.text.configure(state='disabled')
            self._set_buttons()
        else:
            ok, message = result if result else (False, '修复过程中出错，没有完成。')
            self.status.set(message)
            self._set_buttons()
            if ok:
                self._after_repair()
                self.run_check()
        self._poll_id = self.window.after(50, self._poll)

    def copy(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.text.get('1.0', 'end').strip())
        self.status.set('已复制体检报告，可以直接发出去（IP 已打码，不含路径）。')

    def _destroy(self, event):
        if event.widget is self.window:
            with self._lock:
                self._closed = True
            self.window.after_cancel(self._poll_id)


def report(items, when=None):
    when = when or datetime.now()
    lines = ['Claude 检测助手 · 环境体检报告', '体检时间：' + when.strftime('%Y-%m-%d %H:%M:%S'),
             '说明：只查看、不修改；IP 已打码，不含路径和指纹。', '', summary(items), '']
    for item in items:
        line = f'[{LABELS.get(item.status, item.status)}] {item.name}：{item.detail}'
        if item.fix and item.status in ('fail', 'warn'):
            line += '\n      怎么办：' + item.fix
        lines.append(line)
    return '\n'.join(lines)
