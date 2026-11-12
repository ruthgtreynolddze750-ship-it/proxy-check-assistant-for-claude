"""代理与桌面启动接口；所有实际检测只在调用时执行。"""
from __future__ import annotations

import csv
import hashlib
import http.client
import ipaddress
import json
import math
import ntpath
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class Config:
    proxy_port: int
    manager_port: int
    expected_ip: str = field(repr=False)
    ip_url: str = field(repr=False)
    timeout: float = 5.0
    expected_zone: str = field(default='', repr=False)
    required_reverse_mappings: tuple[str, ...] = field(default=(), repr=False)
    mapping_mode: str = 'unknown'
    manager_executable: str = field(default='', repr=False)
    manager_sha256: str = field(default='', repr=False)


@dataclass(frozen=True)
class Check:
    status: str
    message: str


@dataclass(frozen=True)
class Detection:
    manager: Check
    port: Check
    exit_ip: Check
    claude: Check
    desktop_egress: Check
    mapping: Check = field(default_factory=lambda: Check('unknown', '目标映射尚未确认'))
    observed_ip: str | None = field(default=None, repr=False)
    _owner_evidence: object = field(default=None, repr=False, compare=False)
    target_trace: Check = field(default_factory=lambda: Check('unknown', 'Claude 目标请求出口未确认'))

    @property
    def ready(self):
        return self._owner_evidence is not None and all(c.status == 'pass' for c in (self.manager, self.port, self.exit_ip, self.target_trace, self.mapping))

    def report(self, *, include_full_ip=False):
        result = {name: {'status': check.status, 'message': check.message}
                  for name in ('manager', 'port', 'exit_ip', 'claude', 'target_trace', 'desktop_egress', 'mapping')
                  for check in (getattr(self, name),)}
        if self.observed_ip is None:
            result['observed_ip'] = None
        elif include_full_ip is True:
            result['observed_ip'] = self.observed_ip
        else:
            address = ipaddress.ip_address(self.observed_ip)
            result['observed_ip'] = ('.'.join(str(address).split('.')[:2]) + '.*.*' if address.version == 4
                                     else ':'.join(address.exploded.split(':')[:2]) + ':*')
        return result


@dataclass(frozen=True)
class LaunchResult:
    status: str
    message: str
    detection: Detection | None = None
    pid: int | None = None


class ProxyHTTPError(OSError):
    def __init__(self, status):
        super().__init__('HTTP response not accepted')
        self.status = status


class DetectionCancelled(OSError):
    pass


_REQUEST_SCOPE = threading.local()


@dataclass(frozen=True)
class DetectionStep:
    stage: str
    status: str
    elapsed_seconds: float
    error_code: str = ''


def detection_error_code(error):
    # Never retain exception text, URLs, paths, response bodies or credentials.
    if isinstance(error, DetectionCancelled):
        return 'cancelled_or_deadline'
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'timeout'
    if isinstance(error, ProxyHTTPError):
        return 'http_status'
    if isinstance(error, http.client.HTTPException):
        return 'http_protocol'
    if isinstance(error, UnicodeError):
        return 'encoding'
    if isinstance(error, subprocess.SubprocessError):
        return 'process_query'
    if isinstance(error, OSError):
        return 'os_error'
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return 'invalid_data'
    return 'unexpected_error'


def _note_detection_error(error):
    steps = getattr(_REQUEST_SCOPE, 'steps', None)
    index = getattr(_REQUEST_SCOPE, 'step_index', None)
    if steps is not None and index is not None:
        old = steps[index]
        steps[index] = DetectionStep(old.stage, old.status, old.elapsed_seconds, detection_error_code(error))


def _detection_step(stage, call):
    steps = getattr(_REQUEST_SCOPE, 'steps', None)
    if steps is None:
        return call()
    started = time.monotonic()
    previous = getattr(_REQUEST_SCOPE, 'step_index', None)
    index = len(steps)
    steps.append(DetectionStep(stage, 'running', 0.0))
    _REQUEST_SCOPE.step_index = index
    status = 'error'
    try:
        value = call()
        status = value.status if isinstance(value, Check) else ('unknown' if value is None else 'completed')
        return value
    except BaseException as error:
        _note_detection_error(error)
        raise
    finally:
        steps[index] = DetectionStep(stage, status, max(0.0, time.monotonic()-started), steps[index].error_code)
        _REQUEST_SCOPE.step_index = previous


def _remaining_timeout(seconds):
    scope = getattr(_REQUEST_SCOPE, 'value', None)
    if scope is None:
        return seconds
    deadline, cancelled = scope
    remaining = deadline - time.monotonic()
    if remaining <= 0 or cancelled.is_set():
        raise DetectionCancelled('detection_cancelled_or_expired')
    return min(seconds, remaining)


def _url_parts(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)):
        raise ValueError('invalid URL')
    if parsed.hostname.lower() == 'localhost':
        raise ValueError('local endpoint')
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('IP literal endpoint')
    return parsed


def _request_via_proxy(port, url, timeout, *, allow_same_host_redirects=False):
    original = _url_parts(url)
    for hop in range(4):
        parsed = _url_parts(url)
        connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=_remaining_timeout(timeout),
                                                 context=ssl.create_default_context())
        try:
            connection.set_tunnel(parsed.hostname, 443)
            target = parsed.path or '/'
            if parsed.query:
                target += '?' + parsed.query
            connection.request('GET', target, headers={'Accept': 'application/json, text/plain, */*'})
            response = connection.getresponse()
            if 200 <= response.status < 300:
                return response.read(4097)
            if response.status not in (301, 302, 303, 307, 308) or not allow_same_host_redirects or hop == 3:
                raise ProxyHTTPError(response.status)
            location = response.getheader('Location')
            if not location:
                raise OSError('redirect has no location')
            url = urljoin(url, location)
            redirected = _url_parts(url)
            if redirected.hostname.lower() != original.hostname.lower():
                raise OSError('redirect host not permitted')
        finally:
            connection.close()
    raise OSError('too many redirects')


def _process_present(image):
    result = subprocess.run(['tasklist', '/fo', 'csv', '/nh'], capture_output=True,
                            text=True, errors='replace', timeout=_remaining_timeout(5), check=True)
    return any(row and row[0].casefold() == image.casefold()
               for row in csv.reader(result.stdout.splitlines()))


# R44: some Windows builds leave a working listener out of the listen table. Only then connect once
# (TCP handshake only, no data) and use the owner of the accepted server-side socket instead.
_PORT_ROWS_PS = (
    "function rows([int]$port) { $r = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue "
    "| Where-Object { $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::') }); "
    "if ($r.Count -eq 0) { $c = New-Object Net.Sockets.TcpClient; "
    "try { $c.Connect('127.0.0.1', $port); $local = $c.Client.LocalEndPoint.Port; "
    "for ($i = 0; $i -lt 5 -and $r.Count -eq 0; $i++) { "
    "$r = @(Get-NetTCPConnection -LocalPort $port -RemotePort $local -ErrorAction SilentlyContinue); "
    "if ($r.Count -eq 0) { Start-Sleep -Milliseconds 100 } } } catch { $r = @() } finally { $c.Close() } }; $r }; ")


def _manager_owns_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid port')
    script = (_PORT_ROWS_PS + f"$p = {port}; "
              "$c = @(rows $p); "
              "$found = $false; $safe = $true; foreach ($x in $c) { "
              "if ($x.LocalAddress -ne '127.0.0.1' -and $x.LocalAddress -ne '0.0.0.0') { continue }; "
              "$owner = Get-Process -Id $x.OwningProcess -ErrorAction Stop; "
              "if ($owner.ProcessName -eq 'Proxy Manager') { $found = $true } else { $safe = $false } }; "
              "if ($found -and $safe) { 'yes' } else { 'no' }")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                             script], capture_output=True, text=True,
                            errors='replace', timeout=_remaining_timeout(8), check=True)
    return result.stdout.strip() == 'yes'


def _manager(port, timeout):
    try:
        if not _process_present('Proxy Manager.exe'):
            return Check('unknown', '未识别到 Proxy Manager 进程，请确认安装方式')
        if not _manager_owns_port(port):
            return Check('unknown', '管理端口与 Proxy Manager 进程的关联未确认')
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=_remaining_timeout(timeout))
        try:
            conn.request('GET', '/')
            response = conn.getresponse()
            response.read(4096)
            if not 200 <= response.status < 400:
                return Check('unknown', '管理接口未确认')
        finally:
            conn.close()
        return Check('pass', 'Proxy Manager 进程监听管理端口且接口有响应')
    except (OSError, subprocess.SubprocessError, http.client.HTTPException) as error:
        _note_detection_error(error)
        return Check('unknown', '管理进程或接口无法确认')


def _port(port, timeout):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=_remaining_timeout(timeout)):
            return Check('pass', '本地代理端口可连接')
    except OSError as error:
        _note_detection_error(error)
        return Check('fail', '本地代理端口不可连接')


def _capture_listener_owners(manager_port, proxy_port):
    if (type(manager_port) is not int or type(proxy_port) is not int
            or not 1 <= manager_port <= 65535 or not 1 <= proxy_port <= 65535
            or manager_port == proxy_port):
        raise ValueError('invalid listener ports')
    script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
              + _PORT_ROWS_PS +
              "function listeners([int]$port) { @(rows $port | ForEach-Object { "
              "$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$_.OwningProcess) -ErrorAction Stop; "
              "if (!$p -or !$p.ExecutablePath -or !$p.CreationDate) { throw 'process unavailable' }; "
              "[PSCustomObject]@{pid=[int]$p.ProcessId; started=[string]$p.CreationDate.ToUniversalTime().Ticks; path=$p.ExecutablePath} }) }; "
              f"[PSCustomObject]@{{manager=@(listeners {manager_port}); proxy=@(listeners {proxy_port})}} "
              "| ConvertTo-Json -Depth 4 -Compress")
    output = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, encoding='utf-8', errors='strict',
                            timeout=_remaining_timeout(12), check=True)
    data = json.loads(output.stdout)
    if not isinstance(data, dict) or not isinstance(data.get('manager'), list) or not isinstance(data.get('proxy'), list):
        raise ValueError('invalid listener snapshot')
    return data['manager'], data['proxy']


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _proxy_owner_snapshot(config):
    try:
        if (not isinstance(config.manager_executable, str) or not ntpath.isabs(config.manager_executable)
                or not isinstance(config.manager_sha256, str)
                or not re.fullmatch(r'[0-9a-fA-F]{64}', config.manager_sha256)):
            return None
        managers, proxies = _capture_listener_owners(config.manager_port, config.proxy_port)
        def identity(rows):
            identities = set()
            for row in rows:
                if (not isinstance(row, dict) or type(row.get('pid')) is not int or row['pid'] <= 0
                        or not isinstance(row.get('started'), str) or not row['started'].isdigit()
                        or not isinstance(row.get('path'), str) or not ntpath.isabs(row['path'])):
                    return None
                path = ntpath.normcase(ntpath.normpath(os.path.realpath(row['path'])))
                identities.add((row['pid'], row['started'], path))
            return next(iter(identities)) if len(identities) == 1 else None
        manager = identity(managers)
        proxy = identity(proxies)
        expected_path = ntpath.normcase(ntpath.normpath(os.path.realpath(config.manager_executable)))
        if manager is None or manager != proxy or manager[2] != expected_path:
            return None
        if _file_sha256(config.manager_executable).lower() != config.manager_sha256.lower():
            return None
        return (config.manager_port, config.proxy_port, *manager, config.manager_sha256.lower())
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, UnicodeError) as error:
        _note_detection_error(error)
        return None


def _fetch_manager_json(port, path, timeout):
    if path not in ('/api/proxies_running', '/api/zones'):
        raise ValueError('unsupported local endpoint')
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=_remaining_timeout(timeout))
    try:
        conn.request('GET', path, headers={'Accept': 'application/json'})
        response = conn.getresponse()
        if response.status != 200:
            raise OSError('management endpoint unavailable')
        payload = response.read(2097153)
        if len(payload) > 2097152:
            raise ValueError('management response too large')
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate management response key')
                result[key] = value
            return result
        data = json.loads(payload, object_pairs_hook=unique_object)
        if path == '/api/proxies_running':
            if not isinstance(data, list):
                raise ValueError('unexpected management response')
            keys = ('port', 'zone', 'reverse_lookup_values', 'reverse_lookup_dns')
            result = []
            for item in data:
                if not isinstance(item, dict):
                    raise ValueError('invalid proxy entry')
                clean = {k: item[k] for k in keys if k in item}
                clean['reverse_lookup_file'] = bool(item.get('reverse_lookup_file'))
                clean['ext_proxies'] = bool(item.get('ext_proxies'))
                result.append(clean)
            return result
        if not isinstance(data, dict) or not isinstance(data.get('zones'), list):
            raise ValueError('unexpected zones response')
        zones = []
        for zone in data['zones']:
            if not isinstance(zone, dict):
                raise ValueError('invalid zone entry')
            plan = zone.get('plan')
            if not isinstance(plan, dict):
                plan = {}
            zones.append({'name': zone.get('name'), 'plan': {k: plan[k] for k in ('type', 'pool_ip_type', 'disable') if k in plan}})
        return {'zones': zones}
    finally:
        conn.close()


def _mapping_pair(value):
    if not isinstance(value, str):
        raise ValueError('invalid mapping')
    parts = value.split()
    if len(parts) != 2:
        raise ValueError('invalid mapping')
    address = str(ipaddress.IPv4Address(parts[0]))
    host = parts[1].lower().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) or '..' in host:
        raise ValueError('invalid hostname')
    return address, host


def _mapping(config):
    unknown = Check('unknown', '目标映射、区域或 ISP 类型未确认')
    try:
        if (config.mapping_mode not in ('required', 'not_required')
                or not isinstance(config.expected_zone, str) or not config.expected_zone.strip()
                or config.expected_zone != config.expected_zone.strip()
                or not isinstance(config.required_reverse_mappings, tuple)):
            return unknown
        wanted = set()
        if config.mapping_mode == 'required':
            if not config.required_reverse_mappings:
                return unknown
            wanted = {_mapping_pair(item) for item in config.required_reverse_mappings}
            if len({pair[0] for pair in wanted}) != len(wanted):
                return unknown
        if not _manager_owns_port(config.manager_port):
            return unknown
        proxies = _fetch_manager_json(config.manager_port, '/api/proxies_running', config.timeout)
        zones = _fetch_manager_json(config.manager_port, '/api/zones', config.timeout)
        matched = [p for p in proxies if p.get('port') == config.proxy_port]
        if len(matched) != 1:
            return unknown
        proxy = matched[0]
        if proxy.get('zone') != config.expected_zone:
            return Check('fail', '代理端口区域与预期不一致') if proxy.get('zone') else unknown
        if proxy.get('ext_proxies'):
            return unknown
        matching_zones = [z for z in zones.get('zones', []) if z.get('name') == config.expected_zone]
        if len(matching_zones) != 1 or not isinstance(matching_zones[0].get('plan'), dict):
            return unknown
        plan = matching_zones[0]['plan']
        if 'disable' in plan and not isinstance(plan['disable'], bool):
            return unknown
        if plan.get('disable'):
            return Check('fail', '代理区域已禁用')
        plan_type = plan.get('type')
        is_isp = plan_type == 'static_res' or (plan_type == 'static' and plan.get('pool_ip_type') == 'static_res')
        if not is_isp and plan_type in ('resident', 'mobile', 'unblocker', 'serp'):
            return Check('fail', '代理区域类型与 ISP 不一致')
        if not is_isp:
            return unknown
        if config.mapping_mode == 'not_required':
            return Check('pass', '运行端口及 ISP 区域匹配；用户选择不依赖特定映射')
        if proxy.get('reverse_lookup_dns') or proxy.get('reverse_lookup_file'):
            return unknown
        values = proxy.get('reverse_lookup_values')
        if not isinstance(values, list) or not values:
            return unknown
        pairs = [_mapping_pair(item) for item in values]
        if len({item[0] for item in pairs}) != len(pairs):
            return unknown
        if not wanted.issubset(set(pairs)):
            return Check('fail', '代理目标映射与预期不一致')
        return Check('pass', '运行端口对应 ISP 区域与指定映射配置一致')
    except (OSError, subprocess.SubprocessError, http.client.HTTPException, ValueError, TypeError, KeyError, UnicodeError) as error:
        _note_detection_error(error)
        return unknown


def _desktop_snapshot():
    script = r'''$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$packages = @(Get-AppxPackage -Name 'Claude' | ForEach-Object {
  $pkg = $_
  $manifest = Get-AppxPackageManifest -Package $pkg.PackageFullName
  foreach ($app in $manifest.Package.Applications.Application) {
    if ($app.Id -eq 'Claude' -and $app.Executable) {
      [PSCustomObject]@{aumid=($pkg.PackageFamilyName + '!' + $app.Id); executable=(Join-Path $pkg.InstallLocation $app.Executable)}
    }
  }
})
$processes = @(Get-CimInstance Win32_Process -Filter "Name='claude.exe'" | ForEach-Object {
  $path = $_.ExecutablePath
  $product = $null
  if ($path) { try { $product = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo.ProductName } catch {} }
  [PSCustomObject]@{path=$path; product=$product}
})
[PSCustomObject]@{packages=$packages; processes=$processes} | ConvertTo-Json -Depth 4 -Compress'''
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, encoding='utf-8', errors='strict',
                            timeout=15, check=True)
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not isinstance(data.get('packages'), list) or not isinstance(data.get('processes'), list):
        raise ValueError('invalid process snapshot')
    return data['packages'], data['processes']


def discover_desktop():
    """返回本机已注册的 Claude 桌面应用 ID；失败时抛出不含底层详情的 OSError。"""
    try:
        packages, _ = _desktop_snapshot()
        return tuple(item['aumid'] for item in packages if item.get('aumid') and item.get('executable'))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, UnicodeError):
        raise OSError('无法确认已注册的 Claude 桌面应用') from None


def _claude_running():
    try:
        packages, processes = _desktop_snapshot()
        desktop_paths = {ntpath.normcase(ntpath.normpath(p['executable'])) for p in packages if p.get('aumid') and p.get('executable')}
        if not desktop_paths:
            return Check('unknown', '未确认已注册的 Claude 桌面应用')
        profile = os.environ.get('USERPROFILE')
        cli_path = ntpath.normcase(ntpath.join(profile, '.local', 'bin', 'claude.exe')) if profile else None
        unrecognized = False
        for process in processes:
            path = process.get('path')
            if not path:
                unrecognized = True
                continue
            normalized = ntpath.normcase(ntpath.normpath(path))
            if normalized in desktop_paths:
                return Check('fail', '已有 Claude 桌面进程，请手动正常退出后重试')
            if normalized == cli_path and process.get('product') == 'Claude Code':
                continue
            unrecognized = True
        if unrecognized:
            return Check('unknown', '存在身份未确认的同名进程')
        return Check('pass', '未发现 Claude 桌面进程')
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, UnicodeError):
        return Check('unknown', '无法确认 Claude 进程状态')


def desktop_status():
    """只读检查桌面版是否运行；不启动或结束进程。"""
    return _claude_running()


def _inspect_claude_trace_request(config, errors=None):
    unknown = Check('unknown', 'Claude trace 请求未确认')
    try:
        expected = ipaddress.ip_address(config.expected_ip)
        trace = _request_via_proxy(config.proxy_port, 'https://claude.ai/cdn-cgi/trace', config.timeout, allow_same_host_redirects=True)
        if len(trace) > 4096:
            return unknown
        fields = {}
        for line in trace.decode('utf-8', errors='strict').splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in ('h', 'ip'):
                if key in fields:
                    return unknown
                fields[key] = value.strip()
        if fields.get('h', '').lower() != 'claude.ai':
            return unknown
        trace_ip = ipaddress.ip_address(fields.get('ip', ''))
        return (Check('pass', 'Claude trace 请求可达且出口与预期一致') if trace_ip == expected
                else Check('fail', 'Claude trace 请求出口与预期不一致'))
    except (OSError, ValueError, TypeError, UnicodeError, http.client.HTTPException) as error:
        _note_detection_error(error)
        if errors is not None:
            errors.append(detection_error_code(error))
        return unknown


def inspect_claude_trace(config):
    """独立检查 Claude trace 请求，结果不替代首页或桌面应用验证。"""
    unknown = Check('unknown', 'Claude trace 请求未确认')
    before = _proxy_owner_snapshot(config)
    if before is None:
        return unknown
    result = _inspect_claude_trace_request(config)
    if _proxy_owner_snapshot(config) != before:
        return unknown
    return result


def detect(config, *, deadline=None, cancelled=None, diagnostics=None, reference_home=True, retry_exit_ip=False,
           retry_target_trace=False):
    if deadline is None and cancelled is None:
        if diagnostics is not None:
            raise ValueError('diagnostics require a bounded detection scope')
        return _detect(config, reference_home, retry_exit_ip, retry_target_trace)
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not isinstance(cancelled, threading.Event)
            or (diagnostics is not None and (type(diagnostics) is not list or diagnostics))):
        raise ValueError('invalid detection cancellation scope')
    previous = getattr(_REQUEST_SCOPE, 'value', None)
    previous_steps = getattr(_REQUEST_SCOPE, 'steps', None)
    previous_index = getattr(_REQUEST_SCOPE, 'step_index', None)
    _REQUEST_SCOPE.value = (deadline, cancelled)
    _REQUEST_SCOPE.steps, _REQUEST_SCOPE.step_index = diagnostics, None
    try:
        _remaining_timeout(1)
        result = _detect(config, reference_home, retry_exit_ip, retry_target_trace)
        _remaining_timeout(1)
        return result
    finally:
        _REQUEST_SCOPE.value = previous
        _REQUEST_SCOPE.steps, _REQUEST_SCOPE.step_index = previous_steps, previous_index


_EXIT_RETRY_MIN_REMAINING_SECONDS = 10


def _detect(config, reference_home=True, retry_exit_ip=False, retry_target_trace=False):
    unknown = Check('unknown', '尚未检测')
    desktop = Check('unknown', '独立代理请求不证明桌面进程实际出口或阻止直连')
    try:
        if (type(config.proxy_port) is not int or type(config.manager_port) is not int
                or not 1 <= config.proxy_port <= 65535 or not 1 <= config.manager_port <= 65535
                or not 0 < config.timeout <= 30):
            raise ValueError('invalid settings')
        expected = ipaddress.ip_address(config.expected_ip)
        _url_parts(config.ip_url)
    except (ValueError, TypeError):
        bad = Check('fail', '配置无效：检查端口、预期 IP 和 HTTPS 检测地址')
        return Detection(bad, unknown, unknown, unknown, desktop)
    _remaining_timeout(1)
    owner_before = _detection_step('owner_before', lambda: _proxy_owner_snapshot(config))
    if owner_before is None:
        unverified = Check('unknown', '代理监听进程或可信程序身份未确认')
        return Detection(unknown, unverified, unknown, unknown, desktop)
    _remaining_timeout(1)
    manager = _detection_step('manager', lambda: _manager(config.manager_port, config.timeout))
    _remaining_timeout(1)
    port = _detection_step('proxy_port', lambda: _port(config.proxy_port, config.timeout))
    if port.status != 'pass':
        return Detection(manager, port, unknown, unknown, desktop)
    exit_ip = unknown
    claude = unknown
    observed_ip = None
    try:
        request = lambda: _request_via_proxy(config.proxy_port, config.ip_url, config.timeout)
        try:
            body = _detection_step('exit_ip', request)
        except OSError as error:
            # R29: one retry for a connection-class error, leaving time for the remaining required checks.
            if (not retry_exit_ip or detection_error_code(error) != 'os_error'
                    or _remaining_timeout(_EXIT_RETRY_MIN_REMAINING_SECONDS) < _EXIT_RETRY_MIN_REMAINING_SECONDS):
                raise
            body = _detection_step('exit_ip', request)
        if len(body) > 4096:
            raise ValueError('oversize')
        raw = body.decode('utf-8').strip()
        try:
            payload = json.loads(raw)
            raw = payload.get('ip') if isinstance(payload, dict) else payload
        except json.JSONDecodeError:
            pass
        actual = ipaddress.ip_address(raw)
        observed_ip = str(actual)
        exit_ip = Check('pass', '代理测试请求的出口 IP 与预期一致') if actual == expected else Check('fail', '代理测试请求的出口 IP 与预期不一致')
    except (OSError, ValueError, TypeError, UnicodeError, http.client.HTTPException):
        exit_ip = Check('unknown', '代理出口检测未确认')
    if not reference_home:
        # R28: the reference-only home request is not repeated during continuous monitoring.
        claude = Check('unknown', '持续监测中不请求 Claude 首页（参考项）')
    else:
        try:
            _detection_step('claude_home', lambda: _request_via_proxy(config.proxy_port, 'https://claude.ai/', config.timeout, allow_same_host_redirects=True))
            claude = Check('pass', '通过代理连接 Claude 测试地址成功')
        except ProxyHTTPError as error:
            claude = Check('unknown', f'Claude 首页返回 HTTP {error.status}，服务未确认')
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            claude = Check('unknown', '通过代理连接 Claude 未确认')
    _remaining_timeout(1)
    trace_errors = []
    target_trace = _detection_step('target_trace', lambda: _inspect_claude_trace_request(config, trace_errors))
    # One retry for a connection-class error or timeout during monitoring, under the same R29 time floor.
    if (retry_target_trace and trace_errors and trace_errors[-1] in ('os_error', 'timeout')
            and _remaining_timeout(_EXIT_RETRY_MIN_REMAINING_SECONDS) >= _EXIT_RETRY_MIN_REMAINING_SECONDS):
        target_trace = _detection_step('target_trace', lambda: _inspect_claude_trace_request(config))
    _remaining_timeout(1)
    mapping = _detection_step('mapping', lambda: _mapping(config)) if manager.status == 'pass' else unknown
    _remaining_timeout(1)
    owner_after = _detection_step('owner_after', lambda: _proxy_owner_snapshot(config))
    if owner_after != owner_before or owner_after is None:
        changed = Check('unknown', '代理监听归属发生变化或无法确认')
        return Detection(changed, changed, unknown, unknown, desktop, mapping=unknown)
    return Detection(manager, port, exit_ip, claude, desktop, mapping=mapping, observed_ip=observed_ip,
                     _owner_evidence=owner_after, target_trace=target_trace)


def _activate_application(app_user_model_id, arguments):
    import ctypes
    import uuid

    class GUID(ctypes.Structure):
        _fields_ = [('data', ctypes.c_ubyte * 16)]

    def guid(value):
        return GUID((ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(value).bytes_le))

    ole32 = ctypes.OleDLL('ole32')
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoCreateInstance.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_uint32,
                                       ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
    ole32.CoCreateInstance.restype = ctypes.c_long
    hr = ole32.CoInitializeEx(None, 2)
    if hr < 0:
        raise OSError('COM initialization failed')
    obj = ctypes.c_void_p()
    try:
        clsid = guid('45ba127d-10a8-46ea-8ab7-56ea9078943c')
        iid = guid('2e941141-7f97-4756-ba1d-9decde894a3d')
        hr = ole32.CoCreateInstance(ctypes.byref(clsid), None, 4, ctypes.byref(iid), ctypes.byref(obj))
        if hr < 0 or not obj.value:
            raise OSError('application activation manager unavailable')
        table = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        call = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_wchar_p,
                                  ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))(table[3])
        pid = ctypes.c_uint32()
        hr = call(obj, app_user_model_id, arguments, 0, ctypes.byref(pid))
        if hr < 0 or not pid.value:
            raise OSError('application activation failed')
        return pid.value
    finally:
        if obj.value:
            table = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(table[2])(obj)
        ole32.CoUninitialize()


def launch_desktop(config, app_user_model_id):
    process = _claude_running()
    if process.status != 'pass':
        return LaunchResult(process.status, process.message)
    try:
        if not isinstance(app_user_model_id, str) or app_user_model_id not in discover_desktop():
            return LaunchResult('unknown', '请选择本机已注册的 Claude 桌面应用')
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, UnicodeError):
        return LaunchResult('unknown', '无法确认已注册的 Claude 桌面应用')
    result = detect(config)
    if not result.ready:
        return LaunchResult('fail', '启动前检测未全部通过', result)
    process = _claude_running()
    if process.status != 'pass':
        return LaunchResult(process.status, process.message, result)
    try:
        if app_user_model_id not in discover_desktop():
            return LaunchResult('unknown', 'Claude 桌面应用注册状态发生变化', result)
        if _proxy_owner_snapshot(config) != result._owner_evidence:
            return LaunchResult('unknown', '启动前代理监听归属发生变化或无法确认', result)
        pid = _activate_application(app_user_model_id, f'--proxy-server=http://127.0.0.1:{config.proxy_port}')
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, UnicodeError):
        return LaunchResult('unknown', '无法确认应用激活结果或注册状态', result)
    return LaunchResult('unknown', '已发起应用激活；参数生效、代理连接和桌面实际出口尚未确认', result, pid)
