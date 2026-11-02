"""Read-only, point-in-time desktop TCP observation; not an egress guarantee."""
from __future__ import annotations

import ctypes
import ipaddress
import json
import ntpath
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .backend import Config, _desktop_snapshot, _proxy_owner_snapshot


@dataclass(frozen=True)
class DesktopRuntimeObservation:
    status: str
    sampled_at: datetime
    identity_confirmed: bool
    proxy_connections: int | None
    other_tcp_connections: int | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class _Process:
    pid: int
    parent_pid: int
    started: str
    path: str | None = field(repr=False)
    name: str | None = field(repr=False)


@dataclass(frozen=True)
class _Tcp:
    pid: int
    remote_address: str = field(repr=False)
    remote_port: int


def _run_json(script):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, encoding='utf-8', errors='strict',
                            timeout=20, check=True)
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise ValueError('invalid local snapshot')
    return value


def _capture_processes():
    script = r'''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$items = @(Get-CimInstance Win32_Process | ForEach-Object {
  [PSCustomObject]@{pid=[int]$_.ProcessId; parent=[int]$_.ParentProcessId;
    started=if ($_.CreationDate) { [string]$_.CreationDate.ToUniversalTime().Ticks } else { $null };
    path=$_.ExecutablePath; name=$_.Name}
})
ConvertTo-Json -InputObject $items -Depth 3 -Compress'''
    return [_Process(row['pid'], row['parent'], row['started'], row['path'], row['name'])
            for row in _run_json(script)]


def _capture_tcp():
    script = r'''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$items = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
  [PSCustomObject]@{pid=[int]$_.OwningProcess; address=$_.RemoteAddress; port=[int]$_.RemotePort}
})
ConvertTo-Json -InputObject $items -Depth 3 -Compress'''
    return [_Tcp(row['pid'], row['address'], row['port']) for row in _run_json(script)]


def _package_family(pid):
    if os.name != 'nt':
        return None
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetPackageFamilyName.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
    kernel.GetPackageFamilyName.restype = wintypes.LONG
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.UINT(0)
        if kernel.GetPackageFamilyName(handle, ctypes.byref(size), None) != 122 or not 1 <= size.value <= 256:
            return None
        value = ctypes.create_unicode_buffer(size.value)
        if kernel.GetPackageFamilyName(handle, ctypes.byref(size), value) != 0:
            return None
        return value.value or None
    finally:
        kernel.CloseHandle(handle)


def _path(value):
    if not isinstance(value, str) or not ntpath.isabs(value):
        return None
    return ntpath.normcase(ntpath.normpath(value))


def _select_processes(rows, executable, family):
    if not isinstance(rows, list):
        return None, 'runtime_check_unavailable'
    index = {}
    for row in rows:
        if (not isinstance(row, _Process) or type(row.pid) is not int or row.pid < 0
                or type(row.parent_pid) is not int or row.parent_pid < 0 or row.pid in index):
            return None, 'process_identity_unconfirmed'
        index[row.pid] = row
    exe = _path(executable)
    if exe is None:
        return None, 'app_identity_unconfirmed'
    basename = ntpath.basename(exe)
    if any(isinstance(row.name, str) and row.name.casefold() == basename and _path(row.path) is None
           for row in rows):
        return None, 'process_identity_unconfirmed'
    candidates = {row.pid for row in rows if _path(row.path) == exe}
    if not candidates:
        return None, 'app_not_running'
    if 0 in candidates:
        return None, 'process_identity_unconfirmed'
    for pid in candidates:
        if _package_family(pid) != family:
            return None, 'process_identity_unconfirmed'

    roots = []
    for pid in candidates:
        child = index[pid]
        seen = {pid}
        ancestor_found = False
        while child.parent_pid in index:
            if child.parent_pid in seen:
                return None, 'process_identity_unconfirmed'
            parent = index[child.parent_pid]
            if parent.pid == 0 and parent.parent_pid == 0:
                break
            if (not isinstance(child.started, str) or not child.started.isdigit()
                    or not isinstance(parent.started, str) or not parent.started.isdigit()
                    or int(child.started) < int(parent.started)):
                return None, 'process_identity_unconfirmed'
            if parent.pid in candidates:
                ancestor_found = True
                break
            seen.add(parent.pid)
            child = parent
        if not ancestor_found:
            roots.append(pid)
    if len(roots) != 1:
        return None, 'app_identity_ambiguous'

    selected = {roots[0]: index[roots[0]]}
    pending = [roots[0]]
    while pending:
        parent_id = pending.pop()
        parent = selected[parent_id]
        for child in rows:
            if child.pid in selected or child.parent_pid != parent_id:
                continue
            if (not isinstance(parent.started, str) or not parent.started.isdigit()
                    or not isinstance(child.started, str) or not child.started.isdigit()
                    or int(child.started) < int(parent.started) or _path(child.path) is None
                    or _package_family(child.pid) != family):
                return None, 'process_identity_unconfirmed'
            selected[child.pid] = child
            pending.append(child.pid)
    if not candidates.issubset(selected):
        return None, 'app_identity_ambiguous'
    root = selected[roots[0]]
    if not isinstance(root.started, str) or not root.started.isdigit():
        return None, 'process_identity_unconfirmed'
    return selected, None


def _registered_app(packages, app_id):
    if (not isinstance(app_id, str) or app_id.count('!') != 1 or not isinstance(packages, list)):
        return None
    matching = [p for p in packages if isinstance(p, dict) and isinstance(p.get('aumid'), str)
                and p['aumid'].casefold() == app_id.casefold()]
    if len(matching) != 1 or _path(matching[0].get('executable')) is None:
        return None
    family, application = app_id.split('!', 1)
    if not family or not application:
        return None
    return (family, _path(matching[0]['executable']))


def inspect_desktop_runtime(config: Config, app_id: str) -> DesktopRuntimeObservation:
    """Inspect registered identity and existing TCP connections without opening connections.

    This is a point-in-time observation, not proof of UDP, DNS, all traffic or actual egress.
    """
    sampled = datetime.now(timezone.utc)
    def unconfirmed(reason):
        return DesktopRuntimeObservation('unconfirmed', sampled, False, None, None, (reason,))
    try:
        if not isinstance(config, Config) or type(config.proxy_port) is not int or not 1 <= config.proxy_port <= 65535:
            return unconfirmed('config_unconfirmed')
        owner_before = _proxy_owner_snapshot(config)
        if owner_before is None:
            return unconfirmed('proxy_owner_unconfirmed')
        packages, _ = _desktop_snapshot()
        app = _registered_app(packages, app_id)
        if app is None:
            return unconfirmed('app_identity_ambiguous')
        before, reason = _select_processes(_capture_processes(), app[1], app[0])
        if reason:
            return unconfirmed(reason)
        connections = _capture_tcp()
        after_packages, _ = _desktop_snapshot()
        if _registered_app(after_packages, app_id) != app:
            return unconfirmed('app_identity_changed')
        after, reason = _select_processes(_capture_processes(), app[1], app[0])
        if reason or before != after:
            return unconfirmed('process_snapshot_changed')
        if _proxy_owner_snapshot(config) != owner_before:
            return unconfirmed('proxy_owner_changed')
        if not isinstance(connections, list):
            return unconfirmed('runtime_check_unavailable')
        proxy_count = other_count = 0
        for conn in connections:
            if not isinstance(conn, _Tcp) or type(conn.pid) is not int:
                return unconfirmed('runtime_check_unavailable')
            if conn.pid not in before:
                continue
            if type(conn.remote_port) is not int or not 1 <= conn.remote_port <= 65535:
                return unconfirmed('connection_unconfirmed')
            address = ipaddress.ip_address(conn.remote_address)
            if (address == ipaddress.ip_address('127.0.0.1') or address == ipaddress.ip_address('::1')) and conn.remote_port == config.proxy_port:
                proxy_count += 1
            else:
                other_count += 1
        if other_count:
            return DesktopRuntimeObservation('alarm', sampled, True, proxy_count, other_count, ('unexpected_tcp_connection',))
        if not proxy_count:
            return DesktopRuntimeObservation('unconfirmed', sampled, True, 0, 0, ('no_proxy_connection',))
        return DesktopRuntimeObservation('observed', sampled, True, proxy_count, 0, ())
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return unconfirmed('runtime_check_unavailable')
