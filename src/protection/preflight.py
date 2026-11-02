"""Read-only evidence and an inert, fail-closed protection plan."""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import subprocess


_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$port = [int]$env:CLAUDE_PROTECTION_PROXY_PORT
$packages = @(Get-AppxPackage -Name 'Claude')
$all = @(Get-CimInstance Win32_Process -Property Name,ProcessId,ParentProcessId,ExecutablePath,CreationDate)
$connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq $port -and $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::1','::') })
$appids = @(); $roots = @(); $main = @()
foreach ($pkg in $packages) {
  $mf = Get-AppxPackageManifest -Package $pkg.PackageFullName
  foreach ($app in $mf.Package.Applications.Application) {
    if ($app.Id -eq 'Claude' -and $app.Executable) {
      $appids += ($pkg.PackageFamilyName + '!' + $app.Id)
      $roots += $pkg.InstallLocation.TrimEnd('\')
      $exe = Join-Path $pkg.InstallLocation $app.Executable
      $main += @($all | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -ieq $exe })
    }
  }
}
$members = @{}
foreach ($p in $main) { $members[[int]$p.ProcessId] = $p }
$changed = $true
while ($changed) {
  $changed = $false
  foreach ($p in $all) {
    $parent = [int]$p.ParentProcessId; $pidValue = [int]$p.ProcessId
    if ($members.ContainsKey($parent) -and -not $members.ContainsKey($pidValue) -and
        $p.CreationDate -and $members[$parent].CreationDate -and
        $p.CreationDate -ge $members[$parent].CreationDate) {
      $members[$pidValue] = $p; $changed = $true
    }
  }
}
$resultProcesses = @()
foreach ($p in $members.Values) {
  $isPackageExe = @($main | Where-Object { $_.ProcessId -eq $p.ProcessId }).Count -gt 0
  $parentObserved = $members.ContainsKey([int]$p.ParentProcessId)
  $scope = 'unknown'
  if ($p.ExecutablePath) {
    $scope = 'outside_package'
    foreach ($root in $roots) { if ($p.ExecutablePath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { $scope = 'package' } }
  }
  $owned = @($connections | Where-Object { $_.OwningProcess -eq $p.ProcessId })
  $toProxy = @($owned | Where-Object { $_.RemotePort -eq $port -and $_.RemoteAddress -in @('127.0.0.1','::1') }).Count
  $resultProcesses += [PSCustomObject]@{pid=[int]$p.ProcessId;started=if($p.CreationDate){[string]$p.CreationDate.ToUniversalTime().Ticks}else{''};role=if($isPackageExe -and -not $parentObserved){'package_root_candidate'}elseif($isPackageExe){'package_child'}else{'descendant'};image_scope=$scope;tcp_to_proxy=[int]$toProxy;tcp_other=[int]($owned.Count-$toProxy)}
}
$ownerIds = @($listeners | ForEach-Object { [int]$_.OwningProcess } | Select-Object -Unique)
$ownerPid = 0; $ownerStarted = ''; $ownerName = 'unknown'
if ($ownerIds.Count -eq 1) {
  $owner = @($all | Where-Object { $_.ProcessId -eq $ownerIds[0] })
  if ($owner.Count -eq 1 -and $owner[0].CreationDate) {
    $ownerPid = [int]$owner[0].ProcessId; $ownerStarted = [string]$owner[0].CreationDate.ToUniversalTime().Ticks
    if ($owner[0].Name -ieq 'Proxy Manager.exe') { $ownerName = 'Proxy Manager' } else { $ownerName = 'other' }
  }
}
[PSCustomObject]@{package_ids=@($appids);processes=@($resultProcesses);proxy=[PSCustomObject]@{listener_count=[int]$listeners.Count;owner_pid=$ownerPid;owner_started=$ownerStarted;owner_name=$ownerName};chrome_process_count=[int]@($all | Where-Object { $_.Name -ieq 'chrome.exe' }).Count} | ConvertTo-Json -Depth 6 -Compress
'''

_WFP_EXPORTS = ('FwpmEngineOpen0', 'FwpmEngineClose0', 'FwpmTransactionBegin0',
                'FwpmTransactionCommit0', 'FwpmTransactionAbort0', 'FwpmSubLayerAdd0',
                'FwpmSubLayerDeleteByKey0', 'FwpmProviderAdd0', 'FwpmProviderDeleteByKey0',
                'FwpmFilterAdd0', 'FwpmFilterGetByKey0', 'FwpmFilterDeleteByKey0',
                'FwpmFilterCreateEnumHandle0', 'FwpmFilterEnum0', 'FwpmFilterDestroyEnumHandle0',
                'FwpmFreeMemory0')


def _count(value):
    return value if type(value) is int and 0 <= value <= 1000000 else None


def _identity(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[0-9]{1,24}', value)) and int(value) > 0


def _collect_windows(port):
    if os.name != 'nt':
        raise OSError('Windows required')
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    env = dict(os.environ)
    env['CLAUDE_PROTECTION_PROXY_PORT'] = str(port)
    encoded = base64.b64encode(_SCRIPT.encode('utf-16le')).decode('ascii')
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            capture_output=True, env=env,
                            timeout=30, check=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return json.loads(result.stdout.decode('utf-8-sig'))


def _probe_wfp_exports():
    if os.name != 'nt':
        raise OSError('Windows required')
    import ctypes
    dll = Path(os.environ['SystemRoot']) / 'System32/fwpuclnt.dll'
    library = ctypes.WinDLL(str(dll), winmode=0x00000800)
    return {name: hasattr(library, name) for name in _WFP_EXPORTS}


def make_plan(data, proxy_port, *, source, wfp_exports=None):
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise ValueError('invalid proxy port')
    if source not in ('fixture', 'live_readonly'):
        raise ValueError('invalid source')
    if not isinstance(data, dict):
        data = {}
    raw_apps = data.get('package_ids')
    apps = sorted({x for x in raw_apps if isinstance(x, str) and re.fullmatch(r'Claude_[A-Za-z0-9]{5,64}!Claude', x)}) if isinstance(raw_apps, list) else []
    processes = []
    malformed = False
    seen = set()
    raw_processes = data.get('processes')
    if not isinstance(raw_processes, list) or len(raw_processes) > 256:
        raw_processes = []
        malformed = True
    for p in raw_processes:
        if not isinstance(p, dict):
            malformed = True
            continue
        pid = _count(p.get('pid'))
        role = p.get('role')
        scope = p.get('image_scope')
        proxy_count, other_count = _count(p.get('tcp_to_proxy')), _count(p.get('tcp_other'))
        if (not pid or pid in seen or not _identity(p.get('started')) or role not in ('package_root_candidate', 'package_child', 'descendant')
                or scope not in ('package', 'outside_package', 'unknown') or proxy_count is None or other_count is None):
            malformed = True
            continue
        seen.add(pid)
        processes.append({'pid': pid, 'creation_ticks': p['started'], 'role': role, 'image_scope': scope,
                          'tcp_to_proxy': proxy_count, 'tcp_other_established': other_count})
    processes.sort(key=lambda p: p['pid'])
    raw_proxy = data.get('proxy') if isinstance(data.get('proxy'), dict) else {}
    listeners = _count(raw_proxy.get('listener_count'))
    owner_pid = _count(raw_proxy.get('owner_pid'))
    owner_valid = (listeners is not None and listeners > 0 and bool(owner_pid)
                   and _identity(raw_proxy.get('owner_started')) and raw_proxy.get('owner_name') == 'Proxy Manager')
    proxy = {'port': proxy_port, 'listener_count': listeners,
             'owner_status': 'observed_name_only_not_trusted' if owner_valid else 'unknown'}
    if owner_valid:
        proxy.update({'owner_pid': owner_pid, 'owner_creation_ticks': raw_proxy['owner_started']})
    blockers = ['wfp_api_integration_not_implemented', 'privileged_installation_not_authorized',
                'existing_flow_revocation_unverified', 'watchdog_failure_unverified',
                'browser_instance_isolation_unconfirmed', 'udp_dns_ipv6_coverage_unverified',
                'proxy_owner_untrusted', 'process_coverage_unconfirmed']
    if len(apps) != 1:
        blockers.append('desktop_identity_unconfirmed')
    complete = (isinstance(raw_apps, list) and isinstance(data.get('processes'), list)
                and isinstance(data.get('proxy'), dict) and listeners is not None
                and _count(data.get('chrome_process_count')) is not None and not malformed)
    exports = {k: v for k, v in wfp_exports.items() if k in _WFP_EXPORTS and type(v) is bool} if isinstance(wfp_exports, dict) else {}
    return {
        'schema_version': 1, 'source': source,
        'collection': 'observed' if complete else ('partial' if data else 'unavailable'),
        'wfp_api': {'exports': exports,
                    'probe_status': 'not_run_fixture' if source == 'fixture' else ('observed' if exports else 'unavailable'),
                    'scope': 'export_presence_only_no_wfp_calls', 'permissions': 'unverified'},
        'desktop': {'registered_applications': apps, 'processes': processes,
                    'snapshot_validity': 'incomplete_or_malformed' if malformed else 'syntactically_valid_only',
                    'scope': 'instantaneous_metadata_not_wfp_identity_or_complete_traffic'},
        'proxy': proxy,
        'browser': {'chrome_process_count': _count(data.get('chrome_process_count')),
                    'isolation': 'unconfirmed',
                    'reason': 'profile_to_process_and_page_binding_unverified'},
        'protection': {'effective': 'unknown', 'apply_available': False, 'may_launch': False,
                       'blockers': blockers},
        'proposed_plan': {
            'status': 'concept_only_no_rules_created',
            'scope': 'desktop_package_and_verified_children_only_browser_excluded',
            'proposed_components': ['signed_or_authorized_enforcement_component_tbd', 'watchdog_tbd', 'controlled_gateway_tbd'],
            'proposed_rules': [
                {'purpose': 'prevent_nonapproved_routes', 'target': 'independently_verified_desktop_identity_and_children',
                 'action': 'conceptual_deny_with_nonconflicting_conditions', 'state': 'unimplemented'},
                {'purpose': 'allow_verified_proxy_channel', 'target': 'same_verified_desktop_identity',
                 'destination': 'verified_local_loopback_proxy_only', 'port_ref': 'proxy.port', 'state': 'unimplemented'},
            ],
            'traffic_to_verify': ['ipv4', 'ipv6', 'tcp', 'udp', 'dns', 'existing_flows', 'loopback'],
            'rollback': ['before_install_inventory_and_record_owned_provider_sublayer_filter_keys',
                         'after_separate_authorization_remove_only_recorded_project_owned_keys',
                         'do_not_remove_or_change_existing_rules', 'keep_guard_closed_until_protected_sessions_end'],
            'apply_gate': 'unimplemented_no_system_write_entrypoint',
        },
        'limitations': ['process_snapshot_does_not_prove_all_traffic_or_identity_continuity',
                        'listener_name_does_not_establish_executable_trust',
                        'package_root_candidate_is_not_verified_main_process',
                        'existing_tcp_counts_do_not_cover_udp_dns_or_historical_flows',
                        'rule_plan_is_not_a_wfp_filter_or_enforcement_proof'],
    }


def inspect(proxy_port):
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise ValueError('invalid proxy port')
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    error = None
    try:
        data = _collect_windows(proxy_port)
    except subprocess.TimeoutExpired:
        data, error = {}, 'collector_timeout'
    except subprocess.CalledProcessError:
        data, error = {}, 'collector_failed'
    except (ValueError, KeyError, UnicodeError, TypeError):
        data, error = {}, 'collector_invalid_output'
    except (OSError, subprocess.SubprocessError):
        data, error = {}, 'collector_unavailable'
    try:
        exports = _probe_wfp_exports()
    except (OSError, KeyError, AttributeError, TypeError):
        exports = {}
    plan = make_plan(data, proxy_port, source='live_readonly', wfp_exports=exports)
    plan['observation'] = {'started_utc': started, 'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           'atomic': False, 'process_and_connection_data_may_change': True, 'error': error}
    if os.name == 'nt':
        import sys
        plan['wfp_api']['windows_build'] = sys.getwindowsversion().build
    return plan


def _fixture(name):
    if name == 'desktop-observed':
        return {'package_ids': ['Claude_synthetic123!Claude'], 'processes': [
            {'pid': 100, 'started': '100', 'role': 'package_root_candidate', 'image_scope': 'package', 'tcp_to_proxy': 0, 'tcp_other': 0},
            {'pid': 101, 'started': '101', 'role': 'package_child', 'image_scope': 'package', 'tcp_to_proxy': 1, 'tcp_other': 0}],
            'proxy': {'listener_count': 1, 'owner_pid': 200, 'owner_started': '90', 'owner_name': 'Proxy Manager'}, 'chrome_process_count': 2}
    if name == 'proxy-down':
        value = _fixture('desktop-observed')
        value['proxy'] = {'listener_count': 0}
        return value
    return {'package_ids': [], 'processes': [], 'proxy': {'listener_count': 0}, 'chrome_process_count': 2}


def main(argv=None):
    parser = argparse.ArgumentParser(description='仅只读预检；不创建、修改或删除 WFP/防火墙规则。')
    parser.add_argument('--proxy-port', required=True, type=int, help='当前电脑由用户确认的本机代理端口')
    parser.add_argument('--dry-run', action='store_true', help='只读生成计划（默认行为）')
    parser.add_argument('--fixture', choices=('desktop-observed', 'proxy-down', 'ambiguous-chrome'), help='使用合成样本；不读取真实系统')
    args = parser.parse_args(argv)
    try:
        plan = make_plan(_fixture(args.fixture), args.proxy_port, source='fixture') if args.fixture else inspect(args.proxy_port)
    except ValueError:
        parser.error('代理端口必须为 1 至 65535 的整数。')
    print(json.dumps(plan, ensure_ascii=False))
    return 0 if plan['collection'] == 'observed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
