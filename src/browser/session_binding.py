"""Read-only identity of an explicitly selected dedicated Chrome process session."""
from dataclasses import dataclass, field
from contextlib import ExitStack
import json
import math
import ntpath
import os
from pathlib import Path
import secrets
import stat
import subprocess
import threading
import time

from .shortcut_selection import _fixed_local_path, _split_arguments, _without_links


@dataclass(frozen=True)
class DedicatedTarget:
    executable: str = field(repr=False)
    user_data_dir: str = field(repr=False)


@dataclass(frozen=True)
class ProcessFact:
    pid: int
    created: int
    parent_pid: int
    executable: str = field(repr=False)
    process_type: str = field(repr=False)
    user_data_dir: str = field(repr=False)
    utility_sub_type: str = field(repr=False)


@dataclass(frozen=True)
class ProcessSnapshot:
    processes: tuple[ProcessFact, ...] = field(repr=False)
    complete: bool


@dataclass(frozen=True)
class SessionEvidence:
    identity_status: str
    reason_code: str
    observed_at: float | None = None
    expires_at: float | None = None
    binding_id: str = ''
    root: ProcessFact | None = field(default=None, repr=False)
    network_processes: tuple[ProcessFact, ...] = field(default=(), repr=False)
    request_status: str = 'unknown'
    proxy_status: str = 'unknown'
    protection_status: str = 'not_enabled'
    may_launch: bool = False
    source: str = 'unknown'
    _revoked: threading.Event | None = field(default=None, repr=False, compare=False)

    def is_fresh(self, now):
        return (self.identity_status == 'pass' and self._revoked is not None
                and not self._revoked.is_set() and _finite(now)
                and self.observed_at <= now < self.expires_at)


def _finite(value):
    return type(value) in (float, int) and math.isfinite(value)


def _path_key(value):
    if (not isinstance(value, str) or not value or '\x00' in value
            or not ntpath.isabs(value) or value.startswith(('\\\\', '//'))
            or any(part in ('.', '..') for part in value.replace('/', '\\').split('\\'))):
        raise ValueError('invalid local path')
    return ntpath.normcase(ntpath.normpath(value))


def _target_fingerprint(target):
    if not isinstance(target, DedicatedTarget) or os.name != 'nt':
        raise ValueError('invalid target')
    paths = (target.executable, target.user_data_dir)
    modes = (stat.S_ISREG, stat.S_ISDIR)
    fingerprints = []
    for value, mode in zip(paths, modes):
        if (not _fixed_local_path(value) or not _without_links(value, mode)
                or _path_key(value) != _path_key(str(Path(value).resolve(strict=True)))):
            raise ValueError('invalid target path')
        info = os.stat(value)
        # A hard-linked executable could still be the shared browser file.
        if mode is stat.S_ISREG and info.st_nlink != 1:
            raise ValueError('shared executable')
        fingerprints.append((_path_key(value), info.st_dev, info.st_ino,
                             info.st_size if mode is stat.S_ISREG else None,
                             info.st_mtime_ns if mode is stat.S_ISREG else None))
    if ntpath.basename(target.executable).lower() != 'chrome.exe':
        raise ValueError('invalid browser executable')
    if _path_key(ntpath.dirname(target.executable)) == _path_key(target.user_data_dir):
        raise ValueError('invalid data directory')
    return tuple(fingerprints)


@dataclass(frozen=True)
class ProfileDirectoryIdentity:
    profile_directory: str
    user_data_identity: tuple[int, int]
    profile_identity: tuple[int, int]
    path_key: str = field(repr=False)


def profile_directory_identity(target, profile_directory, observed_path):
    """Validate the actual DOM path against local directory IDs; never read profile files."""
    if (not isinstance(profile_directory, str) or not profile_directory
            or profile_directory in ('.', '..') or profile_directory[-1:] in (' ', '.')
            or any(c in profile_directory for c in '\\/:\x00')
            or not isinstance(observed_path, str) or not observed_path or len(observed_path) > 4096
            or any(ord(c) < 32 or ord(c) == 127 or c == '\ufffd' or 0xd800 <= ord(c) <= 0xdfff
                   for c in observed_path)):
        raise ValueError('profile path invalid')
    before = _target_fingerprint(target)
    expected = str(Path(target.user_data_dir) / profile_directory)
    if (_path_key(observed_path) != _path_key(expected)
            or not _fixed_local_path(observed_path) or not _without_links(observed_path, stat.S_ISDIR)
            or _path_key(observed_path) != _path_key(str(Path(observed_path).resolve(strict=True)))):
        raise ValueError('profile path mismatch')
    first, actual = os.stat(expected), os.stat(observed_path)
    user = os.stat(target.user_data_dir)
    identity = (first.st_dev, first.st_ino)
    after = _target_fingerprint(target)
    last = os.stat(expected)
    if (not first.st_ino or not user.st_ino or identity != (actual.st_dev, actual.st_ino)
            or before != after or identity != (last.st_dev, last.st_ino)):
        raise ValueError('profile directory changed')
    return ProfileDirectoryIdentity(profile_directory, (user.st_dev, user.st_ino), identity,
                                    _path_key(observed_path))


def validate_bound_processes(binding, expected_fingerprint):
    """Recheck the already selected root/network IDs with existing native read-only handles.

    The initial tree must come from DedicatedSession. A replacement network process
    is not adopted: the relay still rejects any PID absent from that original binding.
    """
    from src.protection.relay_identity import _process
    target = DedicatedTarget(binding.executable, binding.user_data_dir)
    if _target_fingerprint(target) != expected_fingerprint:
        raise ValueError('target changed')
    with ExitStack() as handles:
        for pid, created in ((binding.root_pid, binding.root_created), *binding.network_processes):
            actual = handles.enter_context(_process(pid))
            if int(actual['created']) != created or _path_key(actual['path']) != _path_key(binding.executable):
                raise ValueError('bound process changed')
        if _target_fingerprint(target) != expected_fingerprint:
            raise ValueError('target changed')


# Only metadata is enumerated for other Chrome installations. Command lines are
# requested only for the selected executable, with creation time checked again.
_CAPTURE_SCRIPT = r'''
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new()
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
try {
  $selection=[Console]::In.ReadToEnd() | ConvertFrom-Json
  $inventory=@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -Property ProcessId,ParentProcessId,ExecutablePath,CreationDate)
  $complete=$true
  $rows=@(foreach ($item in $inventory) {
    if (!$item.ExecutablePath -or !$item.CreationDate) { $complete=$false; continue }
    if (![string]::Equals($item.ExecutablePath,$selection.executable,[StringComparison]::OrdinalIgnoreCase)) { continue }
    $fresh=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$item.ProcessId) -Property ProcessId,ParentProcessId,ExecutablePath,CreationDate,CommandLine
    if (!$fresh -or !$fresh.CreationDate -or !$fresh.CommandLine -or
        $fresh.CreationDate.ToUniversalTime().Ticks -ne $item.CreationDate.ToUniversalTime().Ticks -or
        $fresh.ParentProcessId -ne $item.ParentProcessId -or
        ![string]::Equals($fresh.ExecutablePath,$selection.executable,[StringComparison]::OrdinalIgnoreCase)) {
      $complete=$false; continue
    }
    [PSCustomObject]@{pid=[int]$fresh.ProcessId; parent=[int]$fresh.ParentProcessId;
      created=[string]$fresh.CreationDate.ToUniversalTime().Ticks;
      executable=$fresh.ExecutablePath; command=$fresh.CommandLine}
  })
  @{complete=$complete; rows=$rows} | ConvertTo-Json -Depth 4 -Compress
} catch { exit 1 }
'''


def _process_fact(row, executable):
    if (type(row['pid']) is not int or row['pid'] <= 0 or type(row['parent']) is not int
            or row['parent'] < 0 or not isinstance(row['created'], str)
            or not row['created'].isdigit() or int(row['created']) <= 0
            or not isinstance(row['command'], str) or not 0 < len(row['command']) <= 32768
            or _path_key(row['executable']) != _path_key(executable)):
        raise ValueError('invalid process record')
    argv = _split_arguments(row['command'])
    if not argv or _path_key(argv[0]) != _path_key(executable):
        raise ValueError('command image mismatch')
    switches = {}
    index = 1
    while index < len(argv):
        if argv[index] == '--':
            break
        key, separator, value = argv[index].partition('=')
        index += 1
        canonical = '--' + key.lstrip('-/').lower()
        if canonical in ('--type', '--user-data-dir', '--utility-sub-type') and key != canonical:
            raise ValueError('noncanonical switch')
        if key not in ('--type', '--user-data-dir', '--utility-sub-type'):
            continue
        if not separator:
            raise ValueError('explicit switch value required')
        if key in switches or not value:
            raise ValueError('ambiguous switch')
        switches[key] = value
    return ProcessFact(row['pid'], int(row['created']), row['parent'], row['executable'],
                       switches.get('--type', ''), switches.get('--user-data-dir', ''),
                       switches.get('--utility-sub-type', ''))


def capture_process_snapshot(target):
    """No network requests, browser launch, profile reads or process termination."""
    try:
        _target_fingerprint(target)
        executable = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
        result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', _CAPTURE_SCRIPT],
                                input=json.dumps({'executable': str(Path(target.executable).resolve())}).encode('utf-8'),
                                capture_output=True, timeout=12, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        payload = json.loads(result.stdout.decode('utf-8-sig'))
        if payload['complete'] is not True or not isinstance(payload['rows'], list):
            return ProcessSnapshot((), False)
        facts = tuple(_process_fact(row, target.executable) for row in payload['rows'])
        if len({fact.pid for fact in facts}) != len(facts):
            return ProcessSnapshot((), False)
        return ProcessSnapshot(facts, True)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        return ProcessSnapshot((), False)


def _select_identity(snapshot, target):
    if not isinstance(snapshot, ProcessSnapshot) or snapshot.complete is not True:
        return None, 'process_snapshot_unavailable'
    rows = snapshot.processes
    if not rows:
        return None, 'browser_not_running'
    if (not isinstance(rows, tuple) or not all(isinstance(row, ProcessFact) for row in rows)
            or len({row.pid for row in rows}) != len(rows)):
        return None, 'process_snapshot_unavailable'
    for row in rows:
        if (type(row.pid) is not int or row.pid <= 0 or type(row.created) is not int or row.created <= 0
                or type(row.parent_pid) is not int or row.parent_pid < 0
                or _path_key(row.executable) != _path_key(target.executable)):
            return None, 'process_identity_unconfirmed'
    roots = [row for row in rows if row.process_type == '']
    if len(roots) != 1:
        return None, 'root_ambiguous'
    root = roots[0]
    if not root.user_data_dir or _path_key(root.user_data_dir) != _path_key(target.user_data_dir):
        return None, 'data_directory_unconfirmed'
    index = {row.pid: row for row in rows}
    if root.parent_pid in index:
        return None, 'process_identity_unconfirmed'
    for row in rows:
        child = row
        seen = set()
        while child.pid != root.pid:
            if child.pid in seen or child.parent_pid not in index:
                return None, 'process_identity_unconfirmed'
            seen.add(child.pid)
            parent = index[child.parent_pid]
            if parent.created > child.created:
                return None, 'process_identity_unconfirmed'
            child = parent
        if row.user_data_dir and _path_key(row.user_data_dir) != _path_key(target.user_data_dir):
            return None, 'data_directory_unconfirmed'
    network = tuple(sorted((row for row in rows if row.process_type == 'utility'
                            and row.utility_sub_type == 'network.mojom.NetworkService'), key=lambda row: row.pid))
    if not network:
        return None, 'network_process_unconfirmed'
    return (root, network), 'session_observed'


class DedicatedSession:
    """A selected process session, not a page/profile or network-route attestation."""
    def __init__(self, target, *, selected=False, sampler=None, clock=time.monotonic, max_age_seconds=10):
        if (not isinstance(target, DedicatedTarget) or not callable(clock)
                or (sampler is not None and not callable(sampler))
                or not _finite(max_age_seconds) or not 0 < max_age_seconds <= 60):
            raise ValueError('invalid session parameters')
        self._target = target
        self._selected = selected is True
        self._sampler = capture_process_snapshot if sampler is None else sampler
        self._source = 'windows_cim' if sampler is None else 'injected'
        self._clock = clock
        self._max_age = max_age_seconds
        self._identity = None
        self._fingerprint = None
        self._binding_id = ''
        self._invalidated = False
        self._closed = threading.Event()
        self._expires_at = None
        self._last_tick = None
        self._lock = threading.Lock()
        self._revoked = threading.Event()

    def _unknown(self, reason):
        if self._identity is not None:
            self._invalidated = True
            self._revoked.set()
        return SessionEvidence('unknown', reason, source=self._source)

    def poll(self):
        with self._lock:
            if self._closed.is_set():
                return self._unknown('session_closed')
            if not self._selected:
                return self._unknown('target_not_selected')
            if self._invalidated:
                return self._unknown('session_invalidated')
            try:
                started = self._clock()
                if not _finite(started) or (self._last_tick is not None and started < self._last_tick):
                    return self._unknown('clock_unavailable')
                if self._expires_at is not None and started >= self._expires_at:
                    return self._unknown('evidence_expired')
                before = _target_fingerprint(self._target)
                if self._fingerprint is not None and before != self._fingerprint:
                    return self._unknown('target_changed')
                first, reason = _select_identity(self._sampler(self._target), self._target)
                if first is None:
                    return self._unknown(reason)
                second, reason = _select_identity(self._sampler(self._target), self._target)
                if second is None:
                    return self._unknown(reason)
                if first != second or (self._identity is not None and first != self._identity):
                    return self._unknown('session_changed')
                if before != _target_fingerprint(self._target):
                    return self._unknown('target_changed')
                ended = self._clock()
                if not _finite(ended) or ended < started:
                    return self._unknown('clock_unavailable')
                if ended - started >= self._max_age:
                    return self._unknown('evidence_expired')
                if self._closed.is_set():
                    return self._unknown('session_closed')
                if self._identity is None:
                    self._identity, self._fingerprint = second, before
                    self._binding_id = secrets.token_hex(16)
                self._last_tick = ended
                self._expires_at = started + self._max_age
                return SessionEvidence('pass', 'session_observed', started, self._expires_at,
                                       self._binding_id, second[0], second[1],
                                       source=self._source, _revoked=self._revoked)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
                return self._unknown('process_snapshot_unavailable')

    def close(self):
        self._closed.set()
        self._revoked.set()
