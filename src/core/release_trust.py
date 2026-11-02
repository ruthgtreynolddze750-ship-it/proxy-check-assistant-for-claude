"""Offline release evidence for one historically verified Proxy Manager build."""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from .backend import _file_sha256, _proxy_owner_snapshot


VERSION = '1.679.135'
RELEASE_URL = 'https://github.com/luminati-io/luminati-proxy/releases/tag/v1.679.135'
INSTALLER_SHA256 = 'fd957532fbd67c712062cf2bb925eb92891d94d78d1b533ca7c3b2127aac0662'
EXECUTABLE_SHA256 = '3120907190c2879360e061518cf2edf33c5e9a61e610f1a7cf61aae444bc70f3'
MANIFEST_SHA256 = 'a3ba75db50c17c16f04ba8837e4c16e4fbf6577608f07e710cc26dc3c814419d'
MANIFEST_NAME = 'release_v1_679_135_manifest.json'


@dataclass(frozen=True)
class Baseline:
    manager_executable: str = field(repr=False)
    manager_sha256: str = field(repr=False)
    version: str = VERSION


@dataclass(frozen=True)
class ReleaseInspection:
    status: str
    message: str
    release_source: str = 'unknown'
    release_url: str = RELEASE_URL
    package_match: str = 'unknown'
    installed_match: str = 'unknown'
    owner_match: str = 'unknown'
    windows_signature: str = 'unknown'
    baseline: Baseline | None = field(default=None, repr=False)


def _long_path(path):
    value = os.path.abspath(os.fspath(path))
    if os.name == 'nt' and not value.startswith('\\\\?\\'):
        if value.startswith('\\\\'):
            raise ValueError('network path is not allowed')
        value = '\\\\?\\' + value
    return value


def _is_reparse(path):
    stat = os.stat(path, follow_symlinks=False)
    return os.path.islink(path) or bool(getattr(stat, 'st_file_attributes', 0) & 0x400)


def _local_file_is_safe(path):
    if os.name != 'nt':
        return False
    try:
        import ctypes
        normalized = ntpath.normpath(path)
        drive, tail = ntpath.splitdrive(normalized)
        if not re.fullmatch(r'[A-Za-z]:', drive) or not tail.startswith('\\') or ':' in tail:
            return False
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        if get_drive_type(drive + '\\') not in (2, 3):
            return False
        current = drive + '\\'
        if _is_reparse(_long_path(current)):
            return False
        for component in tail.split('\\'):
            if not component:
                continue
            current = ntpath.join(current, component)
            if _is_reparse(_long_path(current)):
                return False
        return stat.S_ISREG(os.stat(_long_path(current), follow_symlinks=False).st_mode)
    except (OSError, ValueError, TypeError):
        return False


def _matches_tree(root, manifest):
    """Compare every file and reject extra files, links, unreadable data and mutation."""
    try:
        root_path = _long_path(root)
        if not isinstance(manifest, dict) or not manifest or _is_reparse(root_path):
            return False
        found = set()
        def onerror(error):
            raise error
        for directory, dirs, files in os.walk(root_path, topdown=True, followlinks=False, onerror=onerror):
            if _is_reparse(directory):
                return False
            for item in dirs:
                if _is_reparse(os.path.join(directory, item)):
                    return False
            for item in files:
                path = os.path.join(directory, item)
                if _is_reparse(path):
                    return False
                key = Path(os.path.relpath(path, root_path)).as_posix().casefold()
                if key in found or key not in manifest:
                    return False
                before = os.stat(path, follow_symlinks=False)
                if not stat.S_ISREG(before.st_mode):
                    return False
                if _file_sha256(path) != manifest[key]:
                    return False
                after = os.stat(path, follow_symlinks=False)
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                    return False
                found.add(key)
        return found == set(manifest)
    except (OSError, ValueError, TypeError):
        return False


def _verify_installed_release(executable):
    try:
        manifest_path = Path(__file__).with_name(MANIFEST_NAME)
        raw = manifest_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
            return False
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('files'), dict):
            return False
        files = data['files']
        if len(files) != 19682 or files.get('proxy manager.exe') != EXECUTABLE_SHA256:
            return False
        return _matches_tree(os.path.dirname(executable), files)
    except (OSError, ValueError, TypeError):
        return False


def inspect_release_baseline(installer, manager_executable, manager_port, proxy_port, *, selected=False):
    """Return an in-memory candidate only for an explicit selection with complete offline evidence."""
    unavailable = ReleaseInspection('unknown', '发布包、安装文件或监听进程的证据未确认')
    try:
        if (selected is not True or not isinstance(installer, str) or not isinstance(manager_executable, str)
                or not re.match(r'^[A-Za-z]:[\\/]', installer)
                or not re.match(r'^[A-Za-z]:[\\/]', manager_executable)
                or ntpath.basename(manager_executable).casefold() != 'proxy manager.exe'
                or type(manager_port) is not int or type(proxy_port) is not int
                or not 1 <= manager_port <= 65535 or not 1 <= proxy_port <= 65535
                or manager_port == proxy_port):
            return unavailable
        if not _local_file_is_safe(installer) or not _local_file_is_safe(manager_executable):
            return unavailable
        if _file_sha256(installer).lower() != INSTALLER_SHA256:
            return unavailable
        package_only = ReleaseInspection('unknown', '发布包摘要一致；安装文件或监听进程仍未确认',
                                         release_source='historical_release_record', package_match='pass',
                                         windows_signature='historical_untrusted')
        config = SimpleNamespace(manager_executable=manager_executable, manager_sha256=EXECUTABLE_SHA256,
                                 manager_port=manager_port, proxy_port=proxy_port)
        before = _proxy_owner_snapshot(config)
        if before is None or not _verify_installed_release(manager_executable):
            return package_only
        after = _proxy_owner_snapshot(config)
        if before != after or after is None or _file_sha256(installer).lower() != INSTALLER_SHA256:
            return unavailable
        return ReleaseInspection('pass', '历史发布摘要、安装文件与当前监听进程检查一致；签名链历史上未受信任',
                                 release_source='historical_release_record', package_match='pass',
                                 installed_match='pass', owner_match='pass', windows_signature='historical_untrusted',
                                 baseline=Baseline(manager_executable, EXECUTABLE_SHA256))
    except (OSError, ValueError, TypeError):
        return unavailable
