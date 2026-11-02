"""Read a user-selected Windows shortcut without starting the browser."""
from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import json
import ntpath
import os
from pathlib import Path
import stat
import subprocess
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ShortcutSelection:
    status: str
    chrome_executable: str = field(repr=False)
    user_data_dir: str | None = field(repr=False)
    profile_directory: str | None = field(repr=False)
    data_dir_source: str = 'unknown'


def _fixed_local_path(value):
    if '\x00' in value:
        return False
    drive, tail = ntpath.splitdrive(value)
    if len(drive) != 2 or drive[1] != ':' or not tail.startswith(('\\', '/')) or ':' in tail:
        return False
    return ctypes.windll.kernel32.GetDriveTypeW(drive + '\\') == 3


def _without_links(path, mode_test):
    try:
        item = Path(path)
        for part in (item, *item.parents):
            info = os.lstat(part)
            if getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return False
        return mode_test(os.lstat(item).st_mode)
    except (OSError, ValueError):
        return False


def _regular_file_without_links(path):
    return _without_links(path, stat.S_ISREG)


def _default_directory_candidate(profile):
    local = os.environ.get('LOCALAPPDATA', '')
    if not _fixed_local_path(local):
        return None
    root = Path(local) / 'Google' / 'Chrome' / 'User Data'
    if not _without_links(root, stat.S_ISDIR) or not _without_links(root / profile, stat.S_ISDIR):
        return None
    return str(root)


def _allowed_target(url):
    if (not isinstance(url, str) or not url or any(ord(c) < 33 or ord(c) == 127 for c in url)
            or any(c in url for c in '\\%?#')):
        return None
    try:
        parts = urlsplit(url)
        if (parts.scheme.lower() != 'https' or parts.netloc.lower() not in ('claude.ai', 'claude.ai:443')
                or parts.username is not None or parts.password is not None):
            return None
        return parts.path or '/'
    except ValueError:
        return None


def _split_arguments(value):
    shell = ctypes.windll.shell32
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel = ctypes.windll.kernel32
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    count = ctypes.c_int()
    argv = shell.CommandLineToArgvW('shortcut.exe ' + value, ctypes.byref(count))
    if not argv:
        raise ValueError('无法解析快捷方式参数。')
    try:
        return [argv[i] for i in range(1, count.value)]
    finally:
        kernel.LocalFree(ctypes.cast(argv, wintypes.HLOCAL))


def inspect_shortcut(path, *, allowed_url=None):
    """Return only metadata; it does not authenticate a profile or launch Chrome."""
    if os.name != 'nt' or not isinstance(path, str) or not _fixed_local_path(path):
        raise ValueError('请选择本机固定磁盘上的快捷方式。')
    shortcut = Path(path)
    if shortcut.suffix.lower() != '.lnk' or not _regular_file_without_links(shortcut):
        raise ValueError('请选择存在的快捷方式。')
    script = ("[Console]::InputEncoding=[Text.UTF8Encoding]::new();"
              "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
              "$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
              "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($d.path);"
              "@{target=$s.TargetPath;arguments=$s.Arguments}|ConvertTo-Json -Compress")
    executable = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    try:
        result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', script],
                                input=json.dumps({'path': path}).encode('utf-8'),
                                capture_output=True, timeout=10, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        data = json.loads(result.stdout.decode('utf-8-sig'))
        target, arguments = data['target'], data['arguments']
        if (not isinstance(target, str) or not _fixed_local_path(target) or
                ntpath.basename(target).lower() != 'chrome.exe' or not _regular_file_without_links(target) or
                not isinstance(arguments, str) or len(arguments) > 32768):
            raise ValueError('快捷方式目标不是可识别的 Chrome 程序。')
        argv = _split_arguments(arguments)
    except (OSError, subprocess.SubprocessError, UnicodeError, KeyError, TypeError, json.JSONDecodeError):
        raise ValueError('无法只读解析快捷方式。') from None

    values = {}
    review = False
    allowed_target = _allowed_target(allowed_url)
    seen_url = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        key, sep, value = arg.partition('=')
        key = key.lower()
        if key not in ('--user-data-dir', '--profile-directory'):
            arg_target = _allowed_target(arg)
            if arg_target is None or allowed_target is None or arg_target != allowed_target or seen_url:
                review = True
            else:
                seen_url = True
            i += 1
            continue
        if not sep:
            i += 1
            if i >= len(argv) or argv[i].startswith('--'):
                review = True
                continue
            value = argv[i]
        if key in values or not value:
            review = True
        else:
            values[key] = value
        i += 1
    root = values.get('--user-data-dir')
    profile = values.get('--profile-directory')
    source = 'shortcut' if root is not None else 'unknown'
    if root is not None and not _fixed_local_path(root):
        review = True
        root = None
    if profile is not None and (profile in ('.', '..') or any(c in profile for c in '/\\:') or
                                any(ord(c) < 32 or ord(c) == 127 for c in profile)):
        review = True
        profile = None
    if root is None and source == 'unknown' and profile is not None:
        root = _default_directory_candidate(profile)
        if root is not None:
            source = 'default_candidate'
    status = 'manual_review' if review else ('complete' if root and profile else 'incomplete')
    return ShortcutSelection(status, target, root, profile, source)
