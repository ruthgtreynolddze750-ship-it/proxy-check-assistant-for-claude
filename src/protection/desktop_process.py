"""Read-only process tree of one protected desktop launch (R33); never ends a process."""
from dataclasses import dataclass
import ctypes
from functools import lru_cache
import ntpath
import os

from .relay_identity import _endpoint_pid, _process, _tcp_rows


class _ProcessEntry(ctypes.Structure):
    _fields_ = [('size', ctypes.c_uint32), ('usage', ctypes.c_uint32), ('pid', ctypes.c_uint32),
                ('heap', ctypes.c_size_t), ('module', ctypes.c_uint32), ('threads', ctypes.c_uint32),
                ('parent', ctypes.c_uint32), ('priority', ctypes.c_long), ('flags', ctypes.c_uint32),
                ('name', ctypes.c_wchar * 260)]


@lru_cache(maxsize=1)
def _toolhelp():
    if os.name != 'nt':
        raise OSError('Windows process list unavailable')
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    handle = ctypes.c_void_p
    for function, arguments, result in (
            (kernel.CreateToolhelp32Snapshot, [ctypes.c_uint32, ctypes.c_uint32], handle),
            (kernel.Process32FirstW, [handle, ctypes.POINTER(_ProcessEntry)], ctypes.c_int),
            (kernel.Process32NextW, [handle, ctypes.POINTER(_ProcessEntry)], ctypes.c_int),
            (kernel.CloseHandle, [handle], ctypes.c_int)):
        function.argtypes, function.restype = arguments, result
    return kernel


def process_list():
    """((pid, parent_pid, image_name), ...) from one toolhelp snapshot."""
    kernel = _toolhelp()
    snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = _ProcessEntry()
        entry.size = ctypes.sizeof(_ProcessEntry)
        rows = []
        ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            rows.append((entry.pid, entry.parent, entry.name))
            if len(rows) > 65536:
                raise OSError('process list outside limit')
            ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() not in (0, 18):
            raise ctypes.WinError(ctypes.get_last_error())
        return tuple(rows)
    finally:
        kernel.CloseHandle(snapshot)


def process_info(pid):
    """(created, image path) of a live process, or None when it is gone."""
    try:
        with _process(pid) as row:
            return int(row['created']), row['path']
    except ValueError:
        return None
    except OSError as error:
        # ERROR_INVALID_PARAMETER: the PID no longer exists (short-lived helpers exit all the time).
        if getattr(error, 'winerror', None) == 87:
            return None
        raise


def _key(path):
    return ntpath.normcase(ntpath.normpath(path))


@dataclass(frozen=True)
class TreeObservation:
    allowed: frozenset          # {(pid, created)} of the protected executables in the tree
    unknown_claude: tuple       # image paths named claude.exe that are not in the plan
    other_children: int         # other descendants (D1: not restricted by the rules)


class DesktopTree:
    """Root fixed at launch; descendants re-read every time (Electron and Claude Code respawn)."""
    MAX_DEPTH = 32

    def __init__(self, root_pid, root_created, desktop_executable, allowed_executables, *,
                 lister=process_list, info=process_info):
        if type(root_pid) is not int or root_pid <= 0 or type(root_created) is not int or root_created <= 0:
            raise ValueError('invalid desktop root')
        self.root = (root_pid, root_created)
        self.desktop = _key(desktop_executable)
        self.allowed_paths = frozenset(_key(path) for path in allowed_executables)
        if self.desktop not in self.allowed_paths:
            raise ValueError('desktop executable outside plan')
        self._list, self._info = lister, info

    def _root_live(self):
        actual = self._info(self.root[0])
        return actual is not None and actual[0] == self.root[1] and _key(actual[1]) == self.desktop

    def root_alive(self):
        try:
            return self._root_live()
        except OSError:
            return False

    def read(self):
        if not self._root_live():
            raise ValueError('desktop_exited')
        children = {}
        for pid, parent, name in self._list():
            if pid != parent and pid > 0:
                children.setdefault(parent, []).append((pid, name))
        allowed, unknown, other = {self.root}, [], 0
        pending, depth = [(self.root[0], self.root[1])], 0
        while pending:
            depth += 1
            if depth > 4096:
                raise ValueError('desktop_tree_unbounded')
            parent_pid, parent_created = pending.pop()
            for pid, name in children.get(parent_pid, ()):
                actual = self._info(pid)
                # A recycled parent PID shows up as a child older than its parent.
                if actual is None or actual[0] < parent_created:
                    continue
                created, path = actual
                if _key(path) in self.allowed_paths:
                    allowed.add((pid, created))
                elif name.lower() == 'claude.exe' or ntpath.basename(path).lower() == 'claude.exe':
                    unknown.append(path)
                else:
                    other += 1
                pending.append((pid, created))
        if not self._root_live():
            raise ValueError('desktop_exited')
        return TreeObservation(frozenset(allowed), tuple(unknown), other)

    def admits(self, pid):
        """True only for a live protected executable whose ancestry reaches the fixed root."""
        if type(pid) is not int or pid <= 0:
            return False
        parents = {child: parent for child, parent, _ in self._list()}
        current = self._info(pid)
        if current is None or _key(current[1]) not in self.allowed_paths:
            return False
        if (pid, current[0]) == self.root:
            return self._root_live()
        child_pid, child_created = pid, current[0]
        for _ in range(self.MAX_DEPTH):
            parent_pid = parents.get(child_pid)
            if parent_pid is None:
                return False
            parent = self._info(parent_pid)
            if parent is None or parent[0] > child_created:
                return False
            if (parent_pid, parent[0]) == self.root:
                return self._root_live()
            child_pid, child_created = parent_pid, parent[0]
        return False


def running_executables(paths, *, lister=process_list, info=process_info):
    """True/False whether any process runs one of paths; None when one could not be identified."""
    keys = frozenset(_key(path) for path in paths)
    names = frozenset(ntpath.basename(key) for key in keys)
    unknown = False
    for pid, _, name in lister():
        if name.lower() not in names or pid <= 0:
            continue
        try:
            actual = info(pid)
        except OSError:
            unknown = True
            continue
        if actual is not None and _key(actual[1]) in keys:
            return True
    return None if unknown else False


def connection_pid(client_endpoint, server_endpoint):
    """PID owning the client side of an accepted loopback connection, read twice."""
    first = _endpoint_pid(_tcp_rows(), client_endpoint, server_endpoint)
    if _endpoint_pid(_tcp_rows(), client_endpoint, server_endpoint) != first:
        raise ValueError('connection owner changed')
    return first
