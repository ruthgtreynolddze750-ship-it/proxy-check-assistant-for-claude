import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.core import backend


class ListenerFallbackScriptTests(unittest.TestCase):
    """R44: the listen table first; only when it is empty, one handshake and the accepted socket's owner."""

    def capture(self, function, *args):
        reply = subprocess.CompletedProcess([], 0, stdout=json.dumps({'manager': [], 'proxy': []}), stderr='')
        with patch.object(backend.subprocess, 'run', return_value=reply) as run:
            function(*args)
        return run.call_args.args[0][-1]

    def test_owner_snapshot_reads_listen_table_then_falls_back_to_the_accepted_socket(self):
        script = self.capture(backend._capture_listener_owners, 22999, 24001)
        listen = script.index('Get-NetTCPConnection -State Listen -LocalPort $port')
        fallback = script.index('if ($r.Count -eq 0)')
        self.assertLess(listen, fallback)
        self.assertIn("$c.Connect('127.0.0.1', $port)", script)
        self.assertIn('Get-NetTCPConnection -LocalPort $port -RemotePort $local', script)
        self.assertIn('finally { $c.Close() }', script)
        self.assertIn("ProcessId='+$_.OwningProcess", script)
        for forbidden in ('.Send(', 'GetStream', 'Write(', 'CommandLine'):
            self.assertNotIn(forbidden, script)

    def test_manager_port_ownership_uses_the_same_rows(self):
        reply = subprocess.CompletedProcess([], 0, stdout='yes\n', stderr='')
        with patch.object(backend.subprocess, 'run', return_value=reply) as run:
            self.assertTrue(backend._manager_owns_port(22999))
        script = run.call_args.args[0][-1]
        self.assertTrue(script.startswith(backend._PORT_ROWS_PS))
        self.assertIn('$c = @(rows $p)', script)
        self.assertIn("$owner.ProcessName -eq 'Proxy Manager'", script)

    def test_empty_rows_still_fail_closed(self):
        reply = subprocess.CompletedProcess([], 0, stdout=json.dumps({'manager': [], 'proxy': []}), stderr='')
        config = backend.Config(proxy_port=24001, manager_port=22999, expected_ip='203.0.113.1', ip_url='https://x.example/',
                                manager_executable='C:\\P\\Proxy Manager.exe', manager_sha256='a' * 64)
        with patch.object(backend.subprocess, 'run', return_value=reply):
            self.assertIsNone(backend._proxy_owner_snapshot(config))

    def test_accepted_socket_owned_by_another_process_is_rejected(self):
        manager = {'pid': 10, 'started': '1', 'path': 'C:\\P\\Proxy Manager.exe'}
        other = {'pid': 11, 'started': '2', 'path': 'C:\\X\\other.exe'}
        config = backend.Config(proxy_port=24001, manager_port=22999, expected_ip='203.0.113.1', ip_url='https://x.example/',
                                manager_executable='C:\\P\\Proxy Manager.exe', manager_sha256='a' * 64)
        with patch.object(backend, '_capture_listener_owners', return_value=([manager], [other])), \
                patch.object(backend, '_file_sha256', return_value='a' * 64), \
                patch.object(backend.os.path, 'realpath', side_effect=lambda value: value):
            self.assertIsNone(backend._proxy_owner_snapshot(config))
        with patch.object(backend, '_capture_listener_owners', return_value=([manager], [manager])), \
                patch.object(backend, '_file_sha256', return_value='a' * 64), \
                patch.object(backend.os.path, 'realpath', side_effect=lambda value: value):
            self.assertIsNotNone(backend._proxy_owner_snapshot(config))


if __name__ == '__main__':
    unittest.main()
