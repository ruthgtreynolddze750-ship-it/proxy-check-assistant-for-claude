"""Windows ownership checks use only this process and its loopback sockets."""
import ctypes
import hashlib
import ntpath
import os
import socket
import sys
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from src.core.backend import Config
from src.core.monitoring import BrowserBinding
from src.protection import relay_identity as identity


class IdentityContractTests(unittest.TestCase):
    def setUp(self):
        self.binding = BrowserBinding(r'C:\test\chrome.exe', r'C:\test-data', 'Default',
                                      'test-only', 101, 1000, ((102, 1001),))
        self.row = {'pid': 102, 'created': '1001', 'path': self.binding.executable,
                    'rootPid': 101, 'rootCreated': '1000', 'rootPath': self.binding.executable}
        self.client = unittest.mock.Mock()
        self.client.getpeername.return_value = ('127.0.0.1', 30001)
        self.client.getsockname.return_value = ('127.0.0.1', 30002)

    def test_changed_owner_between_snapshots_is_unknown(self):
        with patch.object(identity, '_capture_endpoint', side_effect=[self.row, {**self.row, 'created': '9999'}]):
            self.assertIsNone(identity.WindowsRelayVerifier().client(self.binding, self.client))

    def test_changed_root_revokes_instead_of_rebinding(self):
        with patch.object(identity, '_capture_endpoint', return_value={**self.row, 'rootCreated': '9999'}):
            with self.assertRaises(identity.BindingChanged):
                identity.WindowsRelayVerifier().client(self.binding, self.client)

    def test_table_parser_rejects_truncated_or_excess_count(self):
        for payload in (b'', b'\x01\x00\x00\x00', b'\xff' * 32):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                identity._decode_table(payload)

    def test_native_table_abi_and_network_byte_order(self):
        self.assertEqual(ctypes.sizeof(identity._TcpRow), 24)
        self.assertEqual(identity._TcpTable.table.offset, 4)
        row = identity._TcpRow(5, int.from_bytes(socket.inet_aton('127.0.0.1'), 'little'),
                               socket.htons(32101), int.from_bytes(socket.inet_aton('127.0.0.1'), 'little'),
                               socket.htons(32102), 101)
        decoded = identity._decode_table(b'\x01\x00\x00\x00' + bytes(row))
        self.assertEqual(decoded, ((5, ('127.0.0.1', 32101), ('127.0.0.1', 32102), 101),))


@unittest.skipUnless(os.name == 'nt', 'Windows native ABI')
class NativeIdentityLocalTests(unittest.TestCase):
    measurements = []

    def setUp(self):
        self.listener = socket.socket()
        self.addCleanup(self.listener.close)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.manager = socket.socket()
        self.addCleanup(self.manager.close)
        self.manager.bind(('127.0.0.1', 0))
        self.manager.listen(1)
        self.client = socket.create_connection(self.listener.getsockname(), timeout=1)
        self.addCleanup(self.client.close)
        self.accepted, _ = self.listener.accept()
        self.addCleanup(self.accepted.close)
        with open(sys.executable, 'rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        self.config = Config(self.listener.getsockname()[1], self.manager.getsockname()[1],
                             '203.0.113.1', 'https://example.test/ip',
                             manager_executable=sys.executable, manager_sha256=digest)

    def test_actual_endpoint_matches_current_python_process(self):
        before = time.monotonic()
        row = identity._capture_endpoint(self.client.getsockname(), self.client.getpeername(), os.getpid())
        elapsed = time.monotonic() - before
        self.measurements.append({'case': 'native_endpoint', 'elapsed_ms': elapsed * 1000})
        self.assertLess(elapsed, 1)
        self.assertEqual((row['pid'], row['rootPid']), (os.getpid(), os.getpid()))
        self.assertEqual(ntpath.normcase(os.path.realpath(row['path'])), ntpath.normcase(os.path.realpath(sys.executable)))
        self.assertEqual(row['created'], row['rootCreated'])

    def test_native_listener_and_connected_upstream_match_same_owner(self):
        before = time.monotonic()
        checker = identity.WindowsRelayVerifier()
        listener = checker.listener(self.config)
        connected = checker.upstream(self.config, self.client)
        elapsed = time.monotonic() - before
        self.measurements.append({'case': 'native_listener_and_upstream', 'elapsed_ms': elapsed * 1000})
        self.assertIsNotNone(listener)
        self.assertIsNotNone(connected)
        self.assertEqual(listener.owner, connected.owner)
        self.assertEqual(connected.owner[2], os.getpid())
        self.assertEqual(connected.client_endpoint, self.client.getsockname())
        self.assertLess(elapsed, 1)

    def test_wrong_hash_or_missing_listener_never_produces_owner(self):
        checker = identity.WindowsRelayVerifier()
        self.assertIsNone(checker.listener(replace(self.config, manager_sha256='0' * 64)))
        self.manager.close()
        self.assertIsNone(checker.listener(self.config))


if __name__ == '__main__':
    unittest.main()
