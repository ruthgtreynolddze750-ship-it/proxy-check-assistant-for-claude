import importlib
import socket
import subprocess
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from src.core.backend import Config
from src.core import runtime_observation as runtime


class RuntimeObservationTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(24001, 22999, '203.0.113.3', 'https://example.test/ip')
        self.app_id = 'Example_family!Claude'
        self.packages = [{'aumid': self.app_id, 'executable': r'C:\Example\Claude.exe'}]
        self.procs = [runtime._Process(10, 99, '100', r'C:\Example\Claude.exe', 'Claude.exe'),
                      runtime._Process(11, 10, '101', r'C:\Example\Helper.exe', 'Helper.exe'),
                      runtime._Process(50, 99, '103', r'C:\Other\Other.exe', 'Other.exe')]
        self.connections = [runtime._Tcp(10, '127.0.0.1', 24001), runtime._Tcp(11, '::1', 24001),
                            runtime._Tcp(50, '198.51.100.1', 443)]
        self.owner = ('trusted', 1)

    def inspect(self, *, packages=None, pre=None, post=None, connections=None, families=None, owners=None):
        packages = self.packages if packages is None else packages
        pre = self.procs if pre is None else pre
        post = self.procs if post is None else post
        connections = self.connections if connections is None else connections
        families = {10: 'Example_family', 11: 'Example_family'} if families is None else families
        owners = [self.owner, self.owner] if owners is None else owners
        with patch.object(runtime, '_desktop_snapshot', return_value=(packages, [])), \
             patch.object(runtime, '_capture_processes', side_effect=[pre, post]), \
             patch.object(runtime, '_capture_tcp', return_value=connections), \
             patch.object(runtime, '_package_family', side_effect=lambda pid: families.get(pid)), \
             patch.object(runtime, '_proxy_owner_snapshot', side_effect=owners):
            return runtime.inspect_desktop_runtime(self.config, self.app_id)

    def test_valid_tree_and_exact_loopback_are_counted_without_other_process(self):
        result = self.inspect()
        self.assertEqual(result.status, 'observed')
        self.assertTrue(result.identity_confirmed)
        self.assertEqual((result.proxy_connections, result.other_tcp_connections), (2, 0))
        self.assertIsNotNone(result.sampled_at)
        with self.assertRaises(FrozenInstanceError):
            result.status = 'alarm'
        self.assertNotIn('198.51.100.1', repr(result))
        self.assertNotIn('C:\\Example', repr(result))

    def test_foreign_or_unknown_descendant_cannot_be_assumed_trusted(self):
        for family in (None, 'Different_family'):
            with self.subTest(family=family):
                result = self.inspect(families={10: 'Example_family', 11: family})
                self.assertEqual(result.status, 'unconfirmed')
                self.assertIn('process_identity_unconfirmed', result.reason_codes)

    def test_pid_reuse_or_tree_change_invalidates_the_sample(self):
        replaced = list(self.procs)
        replaced[1] = runtime._Process(11, 10, '999', r'C:\Example\Helper.exe', 'Helper.exe')
        result = self.inspect(post=replaced)
        self.assertEqual(result.status, 'unconfirmed')
        self.assertIn('process_snapshot_changed', result.reason_codes)

    def test_foreign_connection_from_confirmed_process_is_an_alarm(self):
        conns = [runtime._Tcp(10, '127.0.0.1', 24001), runtime._Tcp(11, '198.51.100.8', 443)]
        result = self.inspect(connections=conns)
        self.assertEqual(result.status, 'alarm')
        self.assertEqual((result.proxy_connections, result.other_tcp_connections), (1, 1))
        self.assertIn('unexpected_tcp_connection', result.reason_codes)
        self.assertNotIn('198.51.100.8', repr(result))

    def test_other_loopback_ports_and_mapped_ipv6_are_not_exact_proxy(self):
        conns = [runtime._Tcp(10, '127.0.0.1', 24002), runtime._Tcp(11, '::ffff:127.0.0.1', 24001)]
        result = self.inspect(connections=conns)
        self.assertEqual(result.status, 'alarm')
        self.assertEqual((result.proxy_connections, result.other_tcp_connections), (0, 2))

    def test_no_connection_and_missing_proxy_owner_are_unconfirmed(self):
        result = self.inspect(connections=[])
        self.assertEqual(result.status, 'unconfirmed')
        self.assertIn('no_proxy_connection', result.reason_codes)
        result = self.inspect(owners=[None])
        self.assertEqual(result.status, 'unconfirmed')
        self.assertIn('proxy_owner_unconfirmed', result.reason_codes)
        self.assertIsNone(result.proxy_connections)

    def test_multiple_roots_or_ambiguous_application_are_unconfirmed(self):
        procs = self.procs + [runtime._Process(12, 99, '104', r'C:\Example\Claude.exe', 'Claude.exe')]
        result = self.inspect(pre=procs, post=procs, families={10: 'Example_family', 11: 'Example_family', 12: 'Example_family'})
        self.assertEqual(result.status, 'unconfirmed')
        self.assertIn('app_identity_ambiguous', result.reason_codes)
        result = self.inspect(packages=self.packages * 2)
        self.assertEqual(result.status, 'unconfirmed')

    def test_self_parent_and_cyclic_ancestors_are_unconfirmed(self):
        cases = [
            [runtime._Process(10, 10, '100', r'C:\Example\Claude.exe', 'Claude.exe')],
            [runtime._Process(10, 20, '100', r'C:\Example\Claude.exe', 'Claude.exe'),
             runtime._Process(20, 30, '100', r'C:\Other\A.exe', 'A.exe'),
             runtime._Process(30, 20, '100', r'C:\Other\B.exe', 'B.exe')],
        ]
        for procs in cases:
            with self.subTest(case=len(procs)):
                result = self.inspect(pre=procs, post=procs,
                                      connections=[runtime._Tcp(10, '127.0.0.1', 24001)],
                                      families={10: 'Example_family'})
                self.assertEqual(result.status, 'unconfirmed')
                self.assertIn('process_identity_unconfirmed', result.reason_codes)

    def test_system_idle_root_does_not_make_valid_desktop_ambiguous(self):
        procs = [runtime._Process(0, 0, None, None, 'System Idle Process'),
                 runtime._Process(10, 0, '100', r'C:\Example\Claude.exe', 'Claude.exe')]
        result = self.inspect(pre=procs, post=procs,
                              connections=[runtime._Tcp(10, '127.0.0.1', 24001)],
                              families={10: 'Example_family'})
        self.assertEqual(result.status, 'observed')

    def test_missing_relevant_fields_and_changing_owner_never_pass(self):
        procs = [runtime._Process(10, 99, '', r'C:\Example\Claude.exe', 'Claude.exe')]
        self.assertEqual(self.inspect(pre=procs, post=procs).status, 'unconfirmed')
        self.assertEqual(self.inspect(owners=[('owner', 1), ('owner', 2)]).status, 'unconfirmed')
        self.assertEqual(self.inspect(connections=[runtime._Tcp(10, 'invalid', 24001)]).status, 'unconfirmed')

    def test_import_does_not_read_processes_or_open_sockets(self):
        with patch.object(subprocess, 'run') as run, patch.object(socket, 'create_connection') as connect:
            importlib.reload(runtime)
        run.assert_not_called()
        connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
