import unittest
import threading
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch
from src.protection import relay_identity as identity
from src.core.backend import Config
from src.core.monitoring import BrowserBinding


class ProductionGuardTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.binding = BrowserBinding(r'C:\owned\chrome.exe', r'C:\owned-data',
            'Default', 'synthetic-session', 101, 1000, ((102,1001),))
        self.policy = SimpleNamespace(expires_at=105,revoked=threading.Event())
        self.relay = Mock()
        self.relay.endpoint = ('127.0.0.1', 45678)
        self.relay.read_policy.return_value = self.policy
        self.reader = Mock()
        self.guard = identity.WindowsSessionGuard(Config(25001,25002,'203.0.113.1','https://example.test'),
            self.binding, 'synthetic-fingerprint', self.relay, self.reader, clock=lambda:self.now[0])
        self.owner = (25002,25001,501,'900',r'C:\pm.exe','a'*64)
        self.process_check = self.enterContext(patch('src.browser.session_binding.validate_bound_processes'))
        self.owner_check = self.enterContext(patch.object(identity, '_native_proxy_owner', return_value=self.owner))
        self.rows = self.enterContext(patch.object(identity, '_tcp_rows', return_value=[
            (5,('127.0.0.1',40001),self.relay.endpoint,102)]))

    def test_original_guard_receipt_is_bound_to_deadline_and_cannot_be_copied(self):
        proof = self.guard.read()
        self.assertIs(self.guard.latest, proof)
        self.assertTrue(self.guard.accepts(proof))
        self.assertFalse(self.guard.accepts(replace(proof)))
        self.assertEqual(self.process_check.call_count, 2)
        self.assertEqual(self.owner_check.call_count, 2)
        self.now[0] = proof.expires_at
        self.assertIsNone(self.guard.latest)

    def test_route_or_owner_change_and_slow_read_do_not_issue_guard(self):
        cases = ('foreign_route', 'changed_owner', 'slow_native_read')
        for case in cases:
            with self.subTest(case=case):
                self.setUp()
                if case == 'foreign_route':
                    self.rows.return_value = [(5,('127.0.0.1',40001),('203.0.113.8',443),102)]
                elif case == 'changed_owner':
                    self.owner_check.side_effect = [self.owner, (*self.owner[:2],999,*self.owner[3:])]
                else:
                    self.reader.read.side_effect = lambda:self.now.__setitem__(0,100.5)
                with self.assertRaises(ValueError):
                    self.guard.read()
                self.assertIsNone(self.guard.latest)

    def test_cancelled_guard_performs_no_metadata_or_policy_read(self):
        self.guard.cancelled.set()
        with self.assertRaises(ValueError):
            self.guard.read()
        self.process_check.assert_not_called()
        self.reader.read.assert_not_called()

    def test_native_guard_has_an_explicit_original_receipt_validator(self):
        self.assertTrue(hasattr(identity, 'WindowsSessionGuard'), '缺少生产本机守卫签发器')
        self.assertTrue(callable(getattr(identity.WindowsSessionGuard, 'read', None)))
        self.assertTrue(callable(getattr(identity.WindowsSessionGuard, 'accepts', None)))


if __name__ == '__main__':
    unittest.main()
