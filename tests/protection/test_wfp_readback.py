import copy
from dataclasses import replace
import unittest

from src.protection import dedicated_wfp as wfp


class ReadEngine:
    def __init__(self, plan):
        self.plan = plan
        self.objects = {o['key']: o for o in wfp.plan_objects(plan)}
        self.reads = []
        self.closed = 0
        self.close_error = False

    def identity(self, target, excluded):
        return self.plan.identity

    def capabilities(self):
        return wfp.REQUIRED_FIELDS

    def get(self, kind, key):
        self.reads.append((kind, key))
        return copy.deepcopy(self.objects.get(key))

    def close(self):
        self.closed += 1
        if self.close_error:
            raise OSError('injected_close_failure')


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        identity = wfp.ApplicationIdentity(r'C:\dedicated\chrome.exe', r'C:\dedicated\Empty',
            ('fixture',), 'a'*64, b'app-id', ((r'C:\ordinary\chrome.exe', b'other'),), 'fixture')
        self.plan = wfp.PolicyPlan(identity, 49152, 'e3116fb3-71d4-4fa3-83dc-c31eab15fb54')
        self.engine = ReadEngine(self.plan)
        self.now = 10.0

    def reader(self):
        return wfp.PolicyReadbackVerifier(self.plan, backend_factory=lambda: self.engine,
            clock=lambda: self.now, max_age_seconds=5)

    def test_readback_binds_every_object_and_cannot_be_copied_or_boolean(self):
        reader = self.reader()
        proof = reader.read()
        self.assertEqual(proof.plan_digest, self.plan.digest)
        self.assertEqual(proof.relay_port, self.plan.relay_port)
        self.assertEqual(len(proof.object_keys), 6)
        self.assertEqual(proof.source, 'injected')
        self.assertFalse(proof.protection_verified)
        self.assertEqual(len(self.engine.reads), 12)
        self.assertTrue(reader.accepts(proof))
        self.assertFalse(reader.accepts(True))
        self.assertFalse(reader.accepts(replace(proof)))
        self.assertEqual(self.engine.closed, 1)

    def test_changed_or_absent_object_revokes_prior_evidence(self):
        reader = self.reader(); proof = reader.read()
        self.engine.objects.pop(proof.object_keys[-1])
        with self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch'):
            reader.read()
        self.assertFalse(reader.accepts(proof))

    def test_expiration_clock_reversal_and_close_fail_closed(self):
        reader = self.reader(); proof = reader.read()
        self.now = 15
        self.assertFalse(reader.accepts(proof))
        self.now = 9
        self.assertFalse(reader.accepts(proof))
        self.now = 11
        proof = reader.read(); reader.close()
        self.assertFalse(reader.accepts(proof))
        with self.assertRaises(wfp.PolicyError): reader.read()

    def test_close_failure_cannot_issue_readback_or_hide_primary_failure(self):
        reader = self.reader(); self.engine.close_error = True
        with self.assertRaisesRegex(wfp.PolicyError, 'readback_close_failed'):
            reader.read()
        self.engine.objects.clear()
        with self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch') as caught:
            reader.read()
        self.assertTrue(any('close_failed' in x for x in caught.exception.__notes__))

    def test_identity_replacement_rejected_without_idle_process_guard(self):
        reader = self.reader()
        self.engine.plan = replace(self.plan, identity=replace(self.plan.identity, executable_sha256='b'*64))
        with self.assertRaisesRegex(wfp.PolicyError, 'application_identity_changed'):
            reader.read()

    def test_identity_change_during_last_object_read_prevents_issuance(self):
        reader = self.reader()
        original = self.engine.get
        def changing_get(kind, key):
            value = original(kind, key)
            if len(self.engine.reads) == 12:
                self.engine.plan = replace(self.plan,
                    identity=replace(self.plan.identity, executable_sha256='b'*64))
            return value
        self.engine.get = changing_get
        with self.assertRaisesRegex(wfp.PolicyError, 'application_identity_changed'):
            reader.read()
        self.assertFalse(reader.accepts(True))


if __name__ == '__main__':
    unittest.main()
