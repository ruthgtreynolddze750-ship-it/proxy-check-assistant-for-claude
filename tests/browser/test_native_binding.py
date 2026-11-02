import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from src.browser.native_binding import (
    BindingSession, ProcessNode, ProcessRef, binding_proof, host_manifest,
    new_profile_marker, read_frame, write_frame,
)

EXTENSION = 'a' * 32
ORIGIN = f'chrome-extension://{EXTENSION}/'
TARGET = 'https://claude.ai/cdn-cgi/trace'


class Clock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.marker = new_profile_marker()
        self.chrome = ProcessRef(100, 1000)
        self.chain = (ProcessNode(200, 2000, 100, 'nativehost.exe'),
                      ProcessNode(100, 1000, 50, 'chrome.exe'),
                      ProcessNode(50, 500, 0, 'explorer.exe'))
        self.session = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, clock=self.clock)
        self.addCleanup(self.session.close)
        self.offer = self.session.offer()
        self.request_id = str(uuid4())

    def attempt(self, **overrides):
        values = {'origin': ORIGIN, 'session_id': self.offer.session_id, 'profile_marker': self.marker,
                  'request_id': self.request_id, 'target': TARGET, 'chain_before': self.chain,
                  'chain_after': self.chain}
        values['proof'] = binding_proof(self.offer.secret, EXTENSION, self.offer.session_id,
                                        self.marker, self.request_id, TARGET, self.chrome)
        values.update(overrides)
        return self.session.attempt(**values)

    def test_matching_inputs_only_make_candidate_not_identity_or_proxy_proof(self):
        result = self.attempt()
        self.assertEqual(result.transport, 'candidate')
        self.assertEqual(result.identity_status, 'unknown')
        self.assertEqual(result.request_status, 'unknown')
        self.assertEqual(result.proxy_status, 'unknown')
        self.assertFalse(result.may_launch)
        for secret in (self.offer.secret.hex(), self.marker, self.request_id, str(self.chrome.pid)):
            self.assertNotIn(secret, repr(result))

    def test_profile_marker_clone_does_not_prove_which_profile_was_used(self):
        clone_has_same_marker = self.marker
        result = self.attempt(profile_marker=clone_has_same_marker)
        self.assertEqual(result.transport, 'candidate')
        self.assertEqual(result.identity_status, 'unknown')
        self.assertFalse(result.may_launch)

    def test_wrong_profile_origin_target_and_proof_do_not_pass(self):
        alternatives = [dict(profile_marker=new_profile_marker()), dict(origin='chrome-extension://' + 'b' * 32 + '/'),
                        dict(target='https://else.invalid/'), dict(proof='0' * 64)]
        for values in alternatives:
            with self.subTest(values=list(values)):
                session = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, clock=self.clock)
                self.session = session; self.offer = session.offer()
                result = self.attempt(**values)
                self.assertEqual(result.transport, 'unknown')
                self.assertFalse(result.may_launch)

    def test_expired_and_replayed_binding_are_unknown(self):
        self.clock.now += 61
        self.assertEqual(self.attempt().transport, 'unknown')

    def test_unused_offer_is_cleared_after_expiry(self):
        session = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, ttl_seconds=.1)
        deadline = time.monotonic() + 2
        while session._secret is not None and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(session._secret is None, 'expired secret remained in memory')
        with self.assertRaises(ValueError):
            session.offer()

    def test_binding_requires_explicit_boolean_consent(self):
        for choice in (False, None, 1):
            with self.subTest(choice=choice), self.assertRaises(ValueError):
                BindingSession(EXTENSION, self.marker, self.chrome, consent=choice, clock=self.clock)

    def test_old_proof_cannot_be_transferred_to_new_session(self):
        old_proof = binding_proof(self.offer.secret, EXTENSION, self.offer.session_id,
                                  self.marker, self.request_id, TARGET, self.chrome)
        self.session = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, clock=self.clock)
        self.offer = self.session.offer()
        self.assertEqual(self.attempt(proof=old_proof).transport, 'unknown')

    def test_concurrent_replay_cannot_consume_the_offer_twice(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.attempt().transport, range(2)))
        self.assertEqual(sorted(results), ['candidate', 'unknown'])
        fresh = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, clock=self.clock)
        self.session = fresh; self.offer = fresh.offer()
        self.assertEqual(self.attempt().transport, 'candidate')
        self.assertEqual(self.attempt().transport, 'unknown')

    def test_pid_reuse_changed_parent_chain_and_different_browser_rejected(self):
        reused = (self.chain[0], ProcessNode(100, 2500, 50, 'chrome.exe'), self.chain[2])
        different = (self.chain[0], ProcessNode(100, 900, 50, 'chrome.exe'), self.chain[2])
        switched = (self.chain[0], self.chain[1], ProcessNode(50, 600, 0, 'explorer.exe'))
        wrong_name = (self.chain[0], ProcessNode(100, 1000, 50, 'other.exe'), self.chain[2])
        for before, after in [(reused, reused), (different, different), (self.chain, switched), (wrong_name, wrong_name)]:
            with self.subTest(case=before):
                self.session = BindingSession(EXTENSION, self.marker, self.chrome, consent=True, clock=self.clock)
                self.offer = self.session.offer()
                result = self.attempt(chain_before=before, chain_after=after)
                self.assertEqual(result.transport, 'unknown')
                self.assertFalse(result.may_launch)

    def test_same_browser_process_multiple_profiles_cannot_establish_identity(self):
        result = self.attempt()
        self.assertEqual(result.identity_status, 'unknown')
        self.assertEqual(result.request_status, 'unknown')
        self.assertEqual(result.proxy_status, 'unknown')

    def test_two_chrome_ancestors_are_ambiguous(self):
        chain = (ProcessNode(200, 2000, 150, 'nativehost.exe'),
                 ProcessNode(150, 1500, 100, 'chrome.exe'), self.chain[1], self.chain[2])
        self.assertEqual(self.attempt(chain_before=chain, chain_after=chain).transport, 'unknown')

    def test_forged_parent_metadata_cannot_establish_trust(self):
        forged_chain_with_valid_proof = self.attempt()
        self.assertEqual(forged_chain_with_valid_proof.transport, 'candidate')
        self.assertEqual(forged_chain_with_valid_proof.identity_status, 'unknown')
        self.assertEqual(forged_chain_with_valid_proof.request_status, 'unknown')
        self.assertFalse(forged_chain_with_valid_proof.may_launch)

    def test_background_update_invisible_to_sampler_does_not_promote_identity(self):
        same_reported_process = tuple(ProcessNode(n.pid, n.created, n.parent_pid, n.image) for n in self.chain)
        result = self.attempt(chain_before=self.chain, chain_after=same_reported_process)
        self.assertEqual(result.transport, 'candidate')
        self.assertEqual(result.identity_status, 'unknown')
        self.assertEqual(result.request_status, 'unknown')
        self.assertFalse(result.may_launch)

    def test_changed_extension_id_requires_new_allowlist_and_binding(self):
        changed = 'b' * 32
        self.assertNotEqual(host_manifest(r'C:\Example\nativehost.exe', EXTENSION)['allowed_origins'],
                            host_manifest(r'C:\Example\nativehost.exe', changed)['allowed_origins'])
        self.assertEqual(self.attempt(origin=f'chrome-extension://{changed}/').transport, 'unknown')

    def test_unverified_page_request_or_proxy_cannot_unlock(self):
        result = self.attempt()
        self.assertEqual((result.request_status, result.proxy_status), ('unknown', 'unknown'))
        self.assertFalse(result.may_launch)


class ManifestAndFramingTests(unittest.TestCase):
    def test_manifest_has_one_exact_origin_and_no_wildcards(self):
        manifest = host_manifest(r'C:\Example\nativehost.exe', EXTENSION)
        self.assertEqual(manifest['allowed_origins'], [ORIGIN])
        self.assertEqual(manifest['type'], 'stdio')
        for identifier in ('x' * 32, 'a' * 31, '*', 'A' * 32):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                host_manifest(r'C:\Example\nativehost.exe', identifier)
        for path in (r'\\server\share\host.exe', 'relative.exe', r'C:\Example\host.bat', r'C:\Example\file.exe:host.exe'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                host_manifest(path, EXTENSION)

    def test_frame_length_json_and_duplicate_keys_are_strict(self):
        stream = io.BytesIO(); write_frame(stream, {'version': 1, 'type': 'hello'}); stream.seek(0)
        self.assertEqual(read_frame(stream), {'version': 1, 'type': 'hello'})
        for raw in (b'\x08\x00\x00\x00{}', struct.pack('<I', 4097),
                    struct.pack('<I', 13) + b'{"x":1,"x":2}', struct.pack('<I', 1) + b'\xff',
                    struct.pack('<I', 4) + b'null'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_frame(io.BytesIO(raw))

    def test_real_stdio_process_uses_native_frames_without_personal_data(self):
        program = Path(__file__).resolve().parents[2] / 'src/browser/native_host_prototype.py'
        frame = io.BytesIO(); write_frame(frame, {'version': 1, 'type': 'hello'})
        proc = subprocess.run([sys.executable, '-B', str(program), '--stdio', '--allowed-id', EXTENSION,
                               '--origin', ORIGIN], input=frame.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode('utf-8', errors='replace'))
        reply = read_frame(io.BytesIO(proc.stdout))
        self.assertEqual(reply['identity_status'], 'unknown')
        self.assertEqual(reply['proxy_status'], 'unknown')
        self.assertFalse(reply['may_launch'])
        self.assertNotIn(EXTENSION.encode(), proc.stdout + proc.stderr)
        self.assertNotIn(str(os.getpid()).encode(), proc.stdout + proc.stderr)

    def test_process_can_spoof_origin_argument_but_cannot_gain_identity(self):
        program = Path(__file__).resolve().parents[2] / 'src/browser/native_host_prototype.py'
        frame = io.BytesIO(); write_frame(frame, {'version': 1, 'type': 'hello'})
        proc = subprocess.run([sys.executable, '-B', str(program), '--stdio', '--allowed-id', EXTENSION,
                               '--origin', ORIGIN], input=frame.getvalue(), capture_output=True, timeout=10)
        reply = read_frame(io.BytesIO(proc.stdout))
        self.assertTrue(reply['claimed_origin_matches'])
        self.assertEqual(reply['identity_status'], 'unknown')
        self.assertFalse(reply['may_launch'])

    def test_oversized_native_frame_fails_closed_on_real_stdio(self):
        program = Path(__file__).resolve().parents[2] / 'src/browser/native_host_prototype.py'
        proc = subprocess.run([sys.executable, '-B', str(program), '--stdio', '--allowed-id', EXTENSION,
                               '--origin', ORIGIN], input=struct.pack('<I', 4097), capture_output=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        reply = read_frame(io.BytesIO(proc.stdout))
        self.assertEqual(reply['identity_status'], 'unknown')
        self.assertFalse(reply['may_launch'])

    def test_real_parent_chain_probe_is_read_only_and_does_not_expose_pid(self):
        program = Path(__file__).resolve().parents[2] / 'src/browser/native_host_prototype.py'
        proc = subprocess.run([sys.executable, '-B', str(program), '--probe'], capture_output=True,
                              text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        value = json.loads(proc.stdout)
        self.assertIn(value['process_chain'], ('observed', 'unknown'))
        self.assertEqual(value['identity_status'], 'unknown')
        self.assertFalse(value['may_launch'])
        self.assertNotIn(str(os.getpid()), proc.stdout + proc.stderr)

    @unittest.skipUnless(os.name == 'nt', 'Windows process API only')
    def test_real_sampler_matches_own_pid_and_actual_parent_when_available(self):
        from src.browser.native_process import sample_current_chain
        chain = sample_current_chain()
        self.assertIsNotNone(chain)
        self.assertTrue(chain[0].pid == os.getpid(), 'current process mismatch')
        self.assertTrue(chain[0].parent_pid == os.getppid(), 'parent process mismatch')
        self.assertTrue(all(child.created >= parent.created for child, parent in zip(chain, chain[1:])))


if __name__ == '__main__':
    unittest.main()
