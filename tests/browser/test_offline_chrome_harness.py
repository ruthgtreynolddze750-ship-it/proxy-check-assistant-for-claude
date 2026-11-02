import hashlib
import hmac
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from uuid import uuid4

from src.browser import offline_chrome_harness as harness


class SafeHarnessTests(unittest.TestCase):
    def test_untrusted_isolation_claim_never_authorizes_browser(self):
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('process launch forbidden')):
            result = harness.preflight({'offline': True, 'verified': True})
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['isolation'], 'unconfirmed')
        self.assertEqual(result['actual_chrome'], 'not_run')
        self.assertFalse(result['may_launch'])

    def test_loopback_fixture_is_local_synthetic_and_closes(self):
        with harness.SyntheticTarget() as server:
            port = server.port
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            conn.request('GET', '/cdn-cgi/trace')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b'ip=203.0.113.9\n')
            conn.close()
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            conn.request('GET', '/cdn-cgi/trace', headers={'Host': 'evil.invalid'})
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        with self.assertRaises(OSError):
            http.client.HTTPConnection('127.0.0.1', port, timeout=.5).request('GET', '/')

    def test_synthetic_extension_copy_has_only_loopback_access_and_originals_remain(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / 'fixture'
            worker = harness.EXTENSION / 'worker.js'
            before = hashlib.sha256(worker.read_bytes()).hexdigest()
            manifest = harness.prepare_fixture(dest, 41234)
            self.assertEqual(hashlib.sha256(worker.read_bytes()).hexdigest(), before)
            self.assertEqual(manifest['source_sha256']['worker.js'], before)
            extension = json.loads((dest / 'extension' / 'manifest.json').read_text(encoding='utf-8'))
            self.assertEqual(extension['host_permissions'], ['http://127.0.0.1/*'])
            self.assertEqual(extension['content_scripts'][0]['matches'], ['http://127.0.0.1/cdn-cgi/trace*'])
            for name in ['worker.js', 'content.js']:
                text = (dest / 'extension' / name).read_text(encoding='utf-8')
                self.assertIn('http://127.0.0.1:41234', text)
                self.assertNotIn('https://claude.ai', text)
            self.assertIn("_TARGET = 'http://127.0.0.1:41234/cdn-cgi/trace'", (dest / 'fixture_bridge.py').read_text(encoding='utf-8'))
            with self.assertRaises(harness.PreflightError):
                harness.prepare_fixture(dest, 41234)

    def test_synthetic_target_closes_even_with_incomplete_request(self):
        target = harness.SyntheticTarget().__enter__()
        conn = socket.create_connection(('127.0.0.1', target.port), timeout=1)
        conn.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: ')
        time.sleep(.1)
        closer = threading.Thread(target=target.__exit__, args=(None, None, None))
        closer.start(); closer.join(.7)
        if closer.is_alive():
            conn.close(); closer.join(2)
            self.fail('synthetic listener did not close with an incomplete request')
        conn.close()

    def test_manifest_drift_fails_before_fixture_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            shutil.copytree(harness.EXTENSION, source)
            manifest_path = source / 'manifest.json'
            manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
            manifest['content_scripts'].append({'matches': ['https://example.invalid/*'], 'js': ['content.js']})
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            dest = root / 'fixture'
            with mock.patch.object(harness, 'EXTENSION', source):
                with self.assertRaises(harness.PreflightError):
                    harness.prepare_fixture(dest, 41234)
            self.assertFalse(dest.exists())

    def test_cli_does_not_offer_an_unsafe_execute_override(self):
        proc = subprocess.run([sys.executable, '-B', str(Path(harness.__file__)), '--preflight', '--execute'],
                              capture_output=True, text=True, encoding='utf-8')
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('candidate', proc.stdout)

    def test_fixture_worker_and_content_with_synthetic_events_and_real_loopback(self):
        with tempfile.TemporaryDirectory() as temp, harness.SyntheticTarget() as target:
            dest = Path(temp) / 'fixture'
            harness.prepare_fixture(dest, target.port)
            name = 'offline_fixture_bridge'
            spec = importlib.util.spec_from_file_location(name, dest / 'fixture_bridge.py')
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            self.addCleanup(sys.modules.pop, name, None)
            spec.loader.exec_module(module)
            session = str(uuid4())
            bridge = module.EvidenceBridge('a' * 32, session)
            offer = bridge.start()
            try:
                data = {'fixture': str(dest), 'target_port': target.port, 'bridge_port': offer.port,
                        'session': session, 'token': offer.token}
                script = Path(__file__).with_name('offline_fixture_worker.cjs')
                run = subprocess.run(['node', str(script)], input=json.dumps(data), capture_output=True,
                                     text=True, encoding='utf-8', timeout=10, check=True)
                self.assertNotIn(offer.token, run.stdout + run.stderr)
                result = json.loads(run.stdout)
                self.assertEqual(result['page'], 'synthetic_candidate')
                self.assertEqual(result['bridge'], 'delivered')
                self.assertFalse(result['may_launch'])
                self.assertEqual(bridge.result().diagnostic, 'candidate')
                self.assertEqual(bridge.result().identity_status, 'unconfirmed')
                self.assertEqual(bridge.result().proxy_status, 'unconfirmed')
                nonce = str(uuid4())
                conn = http.client.HTTPConnection('127.0.0.1', offer.port, timeout=2)
                conn.request('GET', '/v1/challenge?nonce=' + nonce,
                             headers={'Origin': 'chrome-extension://' + 'a' * 32})
                self.assertEqual(conn.getresponse().status, 403)
                conn.close()
            finally:
                bridge.close()
            wrong = module.EvidenceBridge('a' * 32, str(uuid4()))
            wrong_offer = wrong.start()
            try:
                nonce = str(uuid4())
                origin = {'Origin': 'chrome-extension://' + 'a' * 32}
                conn = http.client.HTTPConnection('127.0.0.1', wrong_offer.port, timeout=2)
                conn.request('GET', '/v1/challenge?nonce=' + nonce, headers=origin)
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                response.read(); conn.close()
                bad_target = 'https://claude.ai/cdn-cgi/trace'
                message = f'bridge-v1|client|{nonce}|{wrong_offer.session_id}|{bad_target}|candidate|seen|observed'
                proof = hmac.new(wrong_offer.token.encode('ascii'), message.encode(), hashlib.sha256).hexdigest()
                body = json.dumps({'version': 1, 'nonce': nonce, 'session_id': wrong_offer.session_id,
                                   'target': bad_target, 'diagnostic': 'candidate', 'page_echo': 'seen',
                                   'target_request': 'observed', 'proof': proof})
                conn = http.client.HTTPConnection('127.0.0.1', wrong_offer.port, timeout=2)
                conn.request('POST', '/v1/evidence', body=body, headers={**origin, 'Content-Type': 'text/plain'})
                self.assertEqual(conn.getresponse().status, 403)
                conn.close()
                self.assertEqual(wrong.result().diagnostic, 'unconfirmed')
                self.assertFalse(wrong.result().may_launch)
            finally:
                wrong.close()


if __name__ == '__main__':
    unittest.main()
