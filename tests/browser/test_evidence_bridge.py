import hashlib
import hmac
import http.client
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import subprocess
import threading
import time
import unittest
from uuid import uuid4

from src.browser.evidence_bridge import EvidenceBridge, BridgeBusy, BridgeInputError

EXTENSION = 'a' * 32
SESSION = str(uuid4())
TARGET = 'https://claude.ai/cdn-cgi/trace'


def mac(token, message):
    return hmac.new(token.encode('ascii'), message.encode('utf-8'), hashlib.sha256).hexdigest()


class FakeClock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class EvidenceBridgeTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.bridge = EvidenceBridge.from_invitation(f'{EXTENSION}.{SESSION}', clock=self.clock)
        self.offer = self.bridge.start()
        self.addCleanup(self.bridge.close)

    def request(self, method, path, payload=None, origin=None, host=None):
        body = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.offer.port, timeout=3)
        headers = {'Origin': origin or ('chrome-extension://' + EXTENSION)}
        if body is not None: headers['Content-Type'] = 'text/plain'
        if host is not None: headers['Host'] = host
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse(); data = resp.read(); conn.close()
        return resp.status, data

    def challenge(self, nonce=None, origin=None, session=SESSION):
        nonce = nonce or str(uuid4())
        code, body = self.request('GET', '/v1/challenge?nonce=' + nonce, origin=origin)
        if code == 200:
            value = json.loads(body)
            expected = mac(self.offer.token, f'bridge-v1|server|{nonce}|{session}')
            self.assertEqual(value['proof'], expected)
            self.assertNotIn(self.offer.token.encode(), body)
        return code, nonce

    def payload(self, nonce, **changes):
        value = {'version': 1, 'nonce': nonce, 'session_id': SESSION,
                 'target': TARGET, 'diagnostic': 'candidate', 'page_echo': 'seen',
                 'target_request': 'observed'}
        message = f'bridge-v1|client|{nonce}|{SESSION}|{TARGET}|candidate|seen|observed'
        value['proof'] = mac(self.offer.token, message)
        value.update(changes)
        return value

    def test_real_loopback_handshake_does_not_send_token_and_cannot_unlock(self):
        code, nonce = self.challenge()
        self.assertEqual(code, 200)
        payload = self.payload(nonce)
        self.assertNotIn(self.offer.token, json.dumps(payload))
        code, body = self.request('POST', '/v1/evidence', payload)
        self.assertEqual(code, 200)
        result = self.bridge.result()
        self.assertEqual(result.diagnostic, 'candidate')
        self.assertEqual(result.identity_status, 'unconfirmed')
        self.assertEqual(result.proxy_status, 'unconfirmed')
        self.assertFalse(result.may_launch)
        self.assertNotIn(self.offer.token, repr(result))
        self.assertNotIn(self.offer.token.encode(), body)
        self.assertEqual(self.request('POST', '/v1/evidence', payload)[0], 403)
        self.assertEqual(self.challenge()[0], 403)

    def test_wrong_origin_session_target_and_extra_data_rejected(self):
        self.assertNotEqual(self.challenge(origin='https://evil.invalid')[0], 200)
        code, nonce = self.challenge()
        self.assertEqual(code, 200)
        for value in [self.payload(nonce, session_id=str(uuid4())),
                      self.payload(nonce, target='https://example.invalid/'),
                      self.payload(nonce, ip='203.0.113.9'),
                      self.payload(nonce, proof='0' * 64)]:
            with self.subTest(case='invalid'):
                self.assertNotEqual(self.request('POST', '/v1/evidence', value)[0], 200)
                self.assertFalse(self.bridge.result().may_launch)
        self.assertEqual(self.bridge.result().diagnostic, 'unconfirmed')

    def test_simultaneous_challenges_cannot_create_two_sessions(self):
        start = threading.Barrier(2)
        def challenge_once():
            start.wait()
            return self.request('GET', '/v1/challenge?nonce=' + str(uuid4()))[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes = list(pool.map(lambda _: challenge_once(), range(2)))
        self.assertEqual(sorted(codes), [200, 403])
        self.assertEqual(self.bridge.result().diagnostic, 'unconfirmed')

    def test_expired_token_and_wrong_host_are_rejected(self):
        nonce = str(uuid4())
        self.assertNotEqual(self.request('GET', '/v1/challenge?nonce=' + nonce, host='example.invalid')[0], 200)
        self.clock.now += 61
        self.assertNotEqual(self.challenge()[0], 200)
        self.assertEqual(self.bridge.result().diagnostic, 'unconfirmed')

    def test_extension_worker_to_real_loopback_bridge_without_exposing_secret(self):
        script = Path(__file__).with_name('bridge_worker_e2e.cjs')
        data = {'port': self.offer.port, 'session_id': SESSION, 'pairing_code': self.offer.pairing_code()}
        run = subprocess.run(['node', str(script)], input=json.dumps(data), capture_output=True,
                             text=True, encoding='utf-8', check=True)
        self.assertNotIn(self.offer.token, run.stdout)
        self.assertNotIn(self.offer.token, run.stderr)
        reply = json.loads(run.stdout)
        self.assertEqual(reply['bridge_status'], 'delivered')
        self.assertTrue(reply['invitation_valid'])
        self.assertTrue(reply['field_cleared'])
        self.assertFalse(reply['may_launch'])
        self.assertEqual(self.bridge.result().diagnostic, 'candidate')
        self.assertEqual(self.bridge.result().identity_status, 'unconfirmed')
        self.assertEqual(self.bridge.result().proxy_status, 'unconfirmed')

    def test_wrong_extension_session_cannot_deliver_to_real_bridge(self):
        script = Path(__file__).with_name('bridge_worker_e2e.cjs')
        data = {'port': self.offer.port, 'session_id': str(uuid4()), 'pairing_code': self.offer.pairing_code()}
        run = subprocess.run(['node', str(script)], input=json.dumps(data), capture_output=True,
                             text=True, encoding='utf-8', check=True)
        self.assertEqual(json.loads(run.stdout)['bridge_status'], 'unconfirmed')
        self.assertEqual(self.bridge.result().diagnostic, 'unconfirmed')

    def test_another_active_session_is_rejected(self):
        other = EvidenceBridge(EXTENSION, str(uuid4()), clock=self.clock)
        with self.assertRaises(BridgeBusy): other.start()
        self.assertFalse(other.result().may_launch)

    def test_token_and_session_are_not_in_repr(self):
        self.assertNotIn(self.offer.token, repr(self.offer))
        self.assertNotIn(SESSION, repr(self.offer))

    def test_pairing_code_and_invitation_require_only_two_transfers(self):
        invitation = f'{EXTENSION}.{SESSION}'
        other = EvidenceBridge.from_invitation(invitation)
        self.assertEqual(other.origin, self.bridge.origin)
        self.assertEqual(self.offer.pairing_code(), f'{self.offer.port}:{self.offer.token}')
        self.assertNotIn(self.offer.pairing_code(), repr(self.offer))
        for invalid in (invitation + '.extra', invitation.upper(), f'{EXTENSION}.invalid'):
            with self.subTest(invalid=invalid), self.assertRaises(BridgeInputError):
                EvidenceBridge.from_invitation(invalid)

    def test_cancel_closes_listener_and_invalidates_session(self):
        port = self.offer.port
        self.bridge.cancel()
        self.assertEqual(self.bridge.result().diagnostic, 'unconfirmed')
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', port), timeout=0.5)
        other = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=1)
        try:
            other.start()
        finally:
            other.close()


class LifecycleTests(unittest.TestCase):
    def test_cancel_interrupts_slow_incomplete_headers(self):
        bridge = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=5)
        offer = bridge.start()
        self.addCleanup(bridge.close)
        conn = socket.create_connection(('127.0.0.1', offer.port), timeout=2)
        self.addCleanup(conn.close)
        conn.sendall(b'GET /v1/challenge HTTP/1.1\r\nHost: ')
        time.sleep(0.1)
        cancel = threading.Thread(target=bridge.cancel)
        cancel.start()
        cancel.join(0.7)
        if cancel.is_alive():
            conn.close()
            cancel.join(4)
            self.fail('cancellation waited for incomplete client headers')
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', offer.port), timeout=0.5)
        self.assertEqual(bridge.result().diagnostic, 'unconfirmed')

    def test_timeout_interrupts_slow_incomplete_headers(self):
        bridge = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=0.2)
        offer = bridge.start()
        self.addCleanup(bridge.close)
        conn = socket.create_connection(('127.0.0.1', offer.port), timeout=2)
        self.addCleanup(conn.close)
        conn.sendall(b'GET /v1/challenge HTTP/1.1\r\nHost: ')
        conn.settimeout(0.1)
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            try:
                conn.recv(1)
                break
            except socket.timeout:
                continue
            except OSError:
                break
        else:
            self.fail('timeout did not interrupt an incomplete request')
        self.assertEqual(bridge.result().diagnostic, 'unconfirmed')
        bridge.close()
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', offer.port), timeout=0.5)

    def test_timeout_releases_port_and_session_without_polling(self):
        bridge = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=0.15)
        offer = bridge.start()
        self.addCleanup(bridge.close)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                conn = socket.create_connection(('127.0.0.1', offer.port), timeout=0.2)
                conn.close()
            except OSError:
                break
            time.sleep(0.02)
        else:
            self.fail('listener remained open after timeout')
        self.assertEqual(bridge.result().diagnostic, 'unconfirmed')
        other = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=1)
        try:
            other.start()
        finally:
            other.close()

    def test_expiry_invalidates_a_request_held_open_past_deadline(self):
        bridge = EvidenceBridge(EXTENSION, str(uuid4()), ttl_seconds=0.15)
        offer = bridge.start()
        self.addCleanup(bridge.close)
        conn = socket.create_connection(('127.0.0.1', offer.port), timeout=2)
        self.addCleanup(conn.close)
        body = b'{}'
        headers = (f'POST /v1/evidence HTTP/1.1\r\nHost: 127.0.0.1:{offer.port}\r\n'
                   f'Origin: chrome-extension://{EXTENSION}\r\nContent-Type: text/plain\r\n'
                   f'Content-Length: {len(body)}\r\n\r\n').encode('ascii')
        conn.sendall(headers)
        time.sleep(0.25)
        try:
            conn.sendall(body)
            reply = conn.recv(1024)
        except OSError:
            reply = b''
        self.assertNotIn(b'200 OK', reply)
        self.assertEqual(bridge.result().diagnostic, 'unconfirmed')


class InvalidInputsTests(unittest.TestCase):
    def test_reject_invalid_extension_session_and_ttl(self):
        for extension, session, ttl in [('x' * 32, SESSION, 60), ('a' * 32, 'fake', 60),
                                        ('a' * 32, SESSION, 61)]:
            with self.subTest(extension=extension, session=session, ttl=ttl):
                with self.assertRaises(BridgeInputError): EvidenceBridge(extension, session, ttl_seconds=ttl)


if __name__ == '__main__':
    unittest.main()
