"""Real local sockets with synthetic process proofs; never real Chrome or PM."""
import importlib.util
import hashlib
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from src.core.backend import Check, Config, Detection
from src.core.monitoring import BrowserBinding, BrowserBindingEvidence, MonitorSession


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted.set()
        try:
            while chunk := self.request.recv(65536):
                self.server.received_bytes += len(chunk)
                self.request.sendall(chunk)
        except OSError:
            pass
        finally:
            self.server.closed.set()


class LocalEcho(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class SessionRelayTests(unittest.TestCase):
    measurements = []

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.protection.session_relay'), '缺少会话转发器实现')
        from src.protection.session_relay import SessionRelay
        from src.protection.relay_identity import ClientProof, ProxyProof
        self.Relay, self.ClientProof, self.ProxyProof = SessionRelay, ClientProof, ProxyProof
        self.upstream = LocalEcho(('127.0.0.1', 0), EchoHandler)
        self.upstream.accepted = threading.Event()
        self.upstream.closed = threading.Event()
        self.upstream.received_bytes = 0
        thread = threading.Thread(target=self.upstream.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        thread.start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        port = self.upstream.server_address[1]
        self.config = Config(port, 25002 if port != 25002 else 25003, '203.0.113.1', 'https://example.test/ip')
        self.binding = BrowserBinding(r'C:\synthetic-browser\chrome.exe', r'C:\synthetic-data',
                                      'Default', 'synthetic-session', 101, 1000, ((102, 1001),))
        self.owner = (self.config.manager_port, port, 501, '900', r'c:\synthetic-pm.exe', 'a' * 64)
        self.provider_gate = None
        self.bad_evidence = False
        def provider(config, binding, sample_id):
            if self.provider_gate is not None:
                self.provider_gate.wait(2)
            return BrowserBindingEvidence(
                binding, sample_id, time.monotonic(), 'pass', 'pass', 'pass',
                config.proxy_port, self.owner, config.expected_ip,
                source='runtime', expires_at=time.monotonic() + 0.8,
                request_profile_status='unknown' if self.bad_evidence else 'pass',
                request_profile_directory='Default', request_profile_source='selected_profile_context')
        def detector(config):
            ok = Check('pass', '合成测试')
            return Detection(ok, ok, ok, ok, Check('unknown', '未验'), mapping=ok,
                             target_trace=ok, _owner_evidence=self.owner)
        self.monitor = MonitorSession(self.config, detector=detector, binding_provider=provider,
                                      browser_binding=self.binding, interval_seconds=0.04, max_age_seconds=0.8)
        self.addCleanup(self.monitor.stop)
        outer = self
        class SyntheticVerifier:
            def listener(self, config):
                return outer.ProxyProof(outer.owner, time.monotonic())
            def client(self, binding, accepted):
                return outer.ClientProof(accepted.getpeername(), accepted.getsockname(),
                                         102, 1001, binding.executable, 101, 1000, time.monotonic())
            def upstream(self, config, connected):
                return outer.ProxyProof(outer.owner, time.monotonic(), connected.getsockname(), connected.getpeername())
        self.verifier = SyntheticVerifier()
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)

    def wait_for(self, predicate, seconds=2):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            threading.Event().wait(0.005)
        self.fail('等待本地验证条件超时')

    def relay(self, seconds=0.5, *, bind=True):
        relay = self.Relay(self.monitor, self.config, verifier=self.verifier, max_lease_seconds=seconds)
        self.addCleanup(relay.stop)
        if bind:
            relay.bind(self.binding)
        return relay

    def connect(self, relay):
        client = socket.create_connection(relay.endpoint, timeout=1)
        client.settimeout(1)
        self.addCleanup(client.close)
        return client

    def assert_closed(self, client):
        try:
            self.assertEqual(client.recv(1), b'')
        except (ConnectionResetError, ConnectionAbortedError):
            pass

    def test_default_unbound_and_missing_or_forged_lease_never_listen(self):
        relay = self.relay(bind=False)
        self.assertIsNone(relay.endpoint)
        with self.assertRaises(ValueError):
            relay.start(self.monitor.relay_lease())
        relay.bind(self.binding)
        for lease in (None, True, replace(self.monitor.relay_lease())):
            with self.subTest(lease_type=type(lease).__name__), self.assertRaises(ValueError):
                relay.start(lease)
            self.assertIsNone(relay.endpoint)

    def test_real_bidirectional_forwarding_and_stop_close_only_owned_sockets(self):
        relay = self.relay()
        relay.start(self.monitor.relay_lease())
        self.assertEqual(relay.endpoint[0], '127.0.0.1')
        client = self.connect(relay)
        payload = b'local-session-payload'
        client.sendall(payload)
        self.assertEqual(client.recv(len(payload)), payload)
        before = time.monotonic()
        relay.stop()
        self.assert_closed(client)
        self.assertTrue(self.upstream.closed.wait(1))
        elapsed = time.monotonic() - before
        self.measurements.append({'case': 'explicit_stop_both_sockets', 'elapsed_ms': elapsed * 1000})
        self.assertLess(elapsed, 1)
        with socket.create_connection(self.upstream.server_address, timeout=1) as control:
            control.sendall(b'control')
            self.assertEqual(control.recv(7), b'control')
        self.assertEqual(relay.snapshot().protection, 'not_enabled')

    def test_unknown_boolean_wrong_pid_and_reused_pid_never_reach_upstream(self):
        original = self.verifier.client
        cases = [lambda *args: None, lambda *args: True,
                 lambda *args: replace(original(*args), pid=999),
                 lambda *args: replace(original(*args), created=9999),
                 lambda *args: replace(original(*args), sampled_at=time.monotonic() - 10),
                 lambda *args: replace(original(*args), client_endpoint=('127.0.0.1', 1))]
        for checker in cases:
            with self.subTest(checker=checker):
                self.verifier.client = checker
                relay = self.relay()
                relay.start(self.monitor.relay_lease())
                client = self.connect(relay)
                client.sendall(b'must-not-forward')
                self.assert_closed(client)
                self.assertFalse(self.upstream.accepted.is_set())
                relay.stop()

    def test_wrong_upstream_owner_prevents_listener_creation(self):
        self.verifier.listener = lambda config: self.ProxyProof(('wrong-owner',), time.monotonic())
        relay = self.relay()
        with self.assertRaises(ValueError):
            relay.start(self.monitor.relay_lease())
        self.assertIsNone(relay.endpoint)

    def test_connected_upstream_must_match_before_any_payload(self):
        self.verifier.upstream = lambda *args: None
        relay = self.relay()
        relay.start(self.monitor.relay_lease())
        client = self.connect(relay)
        client.sendall(b'must-not-forward')
        self.assert_closed(client)
        self.assertTrue(self.upstream.closed.wait(1))
        self.assertEqual(self.upstream.received_bytes, 0)

    def test_expired_lease_closes_both_sides_and_rejects_reconnect(self):
        relay = self.relay(seconds=0.15)
        lease = self.monitor.relay_lease()
        relay.start(lease)
        endpoint = relay.endpoint
        client = self.connect(relay)
        client.sendall(b'x')
        self.assertEqual(client.recv(1), b'x')
        deadline = min(lease.expires_at, lease.accepted_at + 0.15)
        self.assert_closed(client)
        self.assertTrue(self.upstream.closed.wait(1))
        lateness = time.monotonic() - deadline
        self.measurements.append({'case': 'lease_expiry_both_sockets', 'deadline_lateness_ms': lateness * 1000})
        self.assertLess(lateness, 0.5)
        with self.assertRaises(OSError):
            socket.create_connection(endpoint, timeout=0.2)
        self.assertEqual(relay.snapshot().reason_code, 'lease_expired')

    def test_replayed_lease_does_not_extend_but_new_complete_evidence_can_renew(self):
        relay = self.relay(seconds=0.25)
        lease = self.monitor.relay_lease()
        relay.start(lease)
        self.assertFalse(relay.renew(lease))
        self.wait_for(lambda: self.monitor.relay_lease().sequence > lease.sequence)
        fresh = self.monitor.relay_lease()
        self.assertTrue(relay.renew(fresh))
        self.assertFalse(relay.renew(fresh))
        client = self.connect(relay)
        client.sendall(b'new-proof')
        self.assertEqual(client.recv(9), b'new-proof')

    def test_monitor_alarm_or_binding_invalidation_closes_existing_flow(self):
        for invalidate in (lambda: setattr(self, 'bad_evidence', True), self.monitor.invalidate_binding):
            if self.bad_evidence:
                self.bad_evidence = False
                self.monitor.resume()
                self.wait_for(lambda: self.monitor.relay_lease() is not None)
            relay = self.relay()
            relay.start(self.monitor.relay_lease())
            client = self.connect(relay)
            client.sendall(b'x')
            self.assertEqual(client.recv(1), b'x')
            before = time.monotonic()
            invalidate()
            self.assert_closed(client)
            elapsed = time.monotonic() - before
            self.measurements.append({'case': 'binding_invalidation' if not self.bad_evidence else 'monitor_alarm',
                                      'elapsed_ms': elapsed * 1000})
            self.assertLess(elapsed, 0.5)
            self.assertEqual(relay.snapshot().reason_code, 'lease_revoked')

    def test_blocked_identity_lookup_cannot_outlive_lease_or_open_upstream_late(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        original = self.verifier.client
        def blocked(*args):
            entered.set()
            gate.wait(2)
            return original(*args)
        self.verifier.client = blocked
        relay = self.relay(seconds=0.15)
        relay.start(self.monitor.relay_lease())
        client = self.connect(relay)
        self.assertTrue(entered.wait(1))
        self.assert_closed(client)
        gate.set()
        threading.Event().wait(0.05)
        self.assertFalse(self.upstream.accepted.is_set())

    def test_rebinding_closes_existing_stream_and_cannot_reopen(self):
        relay = self.relay()
        lease = self.monitor.relay_lease()
        relay.start(lease)
        client = self.connect(relay)
        client.sendall(b'x')
        self.assertEqual(client.recv(1), b'x')
        changed_at = time.monotonic()
        self.assertLess(changed_at, min(lease.expires_at, lease.accepted_at + 0.5))
        self.assertEqual(relay.snapshot().state, 'listening')
        with self.assertRaises(ValueError):
            relay.bind(replace(self.binding, session_id='other-session'))
        self.assertEqual(relay.snapshot().state, 'closed', 'binding change must close synchronously')
        self.assertEqual(relay.snapshot().reason_code, 'binding_changed')
        self.assert_closed(client)
        self.measurements.append({'case': 'explicit_rebind_closes_before_lease_deadline',
                                  'close_ms': (time.monotonic()-changed_at)*1000,
                                  'remaining_lease_ms': (min(lease.expires_at, lease.accepted_at+0.5)-changed_at)*1000})
        with self.assertRaises(ValueError):
            relay.start(self.monitor.relay_lease())

    def test_monitor_stall_without_new_complete_evidence_expires_lease(self):
        relay = self.relay(seconds=0.15)
        relay.start(self.monitor.relay_lease())
        gate = threading.Event()
        self.addCleanup(gate.set)
        self.provider_gate = gate
        client = self.connect(relay)
        client.sendall(b'x')
        self.assertEqual(client.recv(1), b'x')
        self.assert_closed(client)
        self.assertEqual(relay.snapshot().reason_code, 'lease_expired')

    def test_watchdog_exception_closes_already_open_socket_pair(self):
        relay = self.relay()
        relay.start(self.monitor.relay_lease())
        client = self.connect(relay)
        client.sendall(b'x')
        self.assertEqual(client.recv(1), b'x')
        original = relay._live
        def live():
            if threading.current_thread().name == 'dedicated-relay-watch':
                raise RuntimeError('synthetic-watchdog-error')
            return original()
        with patch.object(relay, '_live', live):
            self.assert_closed(client)
            self.wait_for(lambda: relay.snapshot().state == 'closed')
        self.assertEqual(relay.snapshot().reason_code, 'watchdog_error')
        self.assertNotIn('synthetic-watchdog-error', repr(relay.snapshot()))

    def test_worker_exception_closes_session_without_raw_error(self):
        relay = self.relay()
        with patch.object(relay, '_pump', side_effect=RuntimeError('synthetic-private-error')):
            relay.start(self.monitor.relay_lease())
            client = self.connect(relay)
            client.sendall(b'x')
            self.assert_closed(client)
            self.wait_for(lambda: relay.snapshot().state == 'closed')
        self.assertEqual(relay.snapshot().reason_code, 'worker_error')
        self.assertNotIn('synthetic-private-error', repr(relay.snapshot()))

    def test_start_validation_does_not_hold_relay_lock(self):
        relay = self.relay(seconds=0.7)
        original = self.monitor.accepts_relay_lease
        responsiveness = []
        def validate(lease):
            observed = threading.Event()
            def inspect():
                relay.snapshot()
                observed.set()
            observer = threading.Thread(target=inspect, daemon=True)
            observer.start()
            responsiveness.append(observed.wait(0.1))
            return original(lease)
        with patch.object(self.monitor, 'accepts_relay_lease', validate):
            relay.start(self.monitor.relay_lease())
        self.assertTrue(all(responsiveness), '监测调用持有转发锁，阻塞关流线程')

    def test_real_issuer_with_future_clock_cannot_extend_relay_lease(self):
        previous = self.monitor
        previous.stop()
        def future_provider(*args):
            evidence = previous._binding_provider(*args)
            return replace(evidence, sampled_at=evidence.sampled_at + 60,
                           expires_at=evidence.expires_at + 60)
        self.monitor = MonitorSession(self.config, detector=previous._detector,
                                      binding_provider=future_provider, browser_binding=self.binding,
                                      clock=lambda: time.monotonic() + 60,
                                      interval_seconds=0.04, max_age_seconds=0.8)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)
        lease = self.monitor.relay_lease()
        self.assertTrue(self.monitor.accepts_relay_lease(lease))
        self.assertGreater(lease.accepted_at, time.monotonic())
        relay = self.relay()
        with self.assertRaises(ValueError):
            relay.start(lease)
        self.assertIsNone(relay.endpoint)

    def test_monitor_lock_stall_during_renew_cannot_block_expiry(self):
        relay = self.relay(seconds=0.2)
        lease = self.monitor.relay_lease()
        relay.start(lease)
        client = self.connect(relay)
        client.sendall(b'x')
        self.assertEqual(client.recv(1), b'x')
        entered, released = threading.Event(), threading.Event()
        self.addCleanup(released.set)
        def hold_monitor():
            with self.monitor._cv:
                entered.set()
                released.wait(2)
        holder = threading.Thread(target=hold_monitor, daemon=True)
        holder.start()
        self.assertTrue(entered.wait(1))
        renewer = threading.Thread(target=relay.renew, args=(lease,), daemon=True)
        renewer.start()
        self.assert_closed(client)
        self.assertTrue(self.upstream.closed.wait(1))
        late = time.monotonic() - (lease.accepted_at + 0.2)
        self.measurements.append({'case': 'monitor_lock_stall', 'deadline_lateness_ms': late * 1000})
        self.assertLess(late, 0.5)
        self.assertTrue(renewer.is_alive())
        released.set()
        holder.join(1)
        renewer.join(1)
        self.assertEqual(relay.snapshot().reason_code, 'lease_expired')

    @unittest.skipUnless(os.name == 'nt', 'Windows native ABI')
    def test_real_windows_owner_queries_and_forwarding_fit_short_lease(self):
        from src.protection.relay_identity import _native_proxy_owner, _process
        manager = socket.socket()
        self.addCleanup(manager.close)
        manager.bind(('127.0.0.1', 0))
        manager.listen(1)
        with open(sys.executable, 'rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        self.config = replace(self.config, manager_port=manager.getsockname()[1],
                              manager_executable=sys.executable, manager_sha256=digest)
        with _process(os.getpid()) as process:
            self.binding = replace(self.binding, executable=process['path'], root_pid=os.getpid(),
                                   root_created=int(process['created']), network_processes=((os.getpid() + 100000, 1),))
        self.owner = _native_proxy_owner(self.config)
        self.assertIsNotNone(self.owner)
        previous = self.monitor
        previous.stop()
        # Only browser/monitor evidence is synthetic; both TCP owners are this Python process.
        self.monitor = MonitorSession(self.config, detector=previous._detector,
                                      binding_provider=previous._binding_provider, browser_binding=self.binding,
                                      interval_seconds=0.04, max_age_seconds=0.8)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)
        relay = self.Relay(self.monitor, self.config, max_lease_seconds=0.5)
        self.addCleanup(relay.stop)
        relay.bind(self.binding)
        before = time.monotonic()
        relay.start(self.monitor.relay_lease())
        client = self.connect(relay)
        client.sendall(b'native-owned-sockets')
        self.assertEqual(client.recv(20), b'native-owned-sockets')
        elapsed = time.monotonic() - before
        self.measurements.append({'case': 'native_full_relay_start_to_echo', 'elapsed_ms': elapsed * 1000})
        self.assertLess(elapsed, 0.5)
        relay.stop()
        self.assert_closed(client)
        self.assertEqual(relay.snapshot().protection, 'not_enabled')

    @unittest.skipUnless(os.name == 'nt', 'Windows native ABI')
    def test_native_cross_process_binding_accepts_a_and_rejects_b_before_upstream(self):
        from src.protection.relay_identity import WindowsRelayVerifier, _native_proxy_owner, _process
        script = '''import json,socket,sys
print('ready',flush=True)
port=sys.stdin.readline()
if port:
 try:
  with socket.create_connection(('127.0.0.1',int(port)),timeout=2) as client:
   client.sendall(b'probe')
   response=client.recv(5)
  print(json.dumps({'echo':response==b'probe'}),flush=True)
 except OSError:
  print(json.dumps({'echo':False}),flush=True)
 sys.stdin.readline()
'''
        def read_line(process):
            result, finished = [], threading.Event()
            def read():
                result.append(process.stdout.readline())
                finished.set()
            threading.Thread(target=read, daemon=True).start()
            self.assertTrue(finished.wait(3), '自有客户端未在期限内响应')
            self.assertTrue(result[0])
            return result[0].strip()
        def finish(process):
            if not process.stdin.closed:
                process.stdin.close()
            self.assertEqual(process.wait(timeout=4), 0)
            process.stdout.close()
            process.stderr.close()
        clients = []
        for _ in range(2):
            process = subprocess.Popen([sys.executable, '-B', '-u', '-c', script], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            self.addCleanup(finish, process)
            self.assertEqual(read_line(process), 'ready')
            clients.append(process)
        first, second = clients
        with _process(first.pid) as a, _process(second.pid) as b:
            self.assertNotEqual(a['pid'], b['pid'])
            expected = [(a['pid'], int(a['created'])), (b['pid'], int(b['created']))]
            self.binding = replace(self.binding, executable=a['path'], root_pid=a['pid'],
                                   root_created=int(a['created']), network_processes=((1, 1),))
        manager = socket.socket()
        self.addCleanup(manager.close)
        manager.bind(('127.0.0.1', 0))
        manager.listen(1)
        with open(sys.executable, 'rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        self.config = replace(self.config, manager_port=manager.getsockname()[1],
                              manager_executable=sys.executable, manager_sha256=digest)
        self.owner = _native_proxy_owner(self.config)
        self.assertIsNotNone(self.owner)
        previous = self.monitor
        previous.stop()
        self.monitor = MonitorSession(self.config, detector=previous._detector,
                                      binding_provider=previous._binding_provider, browser_binding=self.binding,
                                      interval_seconds=0.04, max_age_seconds=0.8)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)
        observed = []
        class RecordingNativeVerifier(WindowsRelayVerifier):
            def client(self, binding, accepted):
                proof = super().client(binding, accepted)
                if proof is not None:
                    observed.append((proof.pid, proof.created))
                return proof
        relay = self.Relay(self.monitor, self.config, verifier=RecordingNativeVerifier(), max_lease_seconds=0.5)
        self.addCleanup(relay.stop)
        relay.bind(self.binding)
        relay.start(self.monitor.relay_lease())
        for index, process in enumerate(clients):
            before = time.monotonic()
            process.stdin.write(str(relay.endpoint[1]) + '\n')
            process.stdin.flush()
            self.assertEqual(json.loads(read_line(process))['echo'], index == 0)
            self.assertEqual(self.upstream.received_bytes, 5)
            if index == 0:
                self.upstream.accepted.clear()
            else:
                self.assertFalse(self.upstream.accepted.is_set())
                self.measurements.append({'case': 'native_other_process_rejected',
                                          'elapsed_ms': (time.monotonic() - before) * 1000,
                                          'upstream_bytes_from_rejected_process': 0})
        self.assertEqual(observed, expected)
        self.assertEqual(relay.snapshot().state, 'listening')


if __name__ == '__main__':
    unittest.main()
