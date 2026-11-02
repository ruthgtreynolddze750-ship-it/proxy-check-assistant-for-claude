"""Bounded bootstrap with own sockets; policy/CDP/monitor evidence is synthetic."""
from dataclasses import replace
import hashlib
import os
import socket
import sys
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from src.core.monitoring import MonitorSession
from src.browser.session_binding import ProcessFact, SessionEvidence
from src.protection import session_relay as relay_module
from src.protection.dedicated_wfp import ApplicationIdentity, PolicyPlan, REQUIRED_FIELDS, plan_objects
import test_session_relay as existing


CONNECT = b'CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n'


class ConnectEcho(existing.EchoHandler):
    def handle(self):
        self.server.accepted_connections.append(self.client_address)
        self.server.accepted.set()
        self.request.settimeout(2)
        try:
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                piece = self.request.recv(1)
                if not piece:
                    return
                header.extend(piece)
            self.server.received_bytes += len(header)
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            while piece := self.request.recv(65536):
                self.server.received_bytes += len(piece)
                self.request.sendall(piece)
        except OSError:
            pass
        finally:
            self.server.closed.set()


class RequestAuthority:
    def __init__(self):
        self.issued = []

    def accepts_request(self, request):
        return any(item is request for item in self.issued) and not request.revoked.is_set()


class PolicyReader:
    def __init__(self, plan):
        self.plan = plan
        self.objects = {(o['kind'], o['key']): o for o in plan_objects(plan)}

    def identity(self, target, excluded):
        return self.plan.identity

    def capabilities(self):
        return REQUIRED_FIELDS

    def get(self, kind, key):
        return self.objects.get((kind, key))

    def close(self):
        pass


class BootstrapTests(unittest.TestCase):
    measurements = []
    wait_for = existing.SessionRelayTests.wait_for
    connect = existing.SessionRelayTests.connect
    assert_closed = existing.SessionRelayTests.assert_closed

    def setUp(self):
        existing.SessionRelayTests.setUp(self)
        previous = self.monitor
        previous.stop()
        self.monitor = MonitorSession(self.config, detector=previous._detector,
                                      binding_provider=previous._binding_provider, browser_binding=self.binding,
                                      interval_seconds=0.04, max_age_seconds=0.8, max_samples=1)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)
        self.upstream.RequestHandlerClass = ConnectEcho
        self.upstream.accepted_connections = []
        self.authority = RequestAuthority()
        self.relay = self.Relay(self.monitor, self.config, verifier=self.verifier,
                                request_authority=self.authority, max_lease_seconds=0.5)
        self.addCleanup(self.relay.stop)
        self.reservation = self.relay.reserve()
        self.relay.bind(self.binding)
        identity = ApplicationIdentity(self.binding.executable, self.binding.user_data_dir, (), 'a' * 64,
                                       b'test-app-id', ((r'C:\ordinary\chrome.exe', b'excluded'),), 'injected')
        self.plan = PolicyPlan(identity, self.relay.endpoint[1], str(uuid.uuid4()))
        self.reader = PolicyReader(self.plan)

    def inputs(self, *, sample_id='sample-for-diagnostic', duration=0.5, max_bytes=16384):
        now = time.monotonic()
        root = ProcessFact(self.binding.root_pid, self.binding.root_created, 0,
                           self.binding.executable, '', self.binding.user_data_dir, '')
        pid, created = self.binding.network_processes[0]
        network = ProcessFact(pid, created, self.binding.root_pid, self.binding.executable,
                              'utility', '', 'network.mojom.NetworkService')
        evidence = SessionEvidence('pass', 'synthetic', now, now+1, self.binding.session_id, root, (network,),
                                   source='windows_cim', _revoked=threading.Event())
        request = relay_module.TraceRequestGuard(self.binding, self.reservation.reservation_id,
                                                 str(uuid.uuid4()), sample_id, 'owned-context',
                                                 now, now+duration, source='injected')
        self.authority.issued.append(request)
        approval = relay_module.DiagnosticAuthorization(self.reservation.reservation_id, self.plan.digest,
                                                        self.binding, request.request_id, sample_id,
                                                        'synthetic-explicit-approval', now, now+duration, max_bytes)
        policy = self.relay.read_policy(self.plan, backend=self.reader)
        return approval, policy, evidence, request

    def open(self, **kwargs):
        approval, policy, evidence, request = self.inputs(**kwargs)
        self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=request)
        return approval, policy, evidence, request

    def tunnel(self):
        client = self.connect(self.relay)
        client.sendall(CONNECT)
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            response.extend(client.recv(1))
        self.assertTrue(response.startswith(b'HTTP/1.1 200 '))
        client.sendall(b'fixture')
        self.assertEqual(client.recv(7), b'fixture')
        return client

    def test_reserved_port_is_exclusive_and_never_forwards(self):
        self.assertEqual(self.relay.snapshot().state, 'reserved')
        with self.assertRaises(OSError):
            socket.create_connection(self.relay.endpoint, timeout=0.1)
        self.assertFalse(self.upstream.accepted.is_set())
        with socket.socket() as other, self.assertRaises(OSError):
            other.bind(self.relay.endpoint)

    def test_missing_changed_and_copied_policy_proof_are_rejected(self):
        approval, policy, evidence, request = self.inputs()
        for bad in (None, True, replace(policy)):
            with self.subTest(proof_type=type(bad).__name__), self.assertRaises(ValueError):
                self.relay.start_diagnostic(approval, policy=bad, binding_evidence=evidence, request=request)
        self.reader.objects.clear()
        with self.assertRaises(ValueError):
            self.relay.read_policy(self.plan, backend=self.reader)
        self.assertEqual(self.relay.snapshot().state, 'closed')

    def test_unissued_request_wrong_authorization_and_stale_binding_rejected(self):
        approval, policy, evidence, request = self.inputs()
        for bad in (replace(approval, reservation_id='wrong'), replace(approval, request_id='wrong'),
                    replace(approval, expires_at=time.monotonic()-1), replace(approval, max_bytes=True)):
            with self.subTest(approval=repr(bad)), self.assertRaises(ValueError):
                self.relay.start_diagnostic(bad, policy=policy, binding_evidence=evidence, request=request)
        with self.assertRaises(ValueError):
            self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=replace(request))
        evidence._revoked.set()
        with self.assertRaises(ValueError):
            self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=request)
        self.assertFalse(self.upstream.accepted.is_set())

    def test_wrong_connect_target_never_opens_upstream(self):
        self.open()
        client = self.connect(self.relay)
        client.sendall(CONNECT.replace(b'claude.ai', b'example.test'))
        self.assert_closed(client)
        self.assertFalse(self.upstream.accepted.is_set())
        self.assertEqual(self.relay._diagnostic['connections'], 0)
        self.assertEqual(self.relay.snapshot().state, 'diagnostic')
        self.tunnel()

    def test_idle_candidate_does_not_claim_slot_and_route_belongs_to_winner(self):
        _, _, _, request = self.open(duration=0.8)
        entered = threading.Event()
        original = self.relay._read_header
        def read_header(*args, **kwargs):
            entered.set()
            return original(*args, **kwargs)
        with patch.object(self.relay, '_read_header', side_effect=read_header):
            idle = self.connect(self.relay)
            self.assertTrue(entered.wait(0.2))
            self.assertEqual(self.relay._diagnostic['connections'], 0)
            self.assertFalse(self.upstream.accepted.is_set())
            winner = self.tunnel()
            route = self.relay.complete_diagnostic(request)
        self.assertEqual(route.client_endpoint, winner.getsockname())
        self.assertNotEqual(route.client_endpoint, idle.getsockname())
        self.assertEqual(route.connect_count, 1)
        self.assertEqual(len(self.upstream.accepted_connections), 1)
        self.assert_closed(idle)
        self.assertEqual(self.relay.snapshot().state, 'sealed')

    def test_two_valid_candidates_compete_for_only_one_upstream(self):
        self.open(duration=0.8)
        barrier = threading.Barrier(2)
        original = self.relay._valid_connect
        def validate(header):
            valid = original(header)
            barrier.wait(0.4)
            return valid
        with patch.object(self.relay, '_valid_connect', side_effect=validate):
            clients = [self.connect(self.relay), self.connect(self.relay)]
            for client in clients:
                client.sendall(CONNECT)
            responses = []
            for client in clients:
                response = bytearray()
                try:
                    while not response.endswith(b'\r\n\r\n'):
                        piece = client.recv(1)
                        if not piece:
                            break
                        response.extend(piece)
                except (ConnectionResetError, ConnectionAbortedError):
                    pass
                responses.append(bytes(response))
        winners = [client for client, response in zip(clients, responses) if response.startswith(b'HTTP/1.1 200 ')]
        self.assertEqual(len(winners), 1)
        winners[0].sendall(b'winner')
        self.assertEqual(winners[0].recv(6), b'winner')
        self.assertEqual(self.relay._diagnostic['connections'], 1)
        self.assertEqual(len(self.upstream.accepted_connections), 1)
        self.assertEqual(self.relay.snapshot().state, 'diagnostic')

    def test_diagnostic_is_single_use_and_absolute_deadline_closes_stream(self):
        inputs = self.open(duration=0.15)
        client = self.tunnel()
        approval, policy, evidence, request = inputs
        with self.assertRaises(ValueError):
            self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=request)
        self.assert_closed(client)
        self.assertTrue(self.upstream.closed.wait(1))
        self.assertEqual(self.relay.snapshot().reason_code, 'diagnostic_expired')

    def test_second_connection_closes_only_itself(self):
        self.open(max_bytes=1024)
        first = self.tunnel()
        second = self.connect(self.relay)
        second.sendall(CONNECT)
        self.assert_closed(second)
        first.sendall(b'still-first')
        self.assertEqual(first.recv(11), b'still-first')
        self.assertEqual(len(self.upstream.accepted_connections), 1)
        self.assertEqual(self.relay._diagnostic['connections'], 1)
        self.assertEqual(self.relay.snapshot().state, 'diagnostic')

    def test_candidate_eof_invalid_and_oversize_headers_do_not_close_winner(self):
        self.open(duration=0.8)
        winner = self.tunnel()
        for header in (b'CONNECT incomplete', CONNECT.replace(b'claude.ai', b'example.test'), b'x'*8193):
            with self.subTest(header_size=len(header)):
                candidate = self.connect(self.relay)
                candidate.sendall(header)
                candidate.shutdown(socket.SHUT_WR)
                self.assert_closed(candidate)
                winner.sendall(b'ok')
                self.assertEqual(winner.recv(2), b'ok')
        self.assertEqual(len(self.upstream.accepted_connections), 1)

    def test_winner_failure_closes_session_without_refunding_slot(self):
        self.open()
        self.verifier.upstream = lambda *args:None
        client = self.connect(self.relay)
        client.sendall(CONNECT)
        self.assert_closed(client)
        self.assertEqual(self.relay.snapshot().reason_code, 'upstream_unconfirmed')
        self.assertEqual(self.relay._diagnostic['connections'], 1)
        self.assertEqual(len(self.upstream.accepted_connections), 1)
        self.assertEqual(self.upstream.received_bytes, 0)

    def test_ended_winner_does_not_allow_replacement_upstream(self):
        self.open(duration=0.8)
        first = self.tunnel()
        first.shutdown(socket.SHUT_WR)
        self.assert_closed(first)
        self.wait_for(lambda:self.relay.snapshot().active_connections == 0)
        second = self.connect(self.relay)
        second.sendall(CONNECT)
        self.assert_closed(second)
        self.assertEqual(self.relay._diagnostic['connections'], 1)
        self.assertEqual(len(self.upstream.accepted_connections), 1)
        self.assertEqual(self.relay.snapshot().state, 'diagnostic')

    def test_unclassified_candidate_exception_still_closes_entire_session(self):
        self.open()
        winner = self.tunnel()
        with patch.object(self.relay, '_read_header', side_effect=ValueError('unclassified fixture failure')):
            extra = self.connect(self.relay)
            extra.sendall(CONNECT)
            self.assert_closed(extra)
            self.assert_closed(winner)
        self.assertEqual(self.relay.snapshot().reason_code, 'worker_error')

    def test_candidate_binding_change_still_closes_entire_session(self):
        self.open()
        winner = self.tunnel()
        original = self.verifier.client
        self.verifier.client = lambda *args:replace(original(*args), root_created=9999)
        extra = self.connect(self.relay)
        extra.sendall(CONNECT)
        self.assert_closed(extra)
        self.assert_closed(winner)
        self.assertEqual(self.relay.snapshot().reason_code, 'binding_changed')

    def test_byte_budget_stops_forwarding_without_overrun(self):
        self.open(max_bytes=1024)
        client = self.tunnel()
        client.sendall(b'x' * 2048)
        while True:
            try:
                if not client.recv(4096):
                    break
            except (ConnectionResetError, ConnectionAbortedError):
                break
        self.wait_for(lambda: self.relay.snapshot().state == 'closed')
        self.assertEqual(self.relay.snapshot().reason_code, 'diagnostic_byte_limit')
        self.assertLessEqual(self.upstream.received_bytes, 1024)

    def test_monitor_stop_revokes_diagnostic_without_waiting_for_deadline(self):
        self.open()
        client = self.tunnel()
        self.monitor.stop()
        self.assert_closed(client)
        self.assertEqual(self.relay.snapshot().reason_code, 'diagnostic_revoked')

    def test_stop_during_upstream_check_cannot_open_diagnostic(self):
        approval, policy, evidence, request = self.inputs()
        original = self.verifier.listener
        def stop_during_check(config):
            proof = original(config)
            self.monitor.stop()
            return proof
        self.verifier.listener = stop_during_check
        with self.assertRaises(ValueError):
            self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=request)
        self.assertEqual(self.relay.snapshot().state, 'reserved')
        self.assertFalse(self.upstream.accepted.is_set())

    def test_retired_diagnostic_worker_cannot_close_sealed_session(self):
        original_pump, original_connection = self.relay._pump, self.relay._connection
        released, completed = threading.Event(), threading.Event()
        self.addCleanup(released.set)
        def late_error(*args):
            original_pump(*args)
            released.wait(1)
            raise OSError('retired diagnostic socket')
        def connection(*args):
            try:
                original_connection(*args)
            finally:
                completed.set()
        self.relay._pump = late_error
        self.relay._connection = connection
        _, _, _, request = self.open()
        client = self.tunnel()
        self.relay.complete_diagnostic(request)
        released.set()
        self.assertTrue(completed.wait(1))
        self.assert_closed(client)
        self.assertEqual(self.relay.snapshot().state, 'sealed')

    def test_blocked_policy_read_cannot_block_deadline_or_revive_closed_session(self):
        from src.protection.dedicated_wfp import PolicyReadbackVerifier
        self.open(duration=0.2)
        client = self.tunnel()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        original = self.reader.get
        def blocked(*args):
            entered.set()
            release.wait(2)
            return original(*args)
        self.reader.get = blocked
        reader = PolicyReadbackVerifier(self.plan, backend_factory=lambda: self.reader)
        results = []
        def refresh():
            try:
                self.relay.read_policy(reader)
            except ValueError:
                results.append('closed')
        worker = threading.Thread(target=refresh, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(1))
        self.assert_closed(client)
        self.assertTrue(worker.is_alive())
        release.set()
        worker.join(1)
        self.assertEqual(results, ['closed'])
        self.assertEqual(self.relay.snapshot().reason_code, 'diagnostic_expired')

    def test_complete_seals_and_old_lease_cannot_promote(self):
        old = self.monitor.relay_lease()
        endpoint = self.relay.endpoint
        _, _, _, request = self.open()
        client = self.tunnel()
        route = self.relay.complete_diagnostic(request)
        self.assert_closed(client)
        self.assertEqual(self.relay.endpoint, endpoint)
        self.assertEqual(self.relay.snapshot().state, 'sealed')
        self.assertEqual(route.request_id, request.request_id)
        self.assertEqual(route.connect_count, 1)
        with self.assertRaises(ValueError):
            self.relay.promote(old, route, policy=self.relay.read_policy(self.plan, backend=self.reader))

    def test_default_thirty_second_monitor_schedule_cannot_be_used_for_short_lease(self):
        slow = MonitorSession(self.config)
        with self.assertRaises(ValueError):
            self.Relay(slow, self.config)

    def test_zero_initialization_to_issued_monitor_lease_keeps_same_port(self):
        self._bootstrap_lifecycle('synthetic_identity')

    @unittest.skipUnless(os.name == 'nt', 'Windows native ABI')
    def test_zero_initialization_with_native_socket_owners_keeps_same_port(self):
        from src.protection.relay_identity import WindowsRelayVerifier, _process, _native_proxy_owner
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
                                   root_created=int(process['created']), network_processes=((os.getpid()+100000, 1),))
        self.plan = replace(self.plan, identity=replace(self.plan.identity, executable=self.binding.executable))
        self.owner = _native_proxy_owner(self.config)
        self.assertIsNotNone(self.owner)
        self.verifier = WindowsRelayVerifier()
        self._bootstrap_lifecycle('native_own_python_identity')

    def _bootstrap_lifecycle(self, scope):
        previous = self.monitor
        previous.stop()
        self.relay.stop()
        self.relay = self.Relay(None, self.config, verifier=self.verifier, request_authority=self.authority,
                                max_lease_seconds=0.5)
        self.addCleanup(self.relay.stop)
        self.reservation = self.relay.reserve()
        endpoint = self.relay.endpoint
        self.plan = replace(self.plan, relay_port=endpoint[1], deployment_id=str(uuid.uuid4()))
        self.reader = PolicyReader(self.plan)
        self.relay.read_policy(self.plan, backend=self.reader)
        self.relay.bind(self.binding)
        routes, detector_calls = [], []
        def detector(config):
            detector_calls.append(time.monotonic())
            return previous._detector(config)
        def provider(config, binding, sample_id):
            approval, policy, evidence, request = self.inputs(sample_id=sample_id, duration=0.8)
            self.relay.start_diagnostic(approval, policy=policy, binding_evidence=evidence, request=request)
            self.tunnel()
            routes.append(self.relay.complete_diagnostic(request))
            return previous._binding_provider(config, binding, sample_id)
        self.monitor = MonitorSession(self.config, detector=detector, binding_provider=provider,
                                      browser_binding=self.binding, max_samples=1,
                                      interval_seconds=30, max_age_seconds=2)
        self.addCleanup(self.monitor.stop)
        self.relay.attach_monitor(self.monitor)
        with self.assertRaises(ValueError):
            self.relay.attach_monitor(self.monitor)
        before = time.monotonic()
        self.monitor.start()
        self.wait_for(lambda: self.monitor.relay_lease() is not None)
        lease = self.monitor.relay_lease()
        self.assertEqual(lease.sample_id, routes[0].sample_id)
        policy = self.relay.read_policy(self.plan, backend=self.reader)
        self.assertEqual(self.relay.promote(lease, routes[0], policy=policy), endpoint)
        self.assertEqual(self.relay.endpoint, endpoint)
        self.measurements.append({'case': 'bootstrap_to_monitor_lease_and_same_port_promotion',
                                  'scope': scope,
                                  'elapsed_ms': (time.monotonic()-before)*1000})
        client = self.tunnel()
        threading.Event().wait(0.05)
        self.assertEqual(len(detector_calls), 1)
        timing = self.monitor.last_sample_timing()
        self.assertEqual(timing.sample_id, lease.sample_id)
        self.measurements.append({'case': 'sample_timing', 'scope': scope,
                                  'detector_seconds': timing.detector_seconds,
                                  'provider_seconds': timing.provider_seconds,
                                  'total_seconds': timing.total_seconds})
        self.monitor.stop()
        self.assert_closed(client)
        with self.assertRaises(ValueError):
            self.relay.promote(lease, routes[0], policy=policy)


if __name__ == '__main__':
    unittest.main()
