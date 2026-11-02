"""Real production contracts, fake native/CDP/external-HTTP boundaries, actual localhost TCP."""
from dataclasses import replace
import hashlib
import json
import ntpath
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'browser'))
from test_protected_probe import ProfileTransport
import test_relay_bootstrap as bootstrap
from src.browser import request_probe, session_binding
from src.core import backend
from src.core.monitoring import MonitorSession
from src.protection import dedicated_wfp as wfp
from src.protection.session_relay import SessionRelay, ProtectedBootstrapBridge


class ProtectedBootstrapIntegrationTests(bootstrap.BootstrapTests):
    # unittest's loader below deliberately selects only tests defined on this class.
    measurements = []

    def production_fixture(self, *, connect=True, copy_intent=False, oversize=False):
        self.relay.stop()
        self.monitor.stop()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        executable = root / 'Application/chrome.exe'
        executable.parent.mkdir()
        executable.write_bytes(b'local non-executable fixture')
        data = root / 'fresh-profile'
        data.mkdir()
        profile = data / 'Default'
        pm = root / 'pm-fixture.exe'
        pm.write_bytes(b'trusted local test marker')
        target = session_binding.DedicatedTarget(str(executable), str(data))
        self.config = replace(self.config, expected_ip='203.0.113.9', expected_zone='test-isp',
                              mapping_mode='not_required', manager_executable=str(pm),
                              manager_sha256=hashlib.sha256(pm.read_bytes()).hexdigest())
        owner_row = {'pid': 501, 'started': '900', 'path': str(pm)}
        self.enterContext(patch.object(backend, '_capture_listener_owners', return_value=([owner_row], [owner_row])))
        self.enterContext(patch.object(backend, '_process_present', return_value=True))
        self.enterContext(patch.object(backend, '_manager_owns_port', return_value=True))
        config = self.config
        class LocalManagerResponse:
            status = 200
            def __init__(self, path):
                self.path = path
            def read(self, limit):
                if self.path == '/api/proxies_running':
                    payload = [{'port': config.proxy_port, 'zone': 'test-isp'}]
                elif self.path == '/api/zones':
                    payload = {'zones': [{'name': 'test-isp', 'plan': {'type': 'static_res'}}]}
                else:
                    payload = {}
                return json.dumps(payload).encode()
        class LocalManagerConnection:
            def __init__(self, *args, **kwargs):
                self.path = None
            def request(self, method, path, **kwargs):
                self.path = path
            def getresponse(self):
                return LocalManagerResponse(self.path)
            def close(self):
                pass
        self.enterContext(patch.object(backend.http.client, 'HTTPConnection', LocalManagerConnection))
        requests = []
        def external_http(port, url, timeout, **kwargs):
            requests.append(url)
            if url == config.ip_url:
                return b'203.0.113.9'
            return b'h=claude.ai\nip=203.0.113.9\n'
        self.enterContext(patch.object(backend, '_request_via_proxy', side_effect=external_http))
        self.owner = backend._proxy_owner_snapshot(self.config)
        self.assertIsNotNone(self.owner)
        self.relay = SessionRelay(None, self.config, verifier=self.verifier, max_lease_seconds=0.5)
        self.addCleanup(self.relay.stop)
        reservation = self.relay.reserve()
        with patch.object(request_probe, '_file_version', return_value=request_probe.REVIEWED_VERSION):
            launch = request_probe.prepare_launch(target, reservation.endpoint[1], selected=True)
        identity = wfp.ApplicationIdentity(target.executable, target.user_data_dir, launch.fingerprint,
                                           launch.executable_sha256, b'fixture-app-id',
                                           ((r'C:\ordinary\chrome.exe', b'other-id'),), 'windows_wfp')
        plan = wfp.PolicyPlan(identity, reservation.endpoint[1], 'e3116fb3-71d4-4fa3-83dc-c31eab15fb54')
        native_reads = []
        class NativeBoundary(bootstrap.PolicyReader):
            def __init__(self):
                native_reads.append(time.monotonic())
                super().__init__(plan)
        self.enterContext(patch.object(wfp, 'NativeWfp', NativeBoundary))
        reader = wfp.PolicyReadbackVerifier(plan)
        bridge = ProtectedBootstrapBridge(self.relay, reader)
        self.addCleanup(bridge.close)
        probe_plan = request_probe.ProtectedProbePlan(launch, plan.digest, max_rounds=1)
        approval = request_probe.ProtectedProbeApproval(probe_plan.digest, secrets.token_hex(8), 1,
                                                        time.monotonic()+30, True, True)
        grant = request_probe.ProtectedProbeGrant(probe_plan, approval)
        grant.consume_launch(probe_plan)
        # Chrome creates Default only after the empty-directory launch checks.
        profile.mkdir()
        outer = self
        class SocketProfileTransport(ProfileTransport):
            def __init__(self):
                super().__init__(str(profile))
                self.client = None
                self.trace_oversize = oversize
            def send(self, message, deadline):
                if connect and message['method'] == 'Page.navigate' and message['params'].get('url') == request_probe.TARGET:
                    self.client = socket.create_connection(reservation.endpoint, timeout=1)
                    self.client.settimeout(1)
                    self.client.sendall(bootstrap.CONNECT)
                    response = bytearray()
                    while not response.endswith(b'\r\n\r\n'):
                        piece = self.client.recv(1)
                        if not piece:
                            raise OSError('fixture tunnel closed')
                        response.extend(piece)
                    self.client.sendall(b'fixture TLS traffic')
                    outer.assertEqual(self.client.recv(19), b'fixture TLS traffic')
                super().send(message, deadline)
            def close(self):
                if self.client is not None:
                    self.client.close()
        transport = SocketProfileTransport()
        gate = (lambda intent: bridge.gate(replace(intent))) if copy_intent else bridge.gate
        probe = request_probe._ProtectedProbe(probe_plan, SimpleNamespace(pid=101, poll=lambda: None),
                                               transport, grant, reader, gate)
        self.addCleanup(probe.close)
        # The process/pipe handshake is a simulated native boundary; issuer methods remain real.
        probe._runtime_verified = True
        root_fact = session_binding.ProcessFact(101, 1000, 0, target.executable, '', target.user_data_dir, '')
        net_fact = session_binding.ProcessFact(102, 1001, 101, target.executable,
                                               'utility', '', 'network.mojom.NetworkService')
        now = time.monotonic()
        identity_evidence = session_binding.SessionEvidence('pass', 'fixture', now, now+10, 'integration-binding',
                                root_fact, (net_fact,), source='windows_cim', _revoked=probe._identity._revoked)
        self.enterContext(patch.object(probe._identity, 'poll', return_value=identity_evidence))
        self.enterContext(patch.object(request_probe, 'validate_bound_processes'))
        binding = probe.binding()
        self.relay.bind(binding)
        bridge.attach_probe(probe)
        self.monitor = MonitorSession(config, detector=backend.detect, browser_binding=binding,
                                      binding_provider=bridge, max_samples=1, max_age_seconds=2)
        self.addCleanup(self.monitor.stop)
        self.relay.attach_monitor(self.monitor)
        return bridge, probe, reader, transport, requests, native_reads, reservation.endpoint

    def test_production_issuers_share_original_policy_and_promote_one_fresh_detect(self):
        bridge, probe, reader, transport, requests, reads, endpoint = self.production_fixture()
        before = time.monotonic()
        self.monitor.start()
        self.wait_for(lambda: self.monitor.snapshot().state in ('monitoring', 'alarm'))
        self.assertEqual(self.monitor.snapshot().state, 'monitoring', self.monitor.snapshot().reason_codes)
        self.assertEqual(len(requests), 3)
        self.assertEqual(len(reads), 2, 'bridge must adopt original receipts without re-reading')
        self.assertEqual(probe.grant.rounds_used, 1)
        self.assertTrue(probe.accepts_result(probe.last_result))
        self.assertEqual(probe.last_result.evidence.proxy_status, 'unknown')
        lease = self.monitor.relay_lease()
        self.assertEqual(lease.sample_id, bridge.last_route.sample_id)
        self.assertEqual(lease.proxy_owner, self.owner)
        self.assertEqual(self.relay.promote(lease, bridge.last_route, policy=bridge.last_policy), endpoint)
        self.measurements.append({'case': 'production_contracts_with_bottom_io_fixtures',
                                  'elapsed_ms': (time.monotonic()-before)*1000,
                                  'policy_reads': len(reads), 'fresh_detector_http_calls': len(requests)})
        threading.Event().wait(0.06)
        self.assertEqual(len(requests), 3)
        self.assertEqual(probe.grant.rounds_used, 1)
        self.assert_closed(transport.client)
        with self.assertRaises(ValueError):
            bridge(self.config, probe.binding(), lease.sample_id)

    def test_copied_browser_intent_cannot_open_relay_or_reach_proxy(self):
        _, probe, _, _, requests, _, _ = self.production_fixture(copy_intent=True)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.snapshot().state == 'alarm')
        self.assertIsNone(self.monitor.relay_lease())
        self.assertEqual(probe.grant.rounds_used, 1)
        self.assertEqual(self.upstream.received_bytes, 0)
        self.assertEqual(len(requests), 3)

    def test_complete_profile_events_without_tcp_route_cannot_issue_lease(self):
        bridge, probe, _, _, _, _, _ = self.production_fixture(connect=False)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.snapshot().state == 'alarm')
        self.assertIsNone(self.monitor.relay_lease())
        self.assertIsNone(bridge.last_route)
        self.assertEqual(probe.last_result.evidence.proxy_status, 'unknown')

    def test_browser_byte_limit_failure_revokes_diagnostic_and_never_issues_lease(self):
        bridge, probe, _, _, _, _, _ = self.production_fixture(oversize=True)
        self.monitor.start()
        self.wait_for(lambda: self.monitor.snapshot().state == 'alarm')
        self.assertIsNone(self.monitor.relay_lease())
        self.assertIsNone(bridge.last_route)
        self.assertEqual(self.relay.snapshot().state, 'closed')
        self.assertEqual(probe.grant.rounds_used, 1)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(ProtectedBootstrapIntegrationTests(name) for name in
                              ProtectedBootstrapIntegrationTests.__dict__ if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
