"""Production issuers and local TCP; synthetic Chrome/CDP/policy/process boundaries."""
from dataclasses import replace
import secrets
import socket
import threading
import time
import unittest
from unittest.mock import patch

import test_protected_bootstrap_integration as base
from src.browser import request_probe
from src.core import backend
from src.core.monitoring import LayeredMonitorSession, LocalGuardEvidence
from src.protection.session_relay import ProductionBootstrapBridge


class ProductionIntegrationTests(base.ProtectedBootstrapIntegrationTests):
    def test_old_bootstrap_cannot_use_unbounded_monitor_sampling(self):
        bridge, probe, reader, transport, requests, reads, endpoint = self.production_fixture()
        self.monitor._sample_limit = None
        with self.assertRaises(request_probe.ProbeError):
            bridge(self.config, self.monitor.relay_binding, secrets.token_hex(16))
        self.assertIsNone(bridge.last_route)
        self.assertFalse(self.relay._diagnostic_used)

    def prepare_production_fixture(self):
        old_bridge, old_probe, reader, transport, requests, reads, endpoint = self.production_fixture()
        self.monitor.stop()
        # The fixture has not performed any diagnostic. Replace only its injected owners.
        self.relay._monitor = None
        self.relay._request_authority = None
        plan = request_probe.ProductionProbePlan(old_probe.plan, reader.plan.digest, 'Default')
        cancel = threading.Event()
        grant = request_probe.ProductionSessionGrant(plan, cancel)
        grant.consume_launch(plan)
        bridge = ProductionBootstrapBridge(self.relay, reader)
        probe = request_probe.ProductionProbe(plan, old_probe._process, transport, grant, reader, bridge.gate)
        probe._runtime_verified = True
        self.addCleanup(probe.close)
        self.enterContext(patch.object(probe._identity, 'poll', return_value=old_probe.session_evidence))
        binding = probe.binding()
        guards = []
        self.monitor = LayeredMonitorSession(self.config, browser_binding=binding,
            binding_key=('a'*64,binding.root_pid,binding.root_created,binding.session_id),
            exit_validator=probe.accepts_exit_evidence,
            guard_validator=lambda value:any(value is item for item in guards), lease_seconds=0.5)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()
        start = time.monotonic()
        result = backend.detect(self.config)
        self.assertTrue(self.monitor.accept_manager_sample(result,started_at=start,completed_at=time.monotonic()))
        self.relay.attach_monitor(self.monitor)
        bridge.attach_probe(probe)
        sample_id = secrets.token_hex(16)
        bridge(self.config,binding,sample_id)
        original = probe.last_result
        evidence = probe.seal_first_exit(bridge.last_route)
        self.assertEqual(evidence.sampled_at,original.started_at)
        self.assertAlmostEqual(evidence.expires_at-evidence.sampled_at,30)
        self.assertLessEqual(original.expires_at-original.intent.issued_at,5)
        self.assertTrue(self.monitor.accept_exit_sample(evidence))
        def guard():
            now = time.monotonic()
            policy = self.relay.read_policy(reader)
            item = LocalGuardEvidence(binding,self.owner,len(guards)+1,now,time.monotonic(),now+0.5,policy)
            guards.append(item)
            return item
        first = guard()
        lease = self.monitor.issue_forward_lease(first)
        self.relay.promote(lease,bridge.last_route,policy=first.policy)
        probe.route_provider=lambda:guards[-1] if time.monotonic()<guards[-1].expires_at else None
        return probe, guard, evidence

    def test_first_bootstrap_and_new_exit_sample_use_distinct_original_receipts(self):
        probe, guard, first = self.prepare_production_fixture()
        before = self.upstream.received_bytes
        fresh = probe.collect_exit(self.config,self.monitor.relay_binding,secrets.token_hex(16))
        self.assertNotEqual(first.sample_id,fresh.sample_id)
        self.assertIsNot(first,fresh)
        self.assertGreater(self.upstream.received_bytes,before)
        self.assertTrue(self.monitor.accept_exit_sample(fresh))
        latest = guard()
        lease = self.monitor.issue_forward_lease(latest)
        self.assertTrue(self.relay.renew_production(lease,policy=latest.policy))
        self.assertFalse(self.relay.renew(lease))
        self.assertFalse(probe.accepts_exit_evidence(replace(fresh)))
        self.assertEqual(first.expires_at,first.sampled_at+30)

    def test_active_normal_flow_survives_multiple_short_leases_then_stops(self):
        probe, guard, first = self.prepare_production_fixture()
        client = socket.create_connection(self.relay.endpoint,timeout=1)
        self.addCleanup(client.close)
        client.settimeout(1)
        client.sendall(b'CONNECT assets.example.test:443 HTTP/1.1\r\nHost: assets.example.test:443\r\n\r\n')
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            response.extend(client.recv(1))
        self.assertTrue(response.startswith(b'HTTP/1.1 200'))
        start = time.monotonic()
        while time.monotonic()-start<0.8:
            latest=guard(); lease=self.monitor.issue_forward_lease(latest)
            self.assertTrue(self.relay.renew_production(lease,policy=latest.policy))
            self.assertEqual(lease.sample_id,first.sample_id)
            client.sendall(b'x');self.assertEqual(client.recv(1),b'x')
            threading.Event().wait(0.08)
        self.monitor.stop()
        self.assert_closed(client)
        self.assertEqual(self.relay.snapshot().state,'closed')
        self.assertFalse(self.relay.renew_production(lease,policy=latest.policy))


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(ProductionIntegrationTests(name) for name in
                              ProductionIntegrationTests.__dict__ if name.startswith('test_'))
