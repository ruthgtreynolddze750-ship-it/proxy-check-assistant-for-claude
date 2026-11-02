"""Synthetic provider inputs only; these tests do not certify a live browser."""
import threading
import time
import unittest
from dataclasses import replace

from src.core import monitoring
from src.core.backend import Check, Config, Detection


def independent_result():
    ok = Check('pass', '合成检查')
    return Detection(ok, ok, ok, Check('unknown', '首页未验'),
                     Check('unknown', '桌面未验'), mapping=ok,
                     target_trace=ok, _owner_evidence=('synthetic-owner', 1))


class BrowserMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(monitoring, 'BrowserBinding'), '缺少浏览器绑定契约')
        self.assertTrue(hasattr(monitoring, 'BrowserBindingEvidence'), '缺少浏览器采样证据契约')
        self.binding = monitoring.BrowserBinding(
            r'C:\synthetic-dedicated\chrome.exe', r'C:\synthetic-data', 'Default',
            'synthetic-session', 101, 1000, ((102, 1001),))
        self.config = Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        self.sessions = []
        self.addCleanup(self.stop_sessions)

    def stop_sessions(self):
        for session in self.sessions:
            session.stop()

    def evidence(self, config, binding, sample_id, **changes):
        result = monitoring.BrowserBindingEvidence(
            binding, sample_id, time.monotonic(), 'pass', 'pass', 'pass',
            config.proxy_port, ('synthetic-owner', 1), config.expected_ip,
            source='runtime', expires_at=time.monotonic() + 0.35,
            request_profile_status='pass', request_profile_directory=binding.profile_directory,
            request_profile_source='selected_profile_context')
        return replace(result, **changes)

    def session(self, provider, **kwargs):
        options = dict(interval_seconds=0.03, max_age_seconds=0.4,
                       detector=lambda config: independent_result(),
                       browser_binding=self.binding, binding_provider=provider)
        options.update(kwargs)
        session = monitoring.MonitorSession(self.config, **options)
        self.sessions.append(session)
        return session

    def await_state(self, session, wanted):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            snapshot = session.snapshot()
            if snapshot.state == wanted:
                return snapshot
            threading.Event().wait(0.005)
        self.fail(f'未达到 {wanted}: {session.snapshot()}')

    def test_missing_provider_never_runs_independent_detector(self):
        calls = []
        session = self.session(None, detector=lambda config: calls.append(config) or independent_result())
        snapshot = session.start()
        self.assertEqual(snapshot.state, 'alarm')
        self.assertEqual(snapshot.scope, 'dedicated_browser')
        self.assertEqual(snapshot.browser_status, 'unknown')
        self.assertIn('browser_provider_missing', snapshot.reason_codes)
        self.assertEqual(calls, [])

    def test_ui_binding_key_is_checked_and_read_only(self):
        key = ('a' * 64, 101, 1000, 'synthetic-session')
        session = self.session(None, binding_key=key)
        self.assertEqual(session.binding_key, key)
        with self.assertRaises(AttributeError):
            session.binding_key = None
        for invalid in (('a' * 64, 999, 1000, 'synthetic-session'),
                        ('a' * 64, 101, 2000, 'synthetic-session'),
                        ('a' * 64, 101, 1000, 'different-session')):
            with self.subTest(key=invalid), self.assertRaises(ValueError):
                self.session(None, binding_key=invalid)

    def test_relay_lease_requires_complete_current_evidence_and_issuer_identity(self):
        self.assertTrue(hasattr(monitoring.MonitorSession, 'relay_lease'), '缺少完整监测租约接口')
        missing = self.session(None)
        self.assertIsNone(missing.relay_lease())
        session = self.session(self.evidence)
        session.start()
        self.await_state(session, 'monitoring')
        lease = session.relay_lease()
        self.assertIsNotNone(lease)
        self.assertTrue(session.accepts_relay_lease(lease))
        self.assertFalse(session.accepts_relay_lease(True))
        self.assertFalse(session.accepts_relay_lease(replace(lease)))
        self.assertFalse(missing.accepts_relay_lease(lease))
        self.assertLessEqual(lease.expires_at - lease.accepted_at, 0.4)
        session.stop()
        self.assertTrue(lease.revoked.is_set())
        self.assertFalse(session.accepts_relay_lease(lease))
        self.assertIsNone(session.relay_lease())

    def test_one_sample_budget_keeps_real_lease_without_additional_detector_calls(self):
        calls = []
        def detector(config):
            calls.append(time.monotonic())
            return independent_result()
        session = self.session(self.evidence, detector=detector, max_samples=1)
        session.start()
        self.await_state(session, 'monitoring')
        lease = session.relay_lease()
        timing = session.last_sample_timing()
        self.assertEqual(timing.sample_id, lease.sample_id)
        self.assertGreaterEqual(timing.total_seconds, timing.detector_seconds + timing.provider_seconds)
        threading.Event().wait(0.1)
        self.assertEqual(len(calls), 1)
        self.assertTrue(session.accepts_relay_lease(lease))
        session.stop()
        self.assertIn('sample_budget_exhausted', session.start().reason_codes)
        self.assertIn('sample_budget_exhausted', session.resume().reason_codes)
        self.assertEqual(len(calls), 1)

    def test_failed_attempt_consumes_sample_budget_without_retry(self):
        calls = []
        def detector(config):
            calls.append(1)
            raise OSError('synthetic failure')
        session = self.session(self.evidence, detector=detector, max_samples=1)
        session.start()
        self.await_state(session, 'alarm')
        self.assertIn('sample_budget_exhausted', session.resume().reason_codes)
        self.assertEqual(calls, [1])

    def test_alarm_revokes_every_previously_issued_lease(self):
        self.assertTrue(hasattr(monitoring.MonitorSession, 'relay_lease'), '缺少租约撤销接口')
        current = [True]
        session = self.session(lambda *args: self.evidence(
            *args, request_profile_status='pass' if current[0] else 'unknown'))
        session.start()
        self.await_state(session, 'monitoring')
        lease = session.relay_lease()
        current[0] = False
        self.await_state(session, 'alarm')
        self.assertTrue(lease.revoked.is_set())
        self.assertFalse(session.accepts_relay_lease(lease))

    def test_browser_identity_contract_adapts_without_inventing_request_proof(self):
        from src.browser.inspection import BrowserSelection
        from src.browser.session_binding import ProcessFact, SessionEvidence
        self.assertTrue(hasattr(monitoring, 'binding_from_session'), '缺少现有浏览器接口适配')
        root = ProcessFact(101, 1000, 1, self.binding.executable, '', self.binding.user_data_dir, '')
        network = ProcessFact(102, 1001, 101, self.binding.executable, 'utility', '', 'network.mojom.NetworkService')
        identity = SessionEvidence('pass', 'identity_only', 10.0, 20.0, self.binding.session_id,
                                   root, (network,), source='windows_cim', _revoked=threading.Event())
        selection = BrowserSelection('https://claude.ai', self.binding.executable,
                                     self.binding.user_data_dir, 'Default')
        adapted = monitoring.binding_from_session(selection, identity, now=10.0)
        self.assertEqual(adapted, self.binding)
        session = self.session(None, browser_binding=adapted)
        self.assertEqual(session.start().browser_status, 'unknown')
        for invalid in (replace(identity, source='offline'),
                        replace(identity, expires_at=10.0),
                        replace(identity, root=replace(root, executable=r'C:\ordinary\chrome.exe'))):
            with self.subTest(identity=invalid), self.assertRaises(ValueError):
                monitoring.binding_from_session(selection, invalid, now=10.0)
        identity._revoked.set()
        with self.assertRaises(ValueError):
            monitoring.binding_from_session(selection, identity, now=10.0)

    def test_provider_shorter_expiry_is_not_extended_to_core_max_age(self):
        tick = [10.0]
        def provider(*args):
            return self.evidence(*args, sampled_at=10.0, expires_at=11.0)
        session = self.session(provider, clock=lambda: tick[0], interval_seconds=20, max_age_seconds=60)
        session.start()
        self.await_state(session, 'monitoring')
        tick[0] = 11.0
        snapshot = session.snapshot()
        self.assertEqual(snapshot.state, 'alarm')
        self.assertIn('browser_evidence_expired', snapshot.reason_codes)
        self.assertEqual(snapshot.browser_status, 'unknown')

    def test_independent_success_cannot_claim_browser_binding(self):
        session = monitoring.MonitorSession(self.config, detector=lambda config: independent_result())
        self.sessions.append(session)
        session.start()
        snapshot = self.await_state(session, 'monitoring')
        self.assertEqual(snapshot.scope, 'independent_proxy')
        self.assertEqual(snapshot.browser_status, 'unknown')

    def test_failed_common_checks_do_not_trigger_browser_sampling(self):
        calls = []
        def provider(*args):
            calls.append(1)
            return self.evidence(*args)
        session = self.session(provider, detector=lambda config: replace(
            independent_result(), exit_ip=Check('fail', '合成不匹配')))
        session.start()
        self.await_state(session, 'alarm')
        self.assertEqual(calls, [])

    def test_expired_detector_does_not_trigger_browser_sampling(self):
        tick, calls = [0.0], []
        def detector(config):
            tick[0] = 60.0
            return independent_result()
        def provider(*args):
            calls.append(1)
            return self.evidence(*args)
        session = self.session(provider, detector=detector, clock=lambda: tick[0], max_age_seconds=30)
        session.start()
        self.await_state(session, 'alarm')
        self.assertEqual(calls, [])

    def test_current_bound_evidence_is_monitoring_but_never_protection(self):
        session = self.session(self.evidence)
        self.assertEqual(session.snapshot().browser_status, 'unknown')
        session.start()
        snapshot = self.await_state(session, 'monitoring')
        self.assertEqual((snapshot.scope, snapshot.browser_status), ('dedicated_browser', 'pass'))
        self.assertEqual(snapshot.protection, 'not_enabled')
        self.assertIn('阻断未启用', snapshot.message)
        self.assertEqual(session.stop().browser_status, 'unknown')

    def test_selected_profile_and_process_identity_are_not_request_profile_proof(self):
        for profile in ('Default', 'Profile 3'):
            with self.subTest(profile=profile):
                selected = replace(self.binding, profile_directory=profile)
                def provider(config, binding, sample_id):
                    return monitoring.BrowserBindingEvidence(
                        binding, sample_id, time.monotonic(), 'pass', 'pass', 'pass',
                        config.proxy_port, ('synthetic-owner', 1), config.expected_ip,
                        source='runtime', expires_at=time.monotonic() + 0.35)
                session = self.session(provider, browser_binding=selected)
                session.start()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    snapshot = session.snapshot()
                    if snapshot.checked_at is not None:
                        break
                    threading.Event().wait(0.005)
                self.assertEqual(snapshot.state, 'alarm')
                self.assertEqual(snapshot.browser_status, 'unknown')
                self.assertIn('browser_profile_unconfirmed', snapshot.reason_codes)
                self.assertIsNone(snapshot.last_success_at)
                session.stop()

    def test_command_line_configuration_and_isolated_context_are_not_profile_proof(self):
        for source in ('unknown', 'configuration', 'command_line', 'process_snapshot', 'isolated_context'):
            for profile in ('Default', 'Profile 3'):
                with self.subTest(source=source, profile=profile):
                    selected = replace(self.binding, profile_directory=profile)
                    session = self.session(lambda *args: self.evidence(*args, request_profile_source=source),
                                           browser_binding=selected)
                    session.start()
                    snapshot = self.await_state(session, 'alarm')
                    self.assertIn('browser_profile_unconfirmed', snapshot.reason_codes)
                    self.assertEqual(snapshot.browser_status, 'unknown')
                    self.assertIsNone(snapshot.last_success_at)
                    session.stop()

    def test_profile_proof_must_be_complete_and_match_selected_directory(self):
        variants = [({'request_profile_status': 'unknown'}, 'browser_profile_unconfirmed'),
                    ({'request_profile_status': 'fail'}, 'browser_profile_mismatch'),
                    ({'request_profile_status': 'candidate'}, 'browser_evidence_invalid'),
                    ({'request_profile_directory': None}, 'browser_profile_unconfirmed'),
                    ({'request_profile_directory': ''}, 'browser_profile_unconfirmed'),
                    ({'request_profile_directory': 'Profile 3'}, 'browser_profile_mismatch')]
        for changes, reason in variants:
            with self.subTest(changes=changes):
                session = self.session(lambda *args: self.evidence(*args, **changes))
                session.start()
                snapshot = self.await_state(session, 'alarm')
                self.assertIn(reason, snapshot.reason_codes)
                self.assertEqual(snapshot.browser_status, 'unknown')
                self.assertIsNone(snapshot.last_success_at)
                session.stop()

    def test_lost_profile_proof_latches_alarm_until_a_fresh_manual_check(self):
        confirmed = [True]
        session = self.session(lambda *args: self.evidence(
            *args, request_profile_status='pass' if confirmed[0] else 'unknown'))
        session.start()
        self.await_state(session, 'monitoring')
        confirmed[0] = False
        snapshot = self.await_state(session, 'alarm')
        self.assertIn('browser_profile_unconfirmed', snapshot.reason_codes)
        self.assertEqual(snapshot.browser_status, 'unknown')
        confirmed[0] = True
        self.assertEqual(session.start().state, 'alarm')
        session.resume()
        self.assertEqual(self.await_state(session, 'monitoring').protection, 'not_enabled')

    def test_candidate_unknown_or_failed_evidence_never_passes(self):
        variants = [dict(source='candidate'), dict(source='offline'),
                    dict(identity_status='unknown'), dict(request_status='unknown'),
                    dict(proxy_status='unknown'), dict(identity_status='fail'),
                    dict(request_status='fail'), dict(proxy_status='fail')]
        for changes in variants:
            with self.subTest(changes=changes):
                session = self.session(lambda *args: self.evidence(*args, **changes))
                session.start()
                snapshot = self.await_state(session, 'alarm')
                self.assertEqual(snapshot.browser_status, 'unknown')
                self.assertIsNone(snapshot.last_success_at)
                session.stop()

    def test_changed_session_process_or_selection_is_not_adopted(self):
        variants = [dict(session_id='different'), dict(root_created=2000),
                    dict(network_processes=((102, 2001),)),
                    dict(executable=r'C:\ordinary\chrome.exe'),
                    dict(user_data_dir=r'C:\ordinary-data')]
        for changes in variants:
            with self.subTest(changes=changes):
                changed = replace(self.binding, **changes)
                session = self.session(lambda *args: replace(self.evidence(*args), binding=changed))
                session.start()
                snapshot = self.await_state(session, 'alarm')
                self.assertIn('browser_binding_changed', snapshot.reason_codes)
                session.resume()
                self.assertEqual(self.await_state(session, 'alarm').browser_status, 'unknown')
                session.stop()

    def test_request_proxy_and_target_must_match(self):
        variants = [(dict(sample_id='previous-sample'), 'browser_sample_mismatch'),
                    (dict(proxy_port=25003), 'browser_proxy_mismatch'),
                    (dict(proxy_owner=('another-owner', 2)), 'browser_proxy_mismatch'),
                    (dict(observed_ip='203.0.113.2'), 'browser_exit_mismatch'),
                    (dict(target_origin='https://example.test'), 'browser_request_unconfirmed')]
        for changes, reason in variants:
            with self.subTest(changes=changes):
                session = self.session(lambda *args: replace(self.evidence(*args), **changes))
                session.start()
                snapshot = self.await_state(session, 'alarm')
                self.assertIn(reason, snapshot.reason_codes)
                session.stop()

    def test_observed_binding_change_cannot_reclaim_original_session_on_resume(self):
        current, calls = [self.binding], []
        def provider(*args):
            calls.append(1)
            return replace(self.evidence(*args), binding=current[0])
        session = self.session(provider)
        session.start()
        self.await_state(session, 'monitoring')
        current[0] = replace(self.binding, session_id='changed-browser-session')
        self.assertIn('browser_binding_changed', self.await_state(session, 'alarm').reason_codes)
        current[0] = self.binding
        count = len(calls)
        self.assertEqual(session.resume().state, 'alarm')
        threading.Event().wait(0.05)
        self.assertEqual(len(calls), count)
        self.assertEqual(session.snapshot().browser_status, 'unknown')

    def test_old_future_and_malformed_sample_times_fail_closed(self):
        for value in (0, time.monotonic() + 1000, float('nan'), float('inf'), True):
            with self.subTest(value=value):
                session = self.session(lambda *args: self.evidence(*args, sampled_at=value))
                session.start()
                snapshot = self.await_state(session, 'alarm')
                self.assertEqual(snapshot.browser_status, 'unknown')
                self.assertIsNone(snapshot.last_success_at)
                session.stop()

    def test_cached_previous_sample_cannot_extend_evidence(self):
        samples = []
        def provider(*args):
            if not samples:
                samples.append(self.evidence(*args))
            return samples[0]
        session = self.session(provider)
        session.start()
        self.await_state(session, 'monitoring')
        snapshot = self.await_state(session, 'alarm')
        self.assertIn('browser_sample_mismatch', snapshot.reason_codes)
        self.assertEqual(snapshot.browser_status, 'unknown')

    def test_success_expires_even_when_provider_hangs(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        calls = []
        def provider(*args):
            calls.append(1)
            if len(calls) > 1:
                entered.set()
                gate.wait(2)
            return self.evidence(*args)
        session = self.session(provider, max_age_seconds=0.15)
        session.start()
        self.await_state(session, 'monitoring')
        self.assertTrue(entered.wait(1))
        snapshot = self.await_state(session, 'alarm')
        self.assertIn('evidence_expired', snapshot.reason_codes)
        self.assertEqual(snapshot.browser_status, 'unknown')
        self.assertEqual(len(calls), 2)

    def test_invalidation_rejects_inflight_success_and_cannot_resume_old_binding(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        def provider(*args):
            result = self.evidence(*args)
            entered.set()
            gate.wait(2)
            return result
        session = self.session(provider)
        session.start()
        self.assertTrue(entered.wait(1))
        invalidated = session.invalidate_binding()
        self.assertEqual(invalidated.browser_status, 'unknown')
        self.assertIn('browser_binding_changed', invalidated.reason_codes)
        gate.set()
        threading.Event().wait(0.05)
        self.assertEqual(session.snapshot(), invalidated)
        self.assertEqual(session.resume().state, 'alarm')
        self.assertEqual(session.snapshot().browser_status, 'unknown')

    def test_stopped_provider_result_cannot_revive_session(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        def provider(*args):
            result = self.evidence(*args)
            entered.set()
            gate.wait(2)
            return result
        session = self.session(provider)
        session.start()
        self.assertTrue(entered.wait(1))
        stopped = session.stop()
        gate.set()
        threading.Event().wait(0.05)
        self.assertEqual(session.snapshot(), stopped)

    def test_stopped_detector_cannot_alarm_on_a_later_clock_error(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        tick = [10.0]
        def detector(config):
            entered.set()
            gate.wait(2)
            tick[0] = 9.0
            return independent_result()
        session = self.session(self.evidence, detector=detector, clock=lambda: tick[0])
        session.start()
        self.assertTrue(entered.wait(1))
        stopped = session.stop()
        gate.set()
        threading.Event().wait(0.05)
        self.assertEqual(session.snapshot(), stopped)

    def test_provider_error_and_private_fields_are_not_reported(self):
        def provider(*args):
            raise RuntimeError('synthetic-private-secret')
        session = self.session(provider)
        session.start()
        snapshot = self.await_state(session, 'alarm')
        self.assertIn('browser_provider_error', snapshot.reason_codes)
        text = repr(snapshot) + repr(self.binding) + repr(self.evidence(self.config, self.binding, 'sample'))
        for private in ('synthetic-private-secret', self.config.expected_ip, self.binding.executable,
                        self.binding.user_data_dir, self.binding.session_id, 'synthetic-owner'):
            self.assertNotIn(private, text)


if __name__ == '__main__':
    unittest.main()
