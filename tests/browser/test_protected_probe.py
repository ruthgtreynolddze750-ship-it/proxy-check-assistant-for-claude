from collections import deque
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import copy
import json
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from src.browser import cdp_pipe, request_probe, session_binding


class ProfileTransport:
    """Protocol fixture only: never launches Chrome or performs HTTP."""
    def __init__(self, path):
        self.path = path
        self.sent = []
        self.messages = deque()
        self.targets = {}
        self.sessions = {}
        self.wrong_context = False
        self.empty_reads = 0
        self.reject_eval = False
        self.reject_side_effect_guard = False
        self.evaluation_result = None
        self.context_change = False
        self.trace_oversize = False
        self.close_failure = False
        self.changed_after_trace = False
        self.version_child_frame = False

    def send(self, message, deadline):
        self.sent.append(message)
        method, p = message['method'], message['params']
        session = message.get('sessionId')
        result = {}
        events = []
        if method == 'Target.getBrowserContexts':
            result = {'browserContextIds': [], 'defaultBrowserContextId': 'default-context'}
        elif method == 'Target.createTarget':
            target = 'target-' + str(len(self.targets)+1)
            self.targets[target] = 'about:blank'
            result = {'targetId': target}
        elif method == 'Target.getTargetInfo':
            result = {'targetInfo': {'targetId': p['targetId'], 'type': 'page',
                'browserContextId': 'wrong' if self.wrong_context else 'default-context',
                'url': self.targets[p['targetId']]}}
        elif method == 'Target.attachToTarget':
            session = 'session-' + p['targetId'];self.sessions[session] = p['targetId']
            result = {'sessionId': session};session = None
        elif method == 'Page.getFrameTree':
            target = self.sessions[session]
            result = {'frameTree': {'frame': {'id': 'frame-'+target, 'url': self.targets[target],
                                             'loaderId': 'loader-'+target}}}
            if self.version_child_frame and self.targets[target] == 'chrome://version/':
                result['frameTree']['childFrames'] = [{'frame':{'id':'unexpected-child'}}]
        elif method == 'Page.navigate':
            target = self.sessions[session];self.targets[target] = p['url']
            frame = 'frame-'+target;loader = 'loader-'+target
            result = {'frameId': frame, 'loaderId': loader}
            if p['url'] == 'chrome://version/':
                events = [{'method': 'Runtime.executionContextCreated', 'params': {'context': {
                    'id': 5, 'uniqueId': 'unique-version', 'origin': 'chrome://version',
                    'auxData': {'frameId': frame, 'isDefault': True}}}}]
            else:
                events = [
                    {'method': 'Network.requestWillBeSent', 'params': {'requestId': 'net-1',
                        'loaderId': loader, 'frameId': frame, 'type': 'Document',
                        'request': {'url': p['url'], 'method': 'GET'}}},
                    {'method': 'Fetch.requestPaused', 'params': {'requestId': 'fetch-1',
                        'networkId': 'net-1', 'frameId': frame, 'resourceType': 'Document',
                        'request': {'url': p['url'], 'method': 'GET'}}},
                    {'method': 'Network.responseReceived', 'params': {'requestId': 'net-1',
                        'loaderId': loader, 'frameId': frame, 'type': 'Document', 'response': {
                            'url': p['url'], 'status': 200, 'mimeType': 'text/plain',
                            'securityState': 'secure'}}},
                    {'method': 'Network.loadingFinished', 'params': {'requestId': 'net-1',
                        'encodedDataLength': 100000 if self.trace_oversize else 100}}]
        elif method == 'Runtime.evaluate':
            if self.evaluation_result is not None:
                result = copy.deepcopy(self.evaluation_result)
            elif self.reject_side_effect_guard and p.get('throwOnSideEffect') is True:
                result = {'result': {'type': 'object', 'subtype': 'error'},
                    'exceptionDetails': {'text': 'Uncaught', 'exception': {'type': 'object',
                        'className': 'EvalError', 'description': 'EvalError: Possible side-effect in debug-evaluate'}}}
            elif self.reject_eval:
                result = {'result': {'type': 'object'}, 'exceptionDetails': {'text': 'refused'}}
            else:
                path = str(Path(self.path).parent) if self.changed_after_trace and request_probe.TARGET in self.targets.values() else self.path
                result = {'result': {'type': 'string', 'value': '' if self.empty_reads else path}}
                self.empty_reads = max(0, self.empty_reads-1)
            if self.context_change:
                events = [{'method': 'Runtime.executionContextDestroyed',
                           'params': {'executionContextId': 5, 'executionContextUniqueId': 'unique-version'}}]
        elif method == 'Network.getResponseBody':
            result = {'body': 'h=claude.ai\nip=203.0.113.9\n', 'base64Encoded': False}
        elif method == 'Target.closeTarget':
            result = {'success': not self.close_failure}
        for event in events:
            event['sessionId'] = message['sessionId'];self.messages.append(event)
        reply = {'id': message['id'], 'result': result}
        if 'sessionId' in message:reply['sessionId'] = message['sessionId']
        self.messages.append(reply)

    def receive(self, deadline):
        if not self.messages:raise TimeoutError('fixture_timeout')
        return self.messages.popleft()

    def close(self):
        pass


class ProtectedProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name);exe = root/'Application/chrome.exe';exe.parent.mkdir();exe.write_bytes(b'not executable')
        data = root/'Fresh';data.mkdir()
        self.target = session_binding.DedicatedTarget(str(exe), str(data))
        self.profile = data/'Default'

    def run_profile(self, transport, on_ready=None):
        return request_probe.collect_profile_trace(cdp_pipe.CdpChannel(transport), self.target,
            'Default', '203.0.113.9', deadline=time.monotonic()+2, on_ready=on_ready)

    def owned_fixture(self, gate):
        """Deliberately replace native boundaries to test issuer state only, never runtime acceptance."""
        from src.protection import dedicated_wfp as wfp
        with patch.object(request_probe,'_file_version',return_value=request_probe.REVIEWED_VERSION):
            launch = request_probe.prepare_launch(self.target,49152,selected=True)
        identity = wfp.ApplicationIdentity(self.target.executable,self.target.user_data_dir,
            launch.fingerprint,launch.executable_sha256,b'offline',(('ordinary',b'other'),),'windows_wfp')
        policy = wfp.PolicyPlan(identity,49152,'e3116fb3-71d4-4fa3-83dc-c31eab15fb54')
        reader = wfp.PolicyReadbackVerifier(policy)
        def read_fixture():
            now = time.monotonic()
            proof = wfp.PolicyReadback(policy.digest,policy.deployment_id,49152,
                identity.executable_sha256,'a'*64,('offline',),'b'*64,now,now+5,'native_wfp')
            reader._proof = proof
            return proof
        self.enterContext(patch.object(reader,'read',side_effect=read_fixture))
        plan = request_probe.ProtectedProbePlan(launch,policy.digest)
        approval = request_probe.ProtectedProbeApproval(plan.digest,secrets.token_hex(8),3,time.monotonic()+60,True,True)
        grant = request_probe.ProtectedProbeGrant(plan,approval);grant.consume_launch(plan)
        self.profile.mkdir();transport = ProfileTransport(str(self.profile))
        owned = request_probe._ProtectedProbe(plan,SimpleNamespace(pid=100,poll=lambda:None),transport,grant,reader,gate)
        self.addCleanup(owned.close)
        # Only direct unit tests may cross this boundary; production launch tests reject this transport.
        owned._runtime_verified = True
        root = session_binding.ProcessFact(100,1000,42,self.target.executable,'',self.target.user_data_dir,'')
        network = session_binding.ProcessFact(101,1001,100,self.target.executable,'utility','','network.mojom.NetworkService')
        now = time.monotonic()
        evidence = session_binding.SessionEvidence('pass','fixture',now,now+60,'fixture-binding',root,(network,),
            source='windows_cim',_revoked=owned._identity._revoked)
        self.enterContext(patch.object(owned._identity,'poll',return_value=evidence))
        validator = self.enterContext(patch.object(request_probe,'validate_bound_processes'))
        return owned,transport,reader,validator

    def test_directory_proof_checks_real_identity_and_rejects_wrong_or_lossy_path(self):
        self.profile.mkdir()
        proof = session_binding.profile_directory_identity(self.target, 'Default', str(self.profile))
        self.assertEqual(proof.profile_directory, 'Default')
        self.assertEqual(proof.profile_identity, (self.profile.stat().st_dev, self.profile.stat().st_ino))
        for path in [str(self.profile.parent), str(self.profile)+'\ufffd', str(self.profile/'..'/'Default')]:
            with self.assertRaises(ValueError):
                session_binding.profile_directory_identity(self.target, 'Default', path)

    def test_actual_node_is_linked_to_same_explicit_context_without_enumeration(self):
        self.profile.mkdir();transport = ProfileTransport(str(self.profile));transport.empty_reads = 1
        ready = []
        @contextmanager
        def gate(intent):
            ready.append(intent);yield
        result = self.run_profile(transport, gate)
        self.assertEqual(result.trace.request_status, 'pass')
        self.assertEqual(result.browser_context_id, 'default-context')
        self.assertEqual(result.profile.profile_directory, 'Default')
        self.assertEqual(len(ready), 1)
        methods = [m['method'] for m in transport.sent]
        self.assertNotIn('Target.getTargets', methods)
        self.assertNotIn('Target.createBrowserContext', methods)
        self.assertNotIn('Target.disposeBrowserContext', methods)
        self.assertEqual(methods.count('Target.closeTarget'), 2)
        for m in transport.sent:
            if m['method'] == 'Target.createTarget':self.assertEqual(m['params']['browserContextId'], 'default-context')
            if m['method'] == 'Runtime.evaluate':
                self.assertFalse(m['params']['allowUnsafeEvalBlockedByCSP'])
                self.assertFalse(m['params']['throwOnSideEffect'])
                self.assertEqual(m['params']['uniqueContextId'], 'unique-version')

    def test_wrong_context_wrong_profile_csp_and_context_loss_prevent_trace(self):
        self.profile.mkdir()
        @contextmanager
        def gate(_):yield
        for mutation in ['wrong_context','reject_eval','context_change','wrong_path','version_child_frame']:
            with self.subTest(mutation=mutation):
                transport = ProfileTransport(str(self.profile))
                if mutation == 'wrong_path':transport.path = str(self.profile.parent)
                else:setattr(transport,mutation,True)
                with self.assertRaises(cdp_pipe.ProbeError):self.run_profile(transport, gate)
                self.assertFalse(any(m['method']=='Page.navigate' and m['params']['url']==request_probe.TARGET
                    for m in transport.sent))

    def test_trace_has_byte_limit_and_requires_gate(self):
        self.profile.mkdir();transport = ProfileTransport(str(self.profile))
        with self.assertRaisesRegex(cdp_pipe.ProbeError, 'diagnostic_gate_required'):
            self.run_profile(transport)
        transport = ProfileTransport(str(self.profile));transport.trace_oversize = True
        @contextmanager
        def gate(_):yield
        with self.assertRaisesRegex(cdp_pipe.ProbeError, 'response_too_large'):
            self.run_profile(transport,gate)

    def test_profile_rejection_metadata_distinguishes_markers_without_exposing_text(self):
        private = r'C:\Private\SECRET_TOKEN\Profile 192.0.2.37'
        cases = [('EvalError', 'Content Security Policy unsafe-eval ' + private, True, False),
                 ('EvalError', 'Possible side-effect in debug-evaluate ' + private, False, True),
                 (private, private, False, False)]
        for exception_class, description, csp, side_effect in cases:
            with self.subTest(exception_class=exception_class if exception_class == 'EvalError' else 'other'):
                transport = ProfileTransport('unused')
                transport.evaluation_result = {'result': {'type': 'object', 'subtype': 'error'},
                    'exceptionDetails': {'text': 'Uncaught', 'url': private,
                        'exception': {'type': 'object', 'className': exception_class,
                                      'description': description, 'objectId': private},
                        'stackTrace': {'description': private}}}
                channel = cdp_pipe.CdpChannel(transport)
                with self.assertRaisesRegex(cdp_pipe.ProbeError, '^profile_read_rejected$') as raised:
                    channel.read_profile_path('owned-context', time.monotonic()+1, 'owned-session')
                detail = raised.exception.profile_read_diagnostic
                self.assertEqual(detail['branch'], 'exception_details')
                self.assertEqual(detail['exception_class'], 'EvalError' if exception_class == 'EvalError' else 'other')
                self.assertEqual(detail['exception_description_length'], len(description))
                self.assertEqual(detail['csp_marker_present'], csp)
                self.assertEqual(detail['side_effect_marker_present'], side_effect)
                for secret in (private, 'SECRET_TOKEN', '192.0.2.37', description):
                    self.assertNotIn(secret, json.dumps(detail))
                self.assertEqual(len(transport.sent), 1)
                self.assertEqual(transport.sent[0]['params'],
                                 dict(cdp_pipe.PROFILE_EVALUATION, uniqueContextId='owned-context'))

    def test_profile_rejection_metadata_handles_malformed_and_invalid_values(self):
        cases = [({'result': []}, 'profile_read_rejected', 'remote_object_shape', 'array', None),
                 ({'result': None}, 'profile_read_rejected', 'remote_object_shape', 'null', None),
                 ({'result': {}, 'exceptionDetails': []}, 'profile_read_rejected', 'exception_details', 'object', None),
                 ({'result': {'type': 'string', 'value': 'S'*4097}}, 'profile_read_invalid', 'value_contract', 'object', 4097),
                 ({'result': {'type': 'string', 'value': 'PRIVATE', 'objectId': 'PRIVATE'}},
                  'profile_read_invalid', 'value_contract', 'object', 7),
                 ({'result': {'type': {'PRIVATE': True}, 'value': ['PRIVATE']}},
                  'profile_read_invalid', 'value_contract', 'object', None)]
        for reply, reason, branch, shape, length in cases:
            with self.subTest(reason=reason, branch=branch, shape=shape):
                transport = ProfileTransport('unused');transport.evaluation_result = reply
                with self.assertRaisesRegex(cdp_pipe.ProbeError, '^'+reason+'$') as raised:
                    cdp_pipe.CdpChannel(transport).read_profile_path('owned', time.monotonic()+1, 'session')
                detail = raised.exception.profile_read_diagnostic
                self.assertEqual((detail['branch'], detail['remote_object_shape'], detail['value_length']),
                                 (branch, shape, length))
                self.assertNotIn('PRIVATE', json.dumps(detail))
                self.assertLess(len(json.dumps(detail)), 1024)

    def test_profile_rejection_metadata_survives_cleanup_and_never_enters_trace(self):
        self.profile.mkdir();transport = ProfileTransport(str(self.profile))
        transport.reject_eval = transport.close_failure = True
        gate_calls = []
        @contextmanager
        def gate(context):
            gate_calls.append(context);yield
        with self.assertRaisesRegex(cdp_pipe.ProbeError, '^profile_read_rejected$') as raised:
            self.run_profile(transport, gate)
        self.assertEqual(raised.exception.profile_read_diagnostic['branch'], 'exception_details')
        self.assertIn('owned_target_cleanup_failed', raised.exception.__notes__)
        self.assertFalse(gate_calls)
        self.assertFalse(any(m['method'] == 'Page.navigate' and m['params']['url'] == request_probe.TARGET
                             for m in transport.sent))
        self.assertEqual(sum(m['method'] == 'Target.closeTarget' for m in transport.sent), 1)

    def test_channel_rejects_arbitrary_eval_or_security_downgrade(self):
        transport = ProfileTransport('unused');channel = cdp_pipe.CdpChannel(transport)
        fixed = dict(cdp_pipe.PROFILE_EVALUATION, uniqueContextId='context-owned')
        mutations = [{'expression': 'document.cookie'}, {'expression': 'document.body.textContent'},
            {'expression': cdp_pipe.PROFILE_EXPRESSION + ";document.title='changed'"},
            {'allowUnsafeEvalBlockedByCSP': True}, {'returnByValue': False}, {'throwOnSideEffect': True},
            {'includeCommandLineAPI': True}, {'userGesture': True}, {'awaitPromise': True},
            {'contextId': 1}, {'uniqueContextId': ''}, {'uniqueContextId': 123}, {'timeout': 251},
            {'objectGroup': 'unexpected'}]
        rejected = [dict(fixed, **change) for change in mutations]
        rejected += [{key: value for key, value in fixed.items() if key != missing} for missing in fixed]
        for params in rejected:
            with self.subTest(keys=tuple(params)):
                with self.assertRaisesRegex(cdp_pipe.ProbeError, 'profile_expression_required'):
                    channel.command('Runtime.evaluate',params,time.monotonic()+1,'session-owned')
        with self.assertRaisesRegex(cdp_pipe.ProbeError, 'profile_expression_required'):
            channel.command('Runtime.evaluate',fixed,time.monotonic()+1,None)
        self.assertFalse(transport.sent)

    def test_fixed_profile_read_is_compatible_with_observed_side_effect_rejection(self):
        self.profile.mkdir()
        @contextmanager
        def gate(_):yield
        rejected = ProfileTransport(str(self.profile));rejected.reject_side_effect_guard = True
        with patch.dict(cdp_pipe.PROFILE_EVALUATION, throwOnSideEffect=True):
            with self.assertRaisesRegex(cdp_pipe.ProbeError, '^profile_read_rejected$') as raised:
                self.run_profile(rejected, gate)
        self.assertEqual(raised.exception.profile_read_diagnostic['exception_class'], 'EvalError')
        self.assertTrue(raised.exception.profile_read_diagnostic['side_effect_marker_present'])
        self.assertFalse(raised.exception.profile_read_diagnostic['csp_marker_present'])
        self.assertFalse(any(m['method']=='Page.navigate' and m['params']['url']==request_probe.TARGET
                             for m in rejected.sent))
        accepted = ProfileTransport(str(self.profile));accepted.reject_side_effect_guard = True
        result = self.run_profile(accepted, gate)
        self.assertEqual(result.profile.profile_directory, 'Default')
        self.assertEqual(result.trace.request_status, 'pass')
        for message in accepted.sent:
            if message['method'] == 'Runtime.evaluate':
                self.assertEqual(message['params']['expression'], cdp_pipe.PROFILE_EXPRESSION)
                self.assertFalse(message['params']['throwOnSideEffect'])
                self.assertFalse(message['params']['allowUnsafeEvalBlockedByCSP'])
                self.assertTrue(message['params']['returnByValue'])
                self.assertEqual(message['params']['uniqueContextId'], 'unique-version')

    def test_grant_is_distinct_single_launch_and_at_most_three_nonrefundable_attempts(self):
        with patch.object(request_probe,'_file_version',return_value=request_probe.REVIEWED_VERSION):
            plan = request_probe.prepare_protected_launch(self.target,49152,'a'*64,selected=True)
        approval = request_probe.ProtectedProbeApproval(plan.digest,'r20-test',3,time.monotonic()+60,True,True)
        grant = request_probe.ProtectedProbeGrant(plan,approval)
        grant.consume_launch(plan)
        with self.assertRaises(cdp_pipe.ProbeError):grant.consume_launch(plan)
        for index in range(3):self.assertEqual(grant.consume_round('sample-'+str(index)),index+1)
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'diagnostic_grant_consumed'):grant.consume_round('sample-4')
        with self.assertRaises(cdp_pipe.ProbeError):
            request_probe.ProtectedProbeGrant(plan,request_probe.ProbeApproval(plan.digest,True,True))

    def test_protected_launch_rejects_missing_or_injected_readback_before_spawn(self):
        from src.protection import dedicated_wfp as wfp
        with patch.object(request_probe,'_file_version',return_value=request_probe.REVIEWED_VERSION):
            launch = request_probe.prepare_launch(self.target,49152,selected=True)
        identity = wfp.ApplicationIdentity(self.target.executable,self.target.user_data_dir,
            launch.fingerprint,launch.executable_sha256,b'fixture',(('ordinary',b'other'),),'fixture')
        policy = wfp.PolicyPlan(identity,49152,'e3116fb3-71d4-4fa3-83dc-c31eab15fb54')
        plan = request_probe.ProtectedProbePlan(launch,policy.digest)
        approval = request_probe.ProtectedProbeApproval(plan.digest,'launch-test',1,time.monotonic()+60,True,True)
        grant = request_probe.ProtectedProbeGrant(plan,approval)
        with patch.object(request_probe,'spawn_with_pipe') as spawn:
            for reader in (None, True, wfp.PolicyReadbackVerifier(policy,backend_factory=lambda:None)):
                with self.assertRaises(cdp_pipe.ProbeError):
                    request_probe.launch_protected_probe(plan,grant=grant,policy_verifier=reader,
                        proxy_preflight=lambda _:True,diagnostic_gate=lambda _:None)
            spawn.assert_not_called()

    def test_profile_change_after_trace_and_cleanup_failure_preserve_primary(self):
        self.profile.mkdir();transport = ProfileTransport(str(self.profile))
        transport.changed_after_trace = transport.close_failure = True
        @contextmanager
        def gate(_):yield
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'profile_request_unconfirmed') as caught:
            self.run_profile(transport,gate)
        self.assertEqual(len(caught.exception.cleanup_errors),2)
        self.assertTrue(any('cleanup_failed' in x for x in caught.exception.__notes__))

    def test_issued_intent_result_round_budget_and_route_remains_unknown(self):
        intents=[]
        @contextmanager
        def gate(intent):
            self.assertTrue(owned.accepts_intent(intent))
            self.assertFalse(owned.accepts_intent(replace(intent)))
            self.assertFalse(owned.accepts_intent(True))
            intents.append(intent);yield
        owned,transport,reader,validator = self.owned_fixture(gate)
        binding = owned.binding();original_session = owned.session_evidence
        for number in range(3):
            evidence = owned(SimpleNamespace(expected_ip='203.0.113.9'),binding,'sample-'+str(number))
            result = owned.last_result
            self.assertTrue(owned.accepts_result(result))
            self.assertFalse(owned.accepts_result(replace(result)))
            self.assertFalse(owned.accepts_intent(intents[-1]))
            self.assertEqual(evidence.request_profile_status,'pass')
            self.assertEqual(evidence.request_profile_source,'selected_profile_context')
            self.assertEqual(evidence.proxy_status,'unknown')
            self.assertIs(evidence,result.evidence)
        self.assertIs(owned.session_evidence,original_session)
        owned._identity.poll.assert_called_once()
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'diagnostic_grant_consumed'):
            owned(SimpleNamespace(expected_ip='203.0.113.9'),binding,'sample-4')
        self.assertFalse(owned.accepts_result(result))
        owned.close();self.assertFalse(owned.accepts_result(result))

    def test_binding_failure_revokes_issued_result_permanently(self):
        @contextmanager
        def gate(_):yield
        owned,transport,reader,validator = self.owned_fixture(gate)
        binding = owned.binding()
        owned(SimpleNamespace(expected_ip='203.0.113.9'),binding,'sample')
        result = owned.last_result
        validator.side_effect = ValueError('changed')
        self.assertFalse(owned.accepts_result(result))
        validator.side_effect = None
        self.assertFalse(owned.accepts_result(result))
        self.assertFalse(owned.session_evidence.is_fresh(time.monotonic()))

    def test_error_revokes_intent_and_consumes_round_without_creating_result(self):
        intents=[]
        @contextmanager
        def gate(intent):
            intents.append(intent)
            raise cdp_pipe.ProbeError('diagnostic_denied')
            yield
        owned,transport,reader,validator = self.owned_fixture(gate)
        binding = owned.binding()
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'diagnostic_denied'):
            owned(SimpleNamespace(expected_ip='203.0.113.9'),binding,'sample')
        self.assertEqual(owned.grant.rounds_used,1)
        self.assertIsNone(owned.last_result)
        self.assertFalse(owned.accepts_intent(intents[0]))
        self.assertFalse(any(m['method']=='Page.navigate' and m['params']['url']==request_probe.TARGET for m in transport.sent))
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'diagnostic_grant_consumed'):
            owned(SimpleNamespace(expected_ip='203.0.113.9'),binding,'sample')

    def test_grant_copy_expiry_and_clock_reversal_do_not_authorize_round(self):
        @contextmanager
        def gate(_):yield
        owned,_,_,_ = self.owned_fixture(gate)
        self.assertFalse(copy.copy(owned.grant).is_live())
        for tick in (owned.grant._issued_at-1,owned.grant.approval.expires_at,float('nan')):
            with patch.object(request_probe.time,'monotonic',return_value=tick):
                self.assertFalse(owned.grant.is_live())
                with self.assertRaises(cdp_pipe.ProbeError):owned.grant.consume_round('outside-window')

    def test_initial_binding_uses_native_identity_recheck_and_rejects_injected_pipe(self):
        @contextmanager
        def gate(_):yield
        owned,_,_,validator = self.owned_fixture(gate)
        owned._runtime_verified = False
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'runtime_channel_unconfirmed'):owned.binding()
        validator.assert_not_called()
        owned._runtime_verified = True
        validator.side_effect = ValueError('root-replaced')
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'owned_browser_unconfirmed'):owned.binding()
        validator.side_effect = None
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'owned_browser_unavailable'):owned.binding()

    def test_gate_cannot_extend_request_deadline_or_leave_intent_after_expiry(self):
        intents=[]
        @contextmanager
        def gate(intent):
            intents.append(intent)
            with patch.object(request_probe.time,'monotonic',return_value=intent.expires_at):
                yield
        owned,transport,_,_ = self.owned_fixture(gate)
        with self.assertRaisesRegex(cdp_pipe.ProbeError,'diagnostic_intent_unconfirmed'):
            owned(SimpleNamespace(expected_ip='203.0.113.9'),owned.binding(),'sample')
        self.assertFalse(owned.accepts_intent(intents[0]))
        self.assertIsNone(owned.last_result)
        self.assertFalse(any(m['method']=='Page.navigate' and m['params']['url']==request_probe.TARGET for m in transport.sent))

    def test_native_process_handle_check_rejects_created_time_change(self):
        from src.core.monitoring import BrowserBinding
        from src.protection import relay_identity
        binding = BrowserBinding(self.target.executable,self.target.user_data_dir,'Default','fixture',100,1000,((101,1001),))
        fingerprint = session_binding._target_fingerprint(self.target)
        opened=[];closed=[]
        @contextmanager
        def process(pid):
            opened.append(pid)
            try:yield {'created':1000 if pid==100 else 1002,'path':self.target.executable}
            finally:closed.append(pid)
        with patch.object(relay_identity,'_process',side_effect=process):
            with self.assertRaisesRegex(ValueError,'bound process changed'):
                session_binding.validate_bound_processes(binding,fingerprint)
        self.assertEqual(opened,[100,101]);self.assertEqual(closed,[101,100])

    def test_intent_expiring_during_identity_checks_is_not_accepted(self):
        @contextmanager
        def gate(intent):
            tick = [time.monotonic()]
            def slow_binding():tick[0]=intent.expires_at;return intent.binding
            with patch.object(request_probe.time,'monotonic',side_effect=lambda:tick[0]), \
                 patch.object(owned,'binding',side_effect=slow_binding):
                self.assertFalse(owned.accepts_intent(intent))
            yield
        owned,_,_,_ = self.owned_fixture(gate)
        owned(SimpleNamespace(expected_ip='203.0.113.9'),owned.binding(),'sample')

    def test_result_expiring_during_identity_checks_is_not_accepted(self):
        @contextmanager
        def gate(_):yield
        owned,_,_,_ = self.owned_fixture(gate)
        owned(SimpleNamespace(expected_ip='203.0.113.9'),owned.binding(),'sample')
        result = owned.last_result;tick=[time.monotonic()]
        def slow_binding():tick[0]=result.expires_at;return result.intent.binding
        with patch.object(request_probe.time,'monotonic',side_effect=lambda:tick[0]), \
             patch.object(owned,'binding',side_effect=slow_binding):
            self.assertFalse(owned.accepts_result(result))

    def test_pipe_close_attempts_both_ends_and_can_retry_only_unclosed_end(self):
        transport=object.__new__(cdp_pipe.PipeTransport)
        transport._read,transport._write=42,43
        transport._buffer=bytearray();transport._closed=False;transport._lock=threading.Lock()
        original=OSError('first-close-failed');calls=[]
        def close(fd):
            calls.append(fd)
            if fd==42:raise original
        with patch.object(cdp_pipe.os,'close',side_effect=close):
            with self.assertRaises(OSError) as caught:transport.close()
        self.assertIs(caught.exception,original)
        self.assertEqual(calls,[42,43])
        with patch.object(cdp_pipe.os,'close') as retry:
            transport.close();transport.close()
            self.assertEqual(retry.call_args_list,[((42,),)])


if __name__ == '__main__':
    unittest.main()
