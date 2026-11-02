from collections import deque
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace


class ScenarioTransport:
    def __init__(self, change=None, body=None):
        self.messages = deque()
        self.sent = []
        self.change = change or (lambda events: events)
        self.body = body if body is not None else 'h=claude.ai\nip=203.0.113.9\n'

    def send(self, message, deadline):
        self.sent.append(message)
        method = message['method']
        result = {}
        if method == 'Target.createBrowserContext':
            result = {'browserContextId': 'new-context'}
        elif method == 'Target.createTarget':
            result = {'targetId': 'new-target'}
        elif method == 'Target.attachToTarget':
            result = {'sessionId': 'new-session'}
        elif method == 'Page.getFrameTree':
            result = {'frameTree': {'frame': {'id': 'main-frame', 'url': 'about:blank'}}}
        elif method == 'Page.navigate':
            url = 'https://claude.ai/cdn-cgi/trace'
            events = [
                {'method': 'Network.requestWillBeSent', 'params': {
                    'requestId': 'net-1', 'loaderId': 'loader-1', 'frameId': 'main-frame',
                    'type': 'Document', 'request': {'url': url, 'method': 'GET'}}},
                {'method': 'Fetch.requestPaused', 'params': {
                    'requestId': 'fetch-1', 'networkId': 'net-1', 'frameId': 'main-frame',
                    'resourceType': 'Document', 'request': {'url': url, 'method': 'GET'}}},
                {'method': 'Network.responseReceived', 'params': {
                    'requestId': 'net-1', 'loaderId': 'loader-1', 'frameId': 'main-frame',
                    'type': 'Document', 'response': {'url': url, 'status': 200,
                        'mimeType': 'text/plain', 'securityState': 'secure',
                        'fromDiskCache': False, 'fromServiceWorker': False}}},
                {'method': 'Network.loadingFinished', 'params': {'requestId': 'net-1'}}]
            for event in self.change(events):
                event.setdefault('sessionId', 'new-session')
                self.messages.append(event)
            result = {'frameId': 'main-frame', 'loaderId': 'loader-1'}
        elif method == 'Network.getResponseBody':
            result = {'body': self.body, 'base64Encoded': False}
        reply = {'id': message['id'], 'result': result}
        if 'sessionId' in message:
            reply['sessionId'] = message['sessionId']
        self.messages.append(reply)

    def receive(self, deadline):
        if not self.messages:
            raise TimeoutError('fixture_timeout')
        return self.messages.popleft()


class RequestProbeTests(unittest.TestCase):
    def setUp(self):
        try:
            self.api = importlib.import_module('src.browser.request_probe')
            self.pipe = importlib.import_module('src.browser.cdp_pipe')
        except ModuleNotFoundError:
            self.fail('缺少待授权的真实请求采集与匿名管道入口')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        exe = self.root / 'Application/chrome.exe'
        exe.parent.mkdir()
        exe.write_bytes(b'never executed fixture')
        data = self.root / 'User Data'
        data.mkdir()
        self.target = self.api.DedicatedTarget(str(exe), str(data))

    def plan(self):
        with patch.object(self.api, '_file_version', return_value='156.0.8078.48'):
            return self.api.prepare_launch(self.target, 12345, selected=True)

    def trace(self, transport):
        channel = self.pipe.CdpChannel(transport)
        return self.api.collect_trace(channel, '203.0.113.9', deadline=time.monotonic()+2)

    def test_launch_requires_bound_explicit_approval_before_any_spawn(self):
        plan = self.plan()
        with patch.object(self.pipe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(self.api.ProbeError, 'authorization_required'):
                self.api.launch_probe(plan)
        spawn.assert_not_called()

    def test_plan_is_read_only_has_no_port_or_old_profile_and_only_fixed_target(self):
        plan = self.plan()
        self.assertEqual(plan.target_url, 'https://claude.ai/cdn-cgi/trace')
        self.assertIn('--remote-debugging-pipe', plan.arguments)
        self.assertNotIn('--remote-debugging-port', ' '.join(plan.arguments))
        self.assertEqual(plan.arguments[-1], 'about:blank')
        self.assertEqual(list(Path(self.target.user_data_dir).iterdir()), [])
        self.assertNotIn(str(self.root), repr(plan))

    def test_plan_rejects_nonempty_directory_and_unreviewed_version(self):
        with patch.object(self.api, '_file_version', return_value='999.0.0.0'):
            with self.assertRaisesRegex(self.api.ProbeError, 'version_not_reviewed'):
                self.api.prepare_launch(self.target, 12345, selected=True)
        (Path(self.target.user_data_dir)/'existing-profile').mkdir()
        with self.assertRaisesRegex(self.api.ProbeError, 'data_directory_not_empty'):
            self.plan()

    def test_mutated_or_changed_plan_is_rejected_before_spawn(self):
        plan = self.plan()
        approval = self.api.ProbeApproval(plan.digest, True, True)
        for altered in [replace(plan, proxy_port=23456), replace(plan, target_url='https://example.test/')]:
            with self.assertRaises(self.api.ProbeError):
                self.api.launch_probe(altered, approval=approval, proxy_preflight=lambda _: True)
        Path(self.target.executable).write_bytes(b'changed')
        with self.assertRaises(self.api.ProbeError):
            self.api.launch_probe(plan, approval=approval, proxy_preflight=lambda _: True)

    def test_preflight_cannot_replace_empty_data_or_executable_before_spawn(self):
        plan = self.plan()
        def preflight(_):
            (Path(self.target.user_data_dir)/'new-user-data').mkdir()
            return True
        with patch.object(self.api, '_file_version', return_value=plan.version), \
             patch.object(self.api, 'capture_process_snapshot', return_value=SimpleNamespace(complete=True, processes=())), \
             patch.object(self.api, 'spawn_with_pipe', side_effect=self.api.ProbeError('unexpected_spawn')) as spawn:
            with self.assertRaises(self.api.ProbeError):
                self.api.launch_probe(plan, approval=self.api.ProbeApproval(plan.digest, True, True),
                                      proxy_preflight=preflight)
            spawn.assert_not_called()

    def test_injected_channel_cannot_issue_runtime_binding(self):
        owned = self.api._OwnedProbe(self.plan(), SimpleNamespace(pid=999,poll=lambda:None), ScenarioTransport())
        with patch.object(owned._identity,'poll') as sampler:
            with self.assertRaisesRegex(self.api.ProbeError,'runtime_channel_unconfirmed'):
                owned.binding()
            sampler.assert_not_called()

    def test_owned_binding_rechecks_reviewed_executable_before_cim(self):
        plan=self.plan()
        owned=self.api._OwnedProbe(plan,SimpleNamespace(pid=999,poll=lambda:None),ScenarioTransport())
        owned._runtime_verified=True  # Exercise validation only; never produces evidence.
        Path(self.target.executable).write_bytes(b'changed after launch')
        with patch.object(owned._identity,'poll') as sampler:
            with self.assertRaisesRegex(self.api.ProbeError,'launch_target_changed'):
                owned.binding()
            sampler.assert_not_called()

    def test_exit_status_never_turns_missing_observation_into_exit_confirmation(self):
        owned=self.api._OwnedProbe(self.plan(),SimpleNamespace(pid=999,poll=lambda:0),ScenarioTransport())
        owned._closed.set()
        with patch.object(self.api,'capture_process_snapshot',return_value=SimpleNamespace(complete=False,processes=())):
            self.assertEqual(owned.exit_status().status,'unknown')
        with patch.object(self.api,'capture_process_snapshot',return_value=SimpleNamespace(complete=True,processes=())):
            self.assertEqual(owned.exit_status().status,'exited')
        with patch.object(self.api,'capture_process_snapshot',return_value=SimpleNamespace(complete=True,processes=(object(),))):
            self.assertEqual(owned.exit_status().status,'unknown')

    def test_failed_handshake_retains_owned_handle_for_readonly_exit_check(self):
        plan=self.plan()
        transport=ScenarioTransport()
        transport.close=lambda:None
        process=SimpleNamespace(pid=999,poll=lambda:0)
        with patch.object(self.api,'_file_version',return_value=plan.version), \
             patch.object(self.api,'capture_process_snapshot',return_value=SimpleNamespace(complete=True,processes=())), \
             patch.object(self.api,'spawn_with_pipe',return_value=(process,transport)):
            with self.assertRaises(self.api.ProbeError) as error:
                self.api.launch_probe(plan,approval=self.api.ProbeApproval(plan.digest,True,True),
                                      proxy_preflight=lambda _:True)
        self.assertIsNotNone(getattr(error.exception,'owned_probe',None))
        self.assertTrue(error.exception.owned_probe._closed.is_set())

    def test_valid_response_is_owned_request_only_and_never_route_evidence(self):
        transport = ScenarioTransport()
        result = self.trace(transport)
        self.assertEqual(result.request_status, 'pass')
        self.assertEqual(result.observed_ip, '203.0.113.9')
        self.assertEqual(result.proxy_status, 'unknown')
        self.assertEqual(result.request_id, 'net-1')
        self.assertNotIn('203.0.113.9', repr(result))
        methods = [m['method'] for m in transport.sent]
        for forbidden in ['Target.getTargets', 'Target.setDiscoverTargets', 'Network.getCookies',
                          'Network.getAllCookies', 'Runtime.evaluate', 'Browser.close']:
            self.assertNotIn(forbidden, methods)
        target = next(m for m in transport.sent if m['method']=='Target.createTarget')
        self.assertEqual(target['params']['url'], 'about:blank')
        self.assertEqual(target['params']['browserContextId'], 'new-context')
        self.assertIn('Target.disposeBrowserContext', methods)

    def test_ip_mismatch_is_fail_but_no_full_ip_in_repr(self):
        result = self.trace(ScenarioTransport(body='h=claude.ai\nip=203.0.113.10\n'))
        self.assertEqual(result.request_status, 'fail')
        self.assertNotIn('203.0.113.10', repr(result))

    def test_cache_serviceworker_redirect_frame_and_loader_mismatch_rejected(self):
        def changed(index, key, value):
            def change(events):
                events[index]['params'][key] = value
                return events
            return change
        changes = [changed(0, 'redirectResponse', {'status':302}), changed(0,'frameId','other-frame'),
                   changed(0,'loaderId','old-loader'), changed(1,'networkId','other-request')]
        for field in ['fromDiskCache','fromServiceWorker','fromPrefetchCache']:
            def change(events, field=field):
                events[2]['params']['response'][field]=True
                return events
            changes.append(change)
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(self.api.ProbeError):
                    self.trace(ScenarioTransport(change=change))

    def test_unexpected_url_is_blocked_without_reading_response_body(self):
        def change(events):
            events[1]['params']['request']['url']='https://example.test/private'
            return events
        transport = ScenarioTransport(change=change)
        with self.assertRaises(self.api.ProbeError):
            self.trace(transport)
        methods=[m['method'] for m in transport.sent]
        self.assertIn('Fetch.failRequest',methods)
        self.assertNotIn('Network.getResponseBody',methods)

    def test_untrusted_or_oversized_response_body_is_rejected(self):
        for body in ['h=example.test\nip=203.0.113.9\n','h=claude.ai\nip=203.0.113.9\nip=203.0.113.9',
                     'h=claude.ai\nip=not-an-ip','x'*4097]:
            with self.subTest(body_length=len(body)):
                with self.assertRaises(self.api.ProbeError):
                    self.trace(ScenarioTransport(body=body))

    def test_cdp_wrong_session_and_duplicate_reply_fail_closed(self):
        class WrongSession(ScenarioTransport):
            def receive(self,deadline):
                message=super().receive(deadline)
                if 'id' in message:message['sessionId']='unowned-session'
                return message
        with self.assertRaises(self.api.ProbeError):
            self.trace(WrongSession())

    def test_cached_event_even_before_request_cannot_be_accepted(self):
        def change(events):
            return [{'method':'Network.requestServedFromCache','params':{'requestId':'net-1'}}]+events
        with self.assertRaises(self.api.ProbeError):
            self.trace(ScenarioTransport(change=change))

    def test_protocol_duplicate_reply_and_raw_error_are_not_accepted_or_exposed(self):
        transport=ScenarioTransport()
        channel=self.pipe.CdpChannel(transport)
        channel.command('Page.enable',{},time.monotonic()+2)
        transport.messages.append({'id':1,'result':{}})
        with self.assertRaisesRegex(self.api.ProbeError,'unexpected_protocol_reply'):
            channel.pump(time.monotonic()+2)
        channel.send('Page.enable',{},time.monotonic()+2)
        transport.messages.clear()
        transport.messages.append({'id':2,'error':{'message':'private-secret'}})
        with self.assertRaises(self.api.ProbeError) as error:
            channel.pump(time.monotonic()+2)
        self.assertNotIn('private-secret',str(error.exception))

    def test_channel_enforces_deadline_even_for_injected_transport(self):
        transport=ScenarioTransport()
        channel=self.pipe.CdpChannel(transport)
        with self.assertRaisesRegex(self.api.ProbeError,'protocol_timeout'):
            channel.command('Page.enable',{},time.monotonic()-1)
        self.assertEqual(transport.sent,[])

    @unittest.skipUnless(os.name=='nt','Windows pipe framing')
    def test_pipe_fragmented_coalesced_messages_timeout_and_close(self):
        read,write=os.pipe()
        unused_read,unused_write=os.pipe()
        transport=self.pipe.PipeTransport(read,unused_write)
        try:
            os.write(write,b'{"id":1,')
            with self.assertRaisesRegex(self.api.ProbeError,'pipe_timeout'):
                transport.receive(time.monotonic()+.02)
            os.write(write,b'"result":{}}\0{"id":2,"result":{}}\0')
            self.assertEqual(transport.receive(time.monotonic()+1)['id'],1)
            self.assertEqual(transport.receive(time.monotonic()+1)['id'],2)
            transport.close()
            with self.assertRaisesRegex(self.api.ProbeError,'pipe_closed'):
                transport.receive(time.monotonic()+1)
        finally:
            transport.close()
            os.close(write)
            os.close(unused_read)

    @unittest.skipUnless(os.name=='nt','Windows anonymous handle inheritance')
    def test_real_anonymous_handle_pair_with_local_child_and_no_browser(self):
        script = ('import os,sys,msvcrt; '
                  'r=msvcrt.open_osfhandle(int(sys.argv[1]),os.O_RDONLY|os.O_BINARY); '
                  'w=msvcrt.open_osfhandle(int(sys.argv[2]),os.O_WRONLY|os.O_BINARY); '
                  'data=os.read(r,4096); os.write(w,data); os.close(r); os.close(w)')
        process, transport = self.pipe.spawn_with_pipe(
            lambda read,write:[sys.executable,'-I','-B','-c',script,str(read),str(write)])
        try:
            transport.send({'id':1,'result':{'fixture':'中文'}},time.monotonic()+3)
            response=transport.receive(time.monotonic()+3)
            self.assertEqual(response,{'id':1,'result':{'fixture':'中文'}})
            self.assertEqual(process.wait(timeout=3),0)
        finally:
            transport.close()


if __name__ == '__main__':
    unittest.main()
