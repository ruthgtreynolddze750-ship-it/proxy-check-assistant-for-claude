"""Worker failure metadata through real relay/runtime methods; all I/O injected."""
from dataclasses import asdict, FrozenInstanceError
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.protection import session_relay as sr, relay_identity as ri
from src.protection.managed_session import ManagedSessionRuntime, NativeManagedBackend, RuntimeView, SamplingBudget
from src.core.backend import Config
from src.browser.inspection import BrowserSelection
from test_managed_session import SyntheticSessionBackend


class FakeSocket:
    def __init__(self, role, mode='eof'):
        self.role, self.mode, self.closed = role, mode, False
    def getsockname(self): return ('127.0.0.1', 41001 if self.role=='upstream' else 49152)
    def getpeername(self): return ('127.0.0.1', 25001 if self.role=='upstream' else 40001)
    def setblocking(self, *args): pass
    def settimeout(self, *args): pass
    def connect(self, *args):
        if self.mode=='connect_timeout': raise TimeoutError('SECRET endpoint')
    def recv(self, *args):
        if self.mode=='reset' and self.role=='upstream':
            raise ConnectionResetError(10054, 'SECRET request')
        return b''
    def send(self, data): return len(data)
    def shutdown(self, how):
        if self.mode=='shutdown_error' and self.role=='upstream' and how==socket.SHUT_WR:
            raise OSError(10057, 'SECRET half close')
    def close(self): self.closed=True


class WorkerDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.now=[100.]
        self.monotonic=patch('time.monotonic',lambda:self.now[0])
        self.monotonic.start()
        self.addCleanup(self.monotonic.stop)

    def relay(self):
        config=Config(25001,25002,'203.0.113.1','https://example.test')
        selection=BrowserSelection('https://claude.ai/',r'C:\owned\chrome.exe',r'C:\data','Default')
        backend=SyntheticSessionBackend()
        monitor=backend.initialize(config,selection,'a'*64,SamplingBudget(),threading.Event(),None)
        self.addCleanup(monitor.stop)
        relay=sr.SessionRelay(monitor,config,verifier=object(),max_lease_seconds=2.)
        relay._binding=backend.binding
        relay._listener=FakeSocket('listener')
        relay._reservation=sr.RelayReservation('fixture',('127.0.0.1',49152))
        relay._lease=monitor._relay_leases[-1]
        relay._deadline=relay._lease.expires_at
        relay._state,relay._reason,relay._generation='listening','lease_active',7
        relay._diagnostic_used=True
        relay._active_policy=monitor._guard.policy
        relay._policies=[monitor._guard.policy]
        self.addCleanup(relay.stop)
        return relay,backend,monitor

    def connection(self,relay,backend,mode,generation=None,proof_hook=None):
        client,upstream=FakeSocket('client',mode),FakeSocket('upstream',mode)
        binding=backend.binding
        def client_proof(*args):
            if proof_hook is not None: proof_hook()
            if mode=='proof_error': raise OSError('SECRET identity path')
            if mode=='binding_changed': raise ri.BindingChanged('SECRET binding')
            if mode=='proof_missing': return None
            return ri.ClientProof(client.getpeername(),client.getsockname(),102,1001,binding.executable,
                binding.root_pid,binding.root_created,self.now[0])
        relay._verifier=SimpleNamespace(client=client_proof,
            listener=lambda *a:ri.ProxyProof(backend.owner,self.now[0]),
            upstream=lambda *a:ri.ProxyProof(backend.owner,self.now[0],upstream.getsockname(),upstream.getpeername()))
        relay._sockets.add(client);relay._clients.add(client)
        def select(reads,writes,errors,timeout):
            if mode=='select_error_list':return [],[],[client]
            if mode=='shutdown_error':return [client] if client in reads else [],[],[]
            return list(reads),list(writes),[]
        with patch.object(sr.socket,'socket',return_value=upstream),patch.object(sr.select,'select',select):
            relay._connection(client,relay._generation if generation is None else generation)
        return client,upstream

    def detail(self,relay):
        self.assertTrue(hasattr(relay.snapshot(),'worker_diagnostic'),'missing worker diagnostic snapshot contract')
        return relay.snapshot().worker_diagnostic

    def test_snapshot_and_runtime_default_have_no_worker_failure(self):
        relay,_,_=self.relay()
        self.assertIsNone(self.detail(relay))
        self.assertTrue(hasattr(RuntimeView(),'worker_diagnostic'),'missing runtime projection')
        self.assertIsNone(RuntimeView().worker_diagnostic)

    def test_fixed_failure_stages_keep_whole_relay_close_and_revocation(self):
        for mode,stage,code in (('reset','upstream_recv','connection_reset'),
            ('connect_timeout','upstream_connect','timeout'),
            ('shutdown_error','upstream_half_close','os_error'),
            ('proof_error','client_identity','os_error')):
            with self.subTest(mode=mode):
                relay,backend,_=self.relay()
                sockets=self.connection(relay,backend,mode)
                self.assertEqual((relay._state,relay._reason,relay._generation),('closed','worker_error',8))
                self.assertTrue(relay._active_policy.revoked.is_set())
                self.assertTrue(sockets[0].closed)
                self.assertEqual(sockets[1].closed,mode!='proof_error')
                detail=self.detail(relay)
                self.assertEqual(asdict(detail),{'stage':stage,'error_code':code,'incomplete':False})
                with self.assertRaises(FrozenInstanceError):detail.stage='changed'

    def test_other_close_paths_and_normal_connection_end_get_no_worker_record(self):
        for mode in ('eof','proof_missing','select_error_list','binding_changed'):
            with self.subTest(mode=mode):
                relay,backend,_=self.relay()
                self.connection(relay,backend,mode)
                self.assertEqual(relay._reason,'binding_changed' if mode=='binding_changed' else 'lease_active')
                self.assertIsNone(self.detail(relay))

    def test_late_generation_cannot_replace_first_worker_or_expiry_reason(self):
        relay,backend,_=self.relay()
        self.connection(relay,backend,'reset')
        first=self.detail(relay)
        self.connection(relay,backend,'proof_error',generation=7)
        self.assertIs(self.detail(relay),first)
        other,backend,_=self.relay()
        other._close('lease_expired')
        self.connection(other,backend,'proof_error',generation=7)
        self.assertEqual(other._reason,'lease_expired')
        self.assertIsNone(self.detail(other))

    def test_busy_diagnostic_lock_never_blocks_close_or_fills_with_late_failure(self):
        relay,backend,_=self.relay()
        self.assertTrue(hasattr(relay,'_worker_diagnostic_lock'),'missing nonblocking recorder')
        relay._worker_diagnostic_lock.acquire()
        try:
            self.connection(relay,backend,'reset')
            self.assertTrue(relay._active_policy.revoked.is_set())
            self.assertEqual(asdict(self.detail(relay)),{'stage':'unknown','error_code':'unavailable','incomplete':True})
        finally:relay._worker_diagnostic_lock.release()
        self.connection(relay,backend,'proof_error',generation=7)
        self.assertTrue(self.detail(relay).incomplete)
        self.assertEqual(self.detail(relay).error_code,'unavailable')

    def test_failed_diagnostic_publish_cannot_change_original_close(self):
        relay,backend,_=self.relay()
        self.assertTrue(hasattr(relay,'_publish_worker_failure'),'missing post-close recorder')
        def broken(error):
            self.assertEqual(relay._state,'closed')
            self.assertTrue(relay._active_policy.revoked.is_set())
            self.assertIsNone(relay._listener)
            self.assertFalse(relay._sockets)
            raise RuntimeError('SECRET diagnostic error')
        with patch.object(relay,'_publish_worker_failure',broken):
            self.connection(relay,backend,'reset')
        self.assertEqual(relay._reason,'worker_error')
        self.assertTrue(self.detail(relay).incomplete)

    def test_exception_text_is_never_read_or_serialized(self):
        class PrivateError(OSError):
            def __str__(self):raise AssertionError('private str read')
            def __repr__(self):raise AssertionError('private repr read')
        def fail():raise PrivateError('SECRET IP port path content')
        relay,backend,_=self.relay()
        self.connection(relay,backend,'eof',proof_hook=fail)
        detail=self.detail(relay)
        self.assertEqual(detail.error_code,'os_error')
        self.assertEqual(set(asdict(detail)),{'stage','error_code','incomplete'})
        self.assertNotIn('SECRET',json.dumps(asdict(detail)))

    def test_base_exception_in_diagnostic_publish_is_also_non_authoritative(self):
        relay,backend,_=self.relay()
        with patch.object(relay,'_publish_worker_failure',side_effect=SystemExit('SECRET diagnostic')):
            self.connection(relay,backend,'reset')
        self.assertEqual(relay._reason,'worker_error')
        self.assertTrue(relay._active_policy.revoked.is_set())
        self.assertTrue(self.detail(relay).incomplete)

    def test_damaged_thread_local_metadata_cannot_cause_or_prevent_close(self):
        for error_type in (RuntimeError,SystemExit):
            with self.subTest(error=error_type.__name__):
                class BrokenLocal:
                    def __setattr__(self,name,value):raise error_type('diagnostic metadata unavailable')
                relay,backend,_=self.relay()
                relay._worker_diagnostic_local=BrokenLocal()
                self.connection(relay,backend,'eof')
                self.assertEqual(relay._state,'listening')
                self.connection(relay,backend,'reset')
                self.assertEqual(relay._reason,'worker_error')
                self.assertTrue(self.detail(relay).incomplete)

    def test_concurrent_workers_publish_only_the_actual_close_winner(self):
        relay,backend,_=self.relay()
        barrier=threading.Barrier(2)
        winner=[]
        errors=[]
        original=relay._reserve_worker_failure
        def reserve(reason):
            original(reason)
            winner.append(threading.current_thread().name)
        relay._reserve_worker_failure=reserve
        def proof(binding,client):
            barrier.wait(1)
            if client.mode=='reset':raise ConnectionResetError('SECRET')
            raise TimeoutError('SECRET')
        relay._verifier=SimpleNamespace(client=proof)
        def run(mode):
            client=FakeSocket('client',mode)
            try:relay._connection(client,7)
            except BaseException as error:errors.append(type(error).__name__)
        threads=[threading.Thread(target=run,args=(mode,),name=mode) for mode in ('reset','timeout')]
        for thread in threads:thread.start()
        for thread in threads:thread.join(2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertFalse(errors)
        self.assertEqual(len(winner),1)
        self.assertEqual(self.detail(relay).error_code,{'reset':'connection_reset','timeout':'timeout'}[winner[0]])

    def test_runtime_publishes_actual_relay_failure_and_retains_it_after_stop(self):
        relay,backend,monitor=self.relay()
        self.connection(relay,backend,'reset')
        with tempfile.TemporaryDirectory() as folder:
            runtime=ManagedSessionRuntime(journal_path=Path(folder)/'absent.json')
            backend.snapshot=relay.snapshot
            runtime._backend,runtime._session=backend,monitor
            runtime._view=RuntimeView(phase='alarm',reason_code='guard_sample_failed')
            runtime._publish()
            self.assertTrue(hasattr(runtime.current(),'worker_diagnostic'),'missing runtime projection')
            detail=runtime.current().worker_diagnostic
            self.assertIs(detail,self.detail(relay))
            relay.stop()
            runtime._publish()
            self.assertIs(runtime.current().worker_diagnostic,detail)

    def test_initialization_worker_failure_is_reported_without_monitor_session(self):
        relay,adapter,_=self.relay()
        with tempfile.TemporaryDirectory() as folder:
            backend=NativeManagedBackend()
            runtime=ManagedSessionRuntime(journal_path=Path(folder)/'absent.json',backend_factory=lambda:backend)
            backend.relay,backend.cancel=relay,runtime._cancel
            def fail_initialize(*args):
                self.connection(relay,adapter,'reset')
                raise ValueError('synthetic_initialization_failure')
            backend.initialize=fail_initialize
            backend.cleanup=lambda **kwargs:True
            runtime._run()
            self.assertIsNone(runtime._session)
            self.assertEqual(runtime.current().phase,'alarm')
            self.assertIs(runtime.current().worker_diagnostic,self.detail(relay))

    def test_late_runtime_metadata_cannot_overwrite_replaced_backend(self):
        relay,adapter,_=self.relay()
        self.connection(relay,adapter,'reset')
        with tempfile.TemporaryDirectory() as folder:
            runtime=ManagedSessionRuntime(journal_path=Path(folder)/'absent.json')
            def late():
                runtime._backend=object()
                return self.detail(relay)
            backend=SimpleNamespace(worker_diagnostic=late)
            runtime._backend=backend
            runtime._record_worker_diagnostic(backend,runtime._cancel)
            self.assertIsNone(runtime.current().worker_diagnostic)


if __name__=='__main__':unittest.main()
