"""R33 protected desktop launch: rules, process tree, relay and fuse runtime, all offline."""
import copy
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from src.core import backend
from src.core.backend import Check, Config, Detection
from src.protection import dedicated_wfp
from src.protection import desktop_wfp as wfp
from src.protection.desktop_process import DesktopTree, TreeObservation, running_executables
from src.protection.desktop_relay import DesktopRelay
from src.protection.desktop_session import DesktopBudget, DesktopProtectionRuntime
from src.protection.relay_identity import ProxyProof


CFG = Config(proxy_port=24001, manager_port=22999, expected_ip='192.0.2.1', ip_url='https://ip.example/')


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class FakeEngine:
    def __init__(self):
        self.objects, self.pending = {}, None

    def app_id(self, path):
        return ('app:' + wfp.path_key(path)).encode()

    def capabilities(self):
        return dedicated_wfp.REQUIRED_FIELDS

    def sublayer_weights(self):
        return frozenset(o['weight'] for o in self.objects.values() if o['kind'] == 'sublayer')

    def begin(self):
        self.pending = copy.deepcopy(self.objects)

    def add(self, obj):
        self.pending[obj['key']] = copy.deepcopy(obj)

    def get(self, kind, key):
        return copy.deepcopy((self.pending if self.pending is not None else self.objects).get(key))

    def delete(self, kind, key):
        del self.pending[key]

    def commit(self):
        self.objects, self.pending = self.pending, None

    def abort(self):
        self.pending = None

    def close(self):
        pass


class DesktopRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        (base / 'app').mkdir()
        (base / 'code').mkdir()
        self.desktop, self.code = base / 'app' / 'Claude.exe', base / 'code' / 'claude.exe'
        self.desktop.write_bytes(b'desktop')
        self.code.write_bytes(b'code')
        self.engine = FakeEngine()
        self.plan = wfp.prepare_plan((('desktop', str(self.desktop)), ('claude_code', str(self.code))),
                                     43210, backend=self.engine)

    def tearDown(self):
        self.temp.cleanup()

    def test_each_executable_gets_the_dedicated_chrome_rule_set(self):
        objects = wfp.plan_objects(self.plan)
        self.assertEqual([o['kind'] for o in objects], ['provider', 'sublayer'] + ['filter'] * 8)
        for index, app in enumerate(self.plan.apps):
            rules = [o for o in objects if o['kind'] == 'filter' and o['name'].startswith(f'Claude desktop WFP app{index}-')]
            app_condition = (dedicated_wfp.APP_ID, dedicated_wfp.EQUAL, dedicated_wfp.BLOB, app.app_id.hex())
            extras = sorted(tuple(c for c in rule['conditions'] if c != app_condition) for rule in rules)
            self.assertEqual(extras, sorted([(), ((dedicated_wfp.PROTOCOL, dedicated_wfp.NOT_EQUAL, dedicated_wfp.UINT8, 6),),
                ((dedicated_wfp.ADDRESS, dedicated_wfp.NOT_EQUAL, dedicated_wfp.UINT32, 0x7f000001),),
                ((dedicated_wfp.PORT, dedicated_wfp.NOT_EQUAL, dedicated_wfp.UINT16, 43210),)]))
            self.assertTrue(all(rule['action'] == dedicated_wfp.FWP_ACTION_BLOCK for rule in rules))

    def test_rules_never_change_while_the_desktop_runs(self):
        approval = wfp.PlanApproval(self.plan.digest, 'apply')
        with self.assertRaises(wfp.PolicyError):
            wfp.apply_plan(self.plan, approval=approval, backend=self.engine, processes_absent=lambda plan: None)
        self.assertEqual(self.engine.objects, {})
        wfp.apply_plan(self.plan, approval=approval, backend=self.engine, processes_absent=lambda plan: True)
        rollback = wfp.PlanApproval(self.plan.digest, 'rollback')
        with self.assertRaises(wfp.PolicyError):
            wfp.rollback_plan(self.plan, approval=rollback, backend=self.engine, processes_absent=lambda plan: False)
        self.assertEqual(len(self.engine.objects), 10)
        wfp.rollback_plan(self.plan, approval=rollback, backend=self.engine, processes_absent=lambda plan: True)
        self.assertEqual(self.engine.objects, {})
        self.assertTrue(wfp.objects_absent(self.plan, backend=self.engine))

    def test_approval_is_bound_to_the_plan_and_action(self):
        with self.assertRaises(wfp.PolicyError):
            wfp.apply_plan(self.plan, approval=wfp.PlanApproval(self.plan.digest, 'rollback'),
                           backend=self.engine, processes_absent=lambda plan: True)
        with self.assertRaises(wfp.PolicyError):
            wfp.apply_plan(self.plan, approval=wfp.PlanApproval('0' * 64, 'apply'),
                           backend=self.engine, processes_absent=lambda plan: True)

    def test_readback_fails_when_rules_or_executables_change(self):
        wfp.apply_plan(self.plan, approval=wfp.PlanApproval(self.plan.digest, 'apply'), backend=self.engine,
                       processes_absent=lambda plan: True)
        verifier = wfp.DesktopPolicyVerifier(self.plan, clock=time.monotonic, backend_factory=lambda: self.engine)
        self.assertTrue(verifier.accepts(verifier.read()))
        key = next(iter(self.engine.objects))
        removed = self.engine.objects.pop(key)
        with self.assertRaises(wfp.PolicyError):
            verifier.read()
        self.engine.objects[key] = removed
        self.code.write_bytes(b'updated code')
        with self.assertRaises(wfp.PolicyError):
            verifier.read()

    def test_journal_rebuilds_the_exact_plan_and_rejects_tampering(self):
        record = json.loads(json.dumps(wfp.journal_record(self.plan)))
        self.assertEqual(wfp.plan_from_journal(record), self.plan)
        record['relay_port'] = 1
        with self.assertRaises(wfp.PolicyError):
            wfp.plan_from_journal(record)


class DesktopTreeTests(unittest.TestCase):
    DESKTOP, CODE, HERDR = r'C:\pkg\app\Claude.exe', r'C:\data\code\claude.exe', r'C:\Users\u\.local\bin\claude.exe'

    def setUp(self):
        self.rows = [(10, 1, 'Claude.exe'), (11, 10, 'Claude.exe'), (12, 11, 'claude.exe'),
                     (13, 12, 'powershell.exe'), (20, 2, 'claude.exe')]
        self.info = {10: (100, self.DESKTOP), 11: (110, self.DESKTOP), 12: (120, self.CODE),
                     13: (130, r'C:\Windows\powershell.exe'), 20: (90, self.HERDR)}
        self.tree = DesktopTree(10, 100, self.DESKTOP, (self.DESKTOP, self.CODE),
                                lister=lambda: tuple(self.rows), info=self.info.get)

    def test_only_protected_executables_in_this_launch_are_admitted(self):
        self.assertTrue(self.tree.admits(10))
        self.assertTrue(self.tree.admits(11))
        self.assertTrue(self.tree.admits(12))
        self.assertFalse(self.tree.admits(13))   # D1: other children are not protected programs
        self.assertFalse(self.tree.admits(20))   # herdr's Claude Code is a different file and tree

    def test_recycled_parent_pid_is_not_trusted(self):
        self.info[12] = (105, self.CODE)          # older than its claimed parent 11
        self.assertFalse(self.tree.admits(12))

    def test_read_reports_unknown_claude_and_exit(self):
        self.rows.append((14, 11, 'claude.exe'))
        self.info[14] = (140, r'C:\data\code\9.9.9\claude.exe')
        observation = self.tree.read()
        self.assertEqual(observation.allowed, frozenset({(10, 100), (11, 110), (12, 120)}))
        self.assertEqual(observation.unknown_claude, (r'C:\data\code\9.9.9\claude.exe',))
        self.assertEqual(observation.other_children, 1)
        self.info[10] = None
        with self.assertRaisesRegex(ValueError, 'desktop_exited'):
            self.tree.read()

    def test_running_executables(self):
        self.assertTrue(running_executables((self.CODE,), lister=lambda: tuple(self.rows), info=self.info.get))
        self.assertFalse(running_executables((r'C:\other\claude.exe',), lister=lambda: tuple(self.rows),
                                             info=self.info.get))


class _Upstream:
    """Stands in for Proxy Manager 24001: echoes bytes back."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                conn.sendall(data)


class _Verifier:
    owner = ('pm',)

    def upstream(self, config, connected):
        return ProxyProof(self.owner, time.monotonic(), connected.getsockname(), connected.getpeername())


class DesktopRelayTests(unittest.TestCase):
    def setUp(self):
        self.upstream = _Upstream()
        self.verifier = _Verifier()
        self.admitted = True
        self.relay = DesktopRelay(Config(proxy_port=self.upstream.port, manager_port=22999, expected_ip='192.0.2.1', ip_url='https://ip.example/'), admit=lambda c, s: self.admitted,
                                  verifier=self.verifier, max_lease_seconds=0.5)
        self.port = self.relay.reserve()

    def tearDown(self):
        self.relay.close()
        self.upstream.listener.close()

    def roundtrip(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
            client.settimeout(1)
            client.sendall(b'ping')
            try:
                return client.recv(4)
            except (OSError, socket.timeout):
                return b''

    def test_no_forwarding_before_authorization(self):
        self.assertEqual(self.roundtrip(), b'')

    def test_pause_keeps_the_port_and_resume_forwards_again(self):
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('pm',)))
        self.assertEqual(self.roundtrip(), b'ping')
        self.relay.pause('exit_ip_mismatch')
        self.assertEqual(self.relay.snapshot().state, 'paused')
        self.assertEqual(self.roundtrip(), b'')
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('pm',)))
        self.assertEqual(self.relay.port, self.port)
        self.assertEqual(self.roundtrip(), b'ping')

    def test_open_stream_is_cut_by_a_fuse(self):
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('pm',)))
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
            client.sendall(b'a')
            self.assertEqual(client.recv(1), b'a')
            self.relay.pause('proxy_owner_changed')
            client.settimeout(1)
            try:
                closed = client.recv(1) == b''
            except OSError:
                closed = True
            self.assertTrue(closed)

    def test_lease_expiry_pauses(self):
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.1, ('pm',)))
        self.assertTrue(wait_for(lambda: self.relay.snapshot().state == 'paused', 2))
        self.assertEqual(self.relay.snapshot().reason_code, 'lease_expired')

    def test_owner_change_is_refused_unless_readopted_while_paused(self):
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('pm',)))
        self.assertFalse(self.relay.authorize(time.monotonic() + 0.4, ('other',)))
        self.assertEqual(self.relay.snapshot().reason_code, 'proxy_owner_changed')
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('other',), new_owner=True))

    def test_unadmitted_client_is_rejected_and_unverified_upstream_fuses(self):
        self.assertTrue(self.relay.authorize(time.monotonic() + 0.4, ('pm',)))
        self.admitted = False
        self.assertEqual(self.roundtrip(), b'')
        self.assertEqual(self.relay.snapshot().state, 'forwarding')
        self.admitted, self.verifier.owner = True, ('impostor',)
        self.assertEqual(self.roundtrip(), b'')
        self.assertTrue(wait_for(lambda: self.relay.snapshot().state == 'paused', 2))
        self.assertEqual(self.relay.snapshot().reason_code, 'upstream_unconfirmed')


def detection(owner=('pm',), exit_status='pass'):
    ok = Check('pass', 'ok')
    return Detection(ok, ok, Check(exit_status, 'exit'), ok, Check('unknown', ''), mapping=ok,
                     _owner_evidence=owner, target_trace=ok)


class FakeRelay:
    def __init__(self):
        self.state, self.reason, self.port, self.owner = 'unbound', '', None, None
        self.pauses = []

    def reserve(self):
        self.state, self.port = 'reserved', 45678
        return self.port

    def authorize(self, deadline, owner, *, new_owner=False):
        if self.state == 'closed':
            return False
        if self.owner is not None and owner != self.owner and not (new_owner and self.state == 'paused'):
            self.pause('proxy_owner_changed')
            return False
        self.owner, self.state = owner, 'forwarding'
        return True

    def pause(self, reason):
        if self.state != 'closed':
            self.state, self.reason = 'paused', reason
            self.pauses.append(reason)

    def close(self, reason='stopped'):
        self.state = 'closed'

    def snapshot(self):
        from src.protection.desktop_relay import DesktopRelaySnapshot
        return DesktopRelaySnapshot(self.state, self.reason, 0, self.port)


class FakeTree:
    def __init__(self):
        self.alive, self.unknown = True, ()

    def read(self):
        if not self.alive:
            raise ValueError('desktop_exited')
        return TreeObservation(frozenset({(10, 1)}), self.unknown, 0)

    def root_alive(self):
        return self.alive

    def admits(self, pid):
        return pid == 10


class FakeVerifier:
    def __init__(self, plan):
        self.plan, self.fail = plan, False

    def read(self):
        if self.fail:
            raise wfp.PolicyError('object_mismatch')
        now = time.monotonic()
        return wfp.DesktopPolicyReadback(self.plan.digest, self.plan.relay_port, now, now + 5, 'injected')

    def close(self):
        pass


class FakeBackend:
    DESKTOP, CODE = r'C:\fake\app\Claude.exe', r'C:\fake\code\claude.exe'

    def __init__(self):
        self.running_state = False
        self.detections = []
        self.default = detection()
        self.detect_delay = 0.0
        self.owner = ('pm',)
        self.rows = ()
        self.applied = self.rolled_back = self.launches = 0
        self.present = False
        self.launch_pid = 10
        self.relay, self.tree = FakeRelay(), FakeTree()
        self.verifier_obj = None
        self.launch_port = None
        self.exit_status = 'pass'
        self.exit_checks = 0

    def desktop_check(self, config):
        return 'fail' if self.running_state else 'pass'

    def discover(self, app_id):
        return (('desktop', self.DESKTOP), ('claude_code', self.CODE))

    def detect(self, config, *, deadline, cancelled):
        if self.detect_delay:
            if cancelled.wait(self.detect_delay):
                raise backend.DetectionCancelled('cancelled')
        return self.detections.pop(0) if self.detections else self.default

    def exit_check(self, config):
        self.exit_checks += 1
        return Check(self.exit_status, 'exit')

    def make_relay(self, config, admit, lease_seconds):
        self.admit = admit
        return self.relay

    def prepare_plan(self, executables, port):
        apps = tuple(wfp.DesktopApp(role, path, (1, 1, 1, 1), 'a' * 64, path.encode()) for role, path in executables)
        return wfp.DesktopPolicyPlan(apps, port, '0b6c2c2e-7f1f-4bd5-9a43-2f9b0a7a1c11', 0x8000, 'injected')

    def apply(self, plan):
        assert not self.running_state
        self.applied += 1
        self.present = True

    def rollback(self, plan):
        assert not self.running_state
        self.rolled_back += 1
        self.present = False

    def objects_absent(self, plan):
        return not self.present

    def verifier(self, plan, clock, max_age):
        self.verifier_obj = FakeVerifier(plan)
        return self.verifier_obj

    def launch(self, config, app_id, port):
        self.launches += 1
        self.launch_port = port
        if self.launch_pid is not None:
            self.running_state = True
        return self.launch_pid

    def process_info(self, pid):
        return (1, self.DESKTOP)

    def path_key(self, path):
        return wfp.path_key(path)

    def make_tree(self, pid, created, desktop, executables):
        return self.tree

    def running(self, executables):
        return self.running_state

    def connection_pid(self, client_endpoint, server_endpoint):
        return 10

    def proxy_owner(self, config):
        return self.owner

    def tcp_rows(self):
        return self.rows


FAST = DesktopBudget(guard_interval_seconds=0.02, guard_budget_seconds=0.2, lease_seconds=0.5,
                     manager_interval_seconds=0.05, manager_budget_seconds=1.0, exit_ttl_seconds=3.0,
                     exit_check_interval_seconds=0.05, exit_check_budget_seconds=1.0, manager_max_age_seconds=6.0,
                     exit_wait_poll_seconds=0.02)


class DesktopRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = Path(self.temp.name) / 'desktop-recovery.json'
        self.backend = FakeBackend()
        self.runtime = self.make_runtime()

    def make_runtime(self, budget=FAST):
        return DesktopProtectionRuntime(journal_path=self.journal, budget=budget, backend=self.backend)

    def tearDown(self):
        self.runtime.abandon()
        self.temp.cleanup()

    def start(self):
        self.assertTrue(self.runtime.request_start(CFG, 'Claude_pzs8sxrjxfjjc!Claude', 'r1'))
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'running'), self.runtime.current())

    def fused(self, reason):
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'fused'), self.runtime.current())
        view = self.runtime.current()
        self.assertEqual(view.reason_code, reason)
        self.assertEqual(self.backend.relay.state, 'paused')
        self.assertEqual(self.backend.rolled_back, 0)          # rules stay: no direct route after a fuse
        self.assertTrue(self.backend.running_state)             # the desktop is never ended (R3)
        self.assertTrue(self.journal.exists())

    def test_launch_uses_the_relay_and_forwards_after_checks(self):
        self.start()
        self.assertEqual(self.backend.launch_port, 45678)
        self.assertEqual(self.backend.applied, 1)
        self.assertEqual(self.backend.relay.state, 'forwarding')
        self.assertTrue(self.journal.exists())
        self.assertTrue(wait_for(lambda: self.runtime.current().manager_sequence >= 2))
        self.assertTrue(self.backend.admit(('127.0.0.1', 1), ('127.0.0.1', 45678)))

    def test_exit_ip_change_fuses_and_manual_resume_reopens_the_same_port(self):
        self.start()
        self.backend.default = detection(exit_status='fail')
        self.fused('exit_ip_mismatch')
        self.assertTrue(self.runtime.current().resumable)
        self.assertTrue(self.runtime.request_resume())
        self.assertTrue(wait_for(lambda: 'resume_rejected_exit_ip_mismatch' == self.runtime.current().reason_code))
        self.backend.default = detection()
        self.assertTrue(self.runtime.request_resume())
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'running'))
        self.assertEqual((self.backend.relay.state, self.backend.relay.port, self.backend.launches),
                         ('forwarding', 45678, 1))

    def test_proxy_manager_change_fuses_and_restarted_manager_can_be_readopted(self):
        self.start()
        self.backend.owner = ('restarted',)
        self.fused('proxy_owner_changed')
        self.backend.default = detection(owner=('restarted',))
        self.assertTrue(self.runtime.request_resume())
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'running'))

    def test_rule_readback_failure_fuses(self):
        self.start()
        self.backend.verifier_obj.fail = True
        self.fused('guard_failed')

    def test_unknown_desktop_program_fuses(self):
        self.start()
        self.backend.tree.unknown = (r'C:\fake\code\new\claude.exe',)
        self.fused('unknown_desktop_executable')

    def test_route_outside_the_relay_fuses_but_inbound_does_not(self):
        self.start()
        self.backend.rows = ((2, ('127.0.0.1', 7000), ('0.0.0.0', 0), 10),
                             (5, ('127.0.0.1', 7000), ('127.0.0.1', 51000), 10),
                             (5, ('127.0.0.1', 52000), ('127.0.0.1', 45678), 10))
        time.sleep(0.2)
        self.assertEqual(self.runtime.current().phase, 'running')
        self.backend.rows += ((5, ('10.0.0.2', 53000), ('203.0.113.9', 443), 10),)
        self.fused('desktop_route_changed')

    def test_stale_exit_evidence_fuses(self):
        self.runtime = self.make_runtime(DesktopBudget(guard_interval_seconds=0.02, guard_budget_seconds=0.2,
            lease_seconds=0.5, manager_interval_seconds=0.05, manager_budget_seconds=0.5,
            exit_ttl_seconds=0.8, exit_check_interval_seconds=0.05, exit_check_budget_seconds=0.3,
            manager_max_age_seconds=6.0, exit_wait_poll_seconds=0.02))
        self.start()
        self.backend.exit_status = 'unknown'
        self.backend.detect_delay = 0.45
        self.fused('exit_evidence_expired')

    def test_wrong_expected_ip_refuses_to_start_without_rules_or_launch(self):
        self.backend.detections = [detection(exit_status='fail')]
        self.assertTrue(self.runtime.request_start(CFG, 'Claude_pzs8sxrjxfjjc!Claude', 'r1'))
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'failed'))
        self.assertEqual(self.runtime.current().reason_code, 'exit_ip_mismatch')
        self.assertEqual((self.backend.applied, self.backend.launches), (0, 0))
        self.assertFalse(self.journal.exists())

    def test_running_desktop_refuses_to_start(self):
        self.backend.running_state = True
        self.runtime.request_start(CFG, 'Claude_pzs8sxrjxfjjc!Claude', 'r1')
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'failed'))
        self.assertEqual(self.runtime.current().reason_code, 'desktop_running')
        self.assertEqual(self.backend.applied, 0)

    def test_failed_launch_removes_the_rules(self):
        self.backend.launch_pid = None
        self.runtime.request_start(CFG, 'Claude_pzs8sxrjxfjjc!Claude', 'r1')
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'failed'))
        self.assertEqual(self.runtime.current().reason_code, 'desktop_launch_failed')
        self.assertEqual(self.backend.rolled_back, 1)
        self.assertFalse(self.journal.exists())

    def test_stop_waits_for_the_desktop_to_exit_before_removing_rules(self):
        self.start()
        self.assertTrue(self.runtime.request_stop())
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'waiting_exit'))
        self.assertEqual(self.backend.relay.state, 'paused')
        time.sleep(0.1)
        self.assertEqual(self.backend.rolled_back, 0)
        self.backend.running_state = False
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'idle'))
        view = self.runtime.current()
        self.assertEqual((view.cleanup_status, self.backend.rolled_back), ('confirmed', 1))
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.backend.relay.state, 'closed')

    def test_desktop_exit_is_reported_then_stop_cleans_up(self):
        self.start()
        self.backend.tree.alive = False
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'desktop_exited'))
        self.assertFalse(self.runtime.current().resumable)
        self.backend.running_state = False
        self.assertTrue(self.runtime.request_stop())
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == 'idle'))
        self.assertEqual(self.backend.rolled_back, 1)

    def test_closing_the_assistant_keeps_rules_and_next_start_recovers_them(self):
        self.start()
        self.runtime.abandon()
        time.sleep(0.1)
        self.assertEqual((self.backend.rolled_back, self.backend.relay.state), (0, 'closed'))
        self.assertTrue(self.journal.exists())
        self.backend.running_state = False
        recovered = self.make_runtime()
        self.assertEqual(recovered.current().phase, 'blocked')
        self.assertFalse(recovered.request_start(CFG, 'Claude_pzs8sxrjxfjjc!Claude', 'r2'))
        self.assertTrue(recovered.request_stop())
        self.assertTrue(wait_for(lambda: recovered.current().phase == 'idle'))
        self.assertEqual(self.backend.rolled_back, 1)
        self.assertFalse(self.journal.exists())


if __name__ == '__main__':
    unittest.main()
