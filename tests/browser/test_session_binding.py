import importlib
import json
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


class SessionBindingTests(unittest.TestCase):
    def setUp(self):
        try:
            self.api = importlib.import_module('src.browser.session_binding')
        except ModuleNotFoundError:
            self.fail('缺少可采集真实专用 Chrome 会话的生产接口')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.exe = self.base / 'Application' / 'chrome.exe'
        self.exe.parent.mkdir()
        self.exe.write_bytes(b'fixture executable, never launched')
        self.data = self.base / 'User Data'
        self.data.mkdir()
        self.target = self.api.DedicatedTarget(str(self.exe), str(self.data))
        self.root = self.api.ProcessFact(100, 1000, 42, str(self.exe), '', str(self.data), '')
        self.network = self.api.ProcessFact(101, 1001, 100, str(self.exe), 'utility', '',
                                            'network.mojom.NetworkService')
        self.now = 20.0

    def snap(self, *rows, complete=True):
        return self.api.ProcessSnapshot(tuple(rows or (self.root, self.network)), complete)

    def session(self, snapshots, **kwargs):
        samples = iter(snapshots)
        return self.api.DedicatedSession(self.target, selected=True,
                                         sampler=lambda _: next(samples), clock=lambda: self.now, **kwargs)

    def test_stable_target_can_pass_identity_without_claiming_request_or_protection(self):
        result = self.session([self.snap(), self.snap()]).poll()
        self.assertEqual(result.identity_status, 'pass')
        self.assertEqual(result.root.pid, 100)
        self.assertEqual(result.root.created, 1000)
        self.assertEqual(result.network_processes[0].pid, 101)
        self.assertTrue(result.is_fresh(self.now))
        self.assertEqual(result.request_status, 'unknown')
        self.assertEqual(result.proxy_status, 'unknown')
        self.assertEqual(result.protection_status, 'not_enabled')
        self.assertFalse(result.may_launch)
        self.assertTrue(result.binding_id)

    def test_unselected_target_does_not_sample(self):
        def forbidden(_):
            self.fail('未确认选择时不能读取进程')
        result = self.api.DedicatedSession(self.target, sampler=forbidden).poll()
        self.assertEqual(result.reason_code, 'target_not_selected')

    def test_not_running_is_unknown(self):
        empty = self.api.ProcessSnapshot((), True)
        result = self.session([empty, empty]).poll()
        self.assertEqual(result.reason_code, 'browser_not_running')
        self.assertIsNone(result.root)

    def test_missing_or_wrong_data_directory_is_unknown(self):
        for data in ['', str(self.base), 'relative', str(self.data) + '\\..']:
            with self.subTest(data=data):
                snap = self.snap(replace(self.root, user_data_dir=data), self.network)
                result = self.session([snap, snap]).poll()
                self.assertEqual(result.identity_status, 'unknown')

    def test_other_root_using_same_executable_is_ambiguous(self):
        other = replace(self.root, pid=200, created=999, user_data_dir=str(self.base))
        snap = self.snap(self.root, self.network, other)
        self.assertEqual(self.session([snap, snap]).poll().reason_code, 'root_ambiguous')

    def test_missing_unrelated_or_older_network_child_never_passes(self):
        cases = [self.snap(self.root), self.snap(self.root, replace(self.network, parent_pid=999)),
                 self.snap(self.root, replace(self.network, created=999)),
                 self.snap(self.root, replace(self.network, executable=str(self.base / 'chrome.exe')))]
        for snap in cases:
            with self.subTest(snap=snap):
                self.assertEqual(self.session([snap, snap]).poll().identity_status, 'unknown')

    def test_partial_snapshot_fails_closed(self):
        result = self.session([self.snap(complete=False)]).poll()
        self.assertEqual(result.reason_code, 'process_snapshot_unavailable')

    def test_reused_pid_between_snapshots_fails(self):
        newer = self.snap(replace(self.root, created=1002), replace(self.network, created=1003))
        self.assertEqual(self.session([self.snap(), newer]).poll().reason_code, 'session_changed')

    def test_browser_or_network_restart_invalidates_and_requires_new_session(self):
        for changed in [self.snap(replace(self.root, created=1002), replace(self.network, created=1003)),
                        self.snap(self.root, replace(self.network, pid=102, created=1004))]:
            session = self.session([self.snap(), self.snap(), changed, changed, self.snap(), self.snap()])
            self.assertEqual(session.poll().identity_status, 'pass')
            self.assertEqual(session.poll().reason_code, 'session_changed')
            self.assertEqual(session.poll().reason_code, 'session_invalidated')

    def test_sampling_failure_after_success_does_not_return_old_identity(self):
        session = self.session([self.snap(), self.snap(), self.snap(complete=False)])
        self.assertEqual(session.poll().identity_status, 'pass')
        lost = session.poll()
        self.assertEqual(lost.identity_status, 'unknown')
        self.assertIsNone(lost.root)
        self.assertFalse(lost.binding_id)
        self.assertEqual(session.poll().reason_code, 'session_invalidated')

    def test_expired_or_backwards_clock_evidence_is_unusable(self):
        session = self.session([self.snap(), self.snap()], max_age_seconds=5)
        result = session.poll()
        for now in [19.0, 25.0, float('nan'), float('inf'), True]:
            self.assertFalse(result.is_fresh(now))
        self.now = 25.0
        self.assertEqual(session.poll().reason_code, 'evidence_expired')

    def test_executable_replacement_invalidates_binding(self):
        session = self.session([self.snap(), self.snap(), self.snap(), self.snap()])
        self.assertEqual(session.poll().identity_status, 'pass')
        self.exe.write_bytes(b'changed executable')
        self.assertEqual(session.poll().reason_code, 'target_changed')

    def test_close_is_idempotent_and_never_closes_browser(self):
        session = self.session([self.snap(), self.snap()])
        evidence = session.poll()
        session.close()
        session.close()
        self.assertFalse(evidence.is_fresh(self.now))
        self.assertEqual(session.poll().reason_code, 'session_closed')

    def test_close_does_not_wait_for_cim_and_inflight_result_cannot_rebind(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        results = []
        def sample(_):
            entered.set()
            release.wait(3)
            return self.snap()
        session = self.api.DedicatedSession(self.target, selected=True, sampler=sample, clock=lambda: self.now)
        worker = threading.Thread(target=lambda: results.append(session.poll()))
        closer = threading.Thread(target=lambda: (session.close(), closed.set()))
        worker.start()
        self.assertTrue(entered.wait(2))
        closer.start()
        try:
            did_close = closed.wait(.5)
        finally:
            release.set()
            worker.join(3)
            closer.join(3)
        self.assertTrue(did_close, '关闭会话不应阻塞等待 CIM')
        self.assertEqual(results[0].reason_code, 'session_closed')

    def test_failure_revokes_already_issued_evidence(self):
        session = self.session([self.snap(), self.snap(), self.snap(complete=False)])
        evidence = session.poll()
        session.poll()
        self.assertFalse(evidence.is_fresh(self.now))

    def test_clock_cannot_extend_cached_identity(self):
        session = self.session([self.snap(), self.snap(), self.snap(), self.snap()])
        evidence = session.poll()
        self.now = 19.0
        self.assertEqual(session.poll().reason_code, 'clock_unavailable')
        self.assertFalse(evidence.is_fresh(20.0))

    def test_session_source_distinguishes_injected_sample(self):
        result = self.session([self.snap(), self.snap()]).poll()
        self.assertEqual(result.source, 'injected')

    def test_ambiguous_switch_spelling_and_separator_cannot_prove_data_directory(self):
        for args in [['-user-data-dir=' + str(self.data)],
                     ['/user-data-dir=' + str(self.data)],
                     ['--USER-DATA-DIR=' + str(self.data)],
                     ['--user-data-dir', str(self.data)],
                     ['--', '--user-data-dir=' + str(self.data)]]:
            row = {'pid': 100, 'created': '1000', 'parent': 42, 'executable': str(self.exe),
                   'command': subprocess.list2cmdline([str(self.exe)] + args)}
            try:
                fact = self.api._process_fact(row, str(self.exe))
            except ValueError:
                continue
            snap = self.snap(fact, self.network)
            self.assertEqual(self.session([snap, snap]).poll().identity_status, 'unknown')

    def test_private_paths_and_raw_errors_are_not_in_results(self):
        result = self.session([self.snap(), self.snap()]).poll()
        for item in [self.target, self.root, self.snap(), result]:
            self.assertNotIn(str(self.base), repr(item))
        def failed(_):
            raise OSError('private-secret ' + str(self.base))
        result = self.api.DedicatedSession(self.target, selected=True, sampler=failed).poll()
        self.assertEqual(result.reason_code, 'process_snapshot_unavailable')
        self.assertNotIn('private-secret', repr(result))

    def test_capture_decodes_unicode_and_keeps_only_structural_switches(self):
        command = subprocess.list2cmdline([str(self.exe), '--user-data-dir=' + str(self.data),
                                           'https://example.test/?token=private-secret'])
        rows = {'complete': True, 'rows': [{'pid': 100, 'created': '1000', 'parent': 42,
                                          'executable': str(self.exe), 'command': command}]}
        completed = subprocess.CompletedProcess([], 0, json.dumps(rows, ensure_ascii=False).encode('utf-8'), b'')
        with patch.object(self.api.subprocess, 'run', return_value=completed) as run:
            result = self.api.capture_process_snapshot(self.target)
        self.assertTrue(result.complete)
        self.assertEqual(result.processes[0].user_data_dir, str(self.data))
        self.assertNotIn('private-secret', repr(result))
        self.assertEqual(run.call_args.kwargs['creationflags'], subprocess.CREATE_NO_WINDOW)
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_duplicate_structural_switches_and_untrusted_argv_image_fail(self):
        for argv in [[str(self.exe), '--user-data-dir=a', '--user-data-dir=b'],
                     [str(self.exe), '--type=', '--user-data-dir=' + str(self.data)],
                     [str(self.base / 'other.exe'), '--user-data-dir=' + str(self.data)]]:
            rows = {'complete': True, 'rows': [{'pid': 100, 'created': '1000', 'parent': 42,
                                              'executable': str(self.exe), 'command': subprocess.list2cmdline(argv)}]}
            completed = subprocess.CompletedProcess([], 0, json.dumps(rows).encode(), b'')
            with patch.object(self.api.subprocess, 'run', return_value=completed):
                result = self.api.capture_process_snapshot(self.target)
            self.assertFalse(result.complete)


if __name__ == '__main__':
    unittest.main()
