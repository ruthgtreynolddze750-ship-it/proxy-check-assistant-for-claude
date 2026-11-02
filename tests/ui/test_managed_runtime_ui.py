import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.app import App
from ui.model import Config
from src.browser.inspection import BrowserSelection
from src.protection.managed_session import ManagedSessionRuntime, RuntimeView
from src.protection.session_relay import RelaySnapshot
from src.core import monitoring as core_monitor
from src.core.backend import Check, Detection
from ui.adapters import to_core_config
from ui.monitor_binding import _config_key


class CachedRuntime:
    """Offline command/cache contract, never starts a browser or a sampler."""
    def __init__(self):
        self.view = RuntimeView()
        self.starts, self.stops, self.resumes = [], [], []

    def current(self):
        return self.view

    def request_start(self, config, selection, *, config_fingerprint, request_id):
        self.starts.append((config, selection, config_fingerprint, request_id))
        self.view = replace(self.view, request_id=request_id, phase='preparing', cleanup_status='pending')

    def request_stop(self, binding_key=None, request_id=''):
        self.stops.append((binding_key, request_id))
        self.view = replace(self.view, phase='stopping', cleanup_status='pending')

    def request_resume(self, binding_key, request_id):
        self.resumes.append((binding_key, request_id))
        self.view = replace(self.view, request_id=request_id, phase='preparing', cleanup_status='pending')


class ManagedSelectionTests(unittest.TestCase):
    def make_app(self):
        return App(self.root, config_path=self.base / 'unused-settings.json')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = self.make_app()
        self.app.config = Config(port=12001, manager_port=12002, expected_ip='192.0.2.41',
            ip_url='https://ip.example/check', mapping_mode='not_required',
            chrome_path=str(self.base / 'original/chrome.exe'),
            user_data_dir=str(self.base / 'original-data'), chrome_profile='Profile 3')
        self.app.saved = True
        self.original = replace(self.app.config)
        self.target = BrowserSelection('https://claude.ai/', str(self.base / 'owned/chrome.exe'),
                                       str(self.base / 'new-data'), 'Default')

    def tearDown(self):
        if not self.app._managed_closed:
            self.root.destroy()
        self.assertFalse(self.app.config_path.exists())
        self.temp.cleanup()

    def test_selection_is_in_memory_and_does_not_promote_identity(self):
        self.assertTrue(self.app.select_monitor_target(self.target))
        self.assertEqual(self.app.config, self.original)
        self.assertEqual(self.app._monitor_config.chrome_path, self.target.chrome_executable)
        self.assertEqual(self.app._monitor_config.chrome_profile, 'Default')
        self.assertFalse(self.app._monitor_browser_bound())
        self.assertIsNone(self.app._monitor_session)

    def test_saved_original_program_or_data_directory_cannot_be_selected(self):
        for target in (replace(self.target, chrome_executable=self.original.chrome_path),
                       replace(self.target, user_data_dir=self.original.user_data_dir),
                       replace(self.target, profile_directory='../Profile 3')):
            with self.subTest(target=target):
                self.assertFalse(self.app.select_monitor_target(target))
                self.assertIsNone(self.app._monitor_config)
                self.assertEqual(self.app.config, self.original)

    def test_cancelling_native_picker_preserves_original_selection(self):
        with patch('ui.app.filedialog.askopenfilename', return_value=''):
            self.app.choose_monitor_target()
        self.assertIsNone(self.app._monitor_config)
        self.assertEqual(self.app.config, self.original)


class ManagedLifecycleTests(ManagedSelectionTests):
    def make_app(self):
        self.runtime = CachedRuntime()
        self.tick = 100.0
        return App(self.root, config_path=self.base / 'unused-settings.json', monitor_runtime=self.runtime,
                   clock=lambda: self.tick)

    def running(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        selected = self.app._monitor_config
        config = to_core_config(selected)
        binding = core_monitor.BrowserBinding(selected.chrome_path, selected.user_data_dir, selected.chrome_profile,
                                              'offline-generation', 101, 1000, ((102, 1001),))
        key = (_config_key(selected), 101, 1000, 'offline-generation')
        self.owner = (config.manager_port, config.proxy_port, 501, '900', r'C:\pm.exe', 'a'*64)
        self.exits, self.guards = [], []
        self.session = core_monitor.LayeredMonitorSession(config, browser_binding=binding, binding_key=key,
            clock=lambda: self.tick, exit_validator=lambda e: any(e is x for x in self.exits),
            guard_validator=lambda e: any(e is x for x in self.guards))
        self.session.start()
        ok = Check('pass', 'offline fixture')
        detection = Detection(ok, ok, ok, ok, Check('unknown', '未验'), mapping=ok, target_trace=ok,
                              _owner_evidence=self.owner)
        self.assertTrue(self.session.accept_manager_sample(detection, started_at=99, completed_at=100))
        sample = core_monitor.BrowserBindingEvidence(binding, 'offline-exit-1', 100, 'pass', 'pass', 'pass',
            config.proxy_port, self.owner, selected.expected_ip, source='runtime', expires_at=130,
            request_profile_status='pass', request_profile_directory=selected.chrome_profile,
            request_profile_source='selected_profile_context')
        self.exits.append(sample)
        self.assertTrue(self.session.accept_exit_sample(sample))
        self.refresh_guard(1)
        self.runtime.view = replace(self.runtime.view, phase='running', session=self.session,
                                    binding_key=key, **self.session.production_evidence)
        return self.session

    def refresh_guard(self, sequence):
        policy = SimpleNamespace(expires_at=self.tick + 5, revoked=threading.Event())
        guard = core_monitor.LocalGuardEvidence(self.session.relay_binding, self.owner, sequence,
                                                self.tick, self.tick, self.tick + 2, policy)
        self.guards.append(guard)
        self.assertIsNotNone(self.session.issue_forward_lease(guard))

    def test_start_requests_preparation_once_without_promoting_identity(self):
        self.assertTrue(self.app.select_monitor_target(self.target))
        self.assertEqual(str(self.app.start_monitor_button['state']), 'normal')
        self.app.start_monitor()
        self.app.start_monitor()
        self.app._poll_monitor()
        self.assertEqual(len(self.runtime.starts), 1)
        self.assertEqual(self.app._managed_phase, 'preparing')
        self.assertFalse(self.app._monitor_browser_bound())
        self.assertIsNone(self.app._monitor_session)
        self.assertIn('身份和代理尚未确认', self.app.monitor_summary.get())
        self.assertEqual(self.app.config, self.original)

    def test_managed_controls_and_report_fit_minimum_window(self):
        self.root.deiconify()
        self.root.geometry('760x700')
        self.root.update()
        self.assertGreater(self.app.report.winfo_height(), 60)
        for button in (self.app.start_monitor_button, self.app.stop_monitor_button,
                       self.app.resume_monitor_button, self.app.monitor_target_button):
            self.assertTrue(button.winfo_ismapped())
            self.assertGreater(button.winfo_width(), 1)
            self.assertLessEqual(button.winfo_rootx() + button.winfo_width(),
                                 self.root.winfo_rootx() + self.root.winfo_width())

    def test_stop_ignores_late_running_and_waits_for_cleanup(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.app.stop_monitor()
        self.app.stop_monitor()
        self.runtime.view = replace(self.runtime.view, phase='running')
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'stopping')
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(len(self.runtime.stops), 1)
        self.assertEqual(str(self.app.start_monitor_button['state']), 'disabled')
        self.runtime.view = replace(self.runtime.view, phase='idle', cleanup_status='confirmed')
        self.app._poll_monitor()
        self.app.refresh()
        self.assertEqual(str(self.app.start_monitor_button['state']), 'normal')

    def test_older_request_completion_cannot_replace_new_preparation(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        old_view = self.runtime.view
        self.app.stop_monitor()
        self.runtime.view = replace(old_view, phase='idle', cleanup_status='confirmed')
        self.app._poll_monitor()
        self.app.start_monitor()
        self.runtime.view = replace(old_view, phase='running')
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'preparing')
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(len(self.runtime.starts), 2)

    def test_close_keeps_window_until_matching_cleanup_is_confirmed(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.app.request_close()
        self.assertTrue(self.root.winfo_exists())
        self.runtime.view = replace(self.runtime.view, phase='idle', cleanup_status='confirmed')
        self.app._poll_monitor()
        self.assertTrue(self.app._managed_closed)

    def test_unconfirmed_cleanup_blocks_restart_resume_and_target_change(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.runtime.view = replace(self.runtime.view, phase='blocked', cleanup_status='unknown',
                                    reason_code='cleanup_unconfirmed')
        self.app._poll_monitor()
        self.app.start_monitor()
        self.app.resume_monitor()
        self.assertFalse(self.app.select_monitor_target(self.target))
        self.assertEqual(len(self.runtime.starts), 1)
        self.assertEqual(len(self.runtime.resumes), 0)
        self.assertIn('清理未确认', self.app.monitor_summary.get())

    def test_ui_observes_exact_runtime_session_without_start_or_resample(self):
        session = self.running()
        with patch.object(session, 'start', wraps=session.start) as start, patch.object(session, 'resume', wraps=session.resume) as resume:
            self.app._poll_monitor()
            self.app._poll_monitor()
            self.assertIs(self.app._monitor_session, session)
            self.assertTrue(self.app._monitor_browser_bound())
            self.assertEqual(start.call_count, 0)
            self.assertEqual(resume.call_count, 0)
        self.assertEqual(self.runtime.view.exit_sequence, 1)
        self.assertIn('待真实验收', self.app.monitor_summary.get())
        self.assertNotIn(self.owner[-1], self.app._render_report())
        self.assertNotIn(self.app.config.expected_ip, self.app._render_report())

    def test_fast_guards_preserve_exit_time_count_and_original_deadline(self):
        self.running()
        self.app._poll_monitor()
        for i in range(101, 130):
            self.tick = float(i)
            self.refresh_guard(i)
            self.runtime.view = replace(self.runtime.view, **self.session.production_evidence)
            self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'running')
        self.assertEqual(self.app._managed_view.exit_sequence, 1)
        self.assertEqual(self.app._managed_view.exit_expires_at, 130)
        self.assertIn('出口请求开始：29.0 秒前', self.app._render_report())
        self.tick = 130.0
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'stopping')
        self.assertFalse(self.app._monitor_browser_bound())
        self.assertEqual(len(self.runtime.stops), 1)

    def test_same_exit_sequence_cannot_extend_its_deadline(self):
        self.running()
        self.app._poll_monitor()
        sample = replace(self.runtime.view.browser_evidence, expires_at=131)
        self.runtime.view = replace(self.runtime.view, exit_expires_at=131, browser_evidence=sample)
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'stopping')
        self.assertEqual(len(self.runtime.stops), 1)

    def test_manual_resume_uses_runtime_only_after_alarm_cleanup(self):
        self.running()
        self.app._poll_monitor()
        key = self.app._monitor_binding_key
        self.runtime.view = replace(self.runtime.view, phase='alarm', cleanup_status='pending')
        self.app._poll_monitor()
        self.app.resume_monitor()
        self.assertEqual(self.runtime.resumes, [])
        self.runtime.view = replace(self.runtime.view, cleanup_status='confirmed')
        self.app._poll_monitor()
        self.app.resume_monitor()
        self.assertEqual(len(self.runtime.resumes), 1)
        self.assertEqual(self.runtime.resumes[0][0], key)
        self.assertEqual(self.app._managed_phase, 'preparing')

    def test_config_edit_cancels_pending_target_without_saving_or_reopening(self):
        self.app.select_monitor_target(self.target)
        self.app.start_monitor()
        self.app.fields['port'].set('12003')
        self.assertIsNone(self.app._monitor_config)
        self.assertEqual(len(self.runtime.stops), 1)
        self.runtime.view = replace(self.runtime.view, phase='running')
        self.app._poll_monitor()
        self.assertEqual(self.app._managed_phase, 'stopping')
        self.assertIsNone(self.app._monitor_session)
        self.assertEqual(self.app.config, self.original)

    def test_malformed_exit_time_fails_closed_and_report_remains_readable(self):
        self.running()
        self.runtime.view = replace(self.runtime.view,
            browser_evidence=replace(self.runtime.view.browser_evidence, sampled_at=None))
        self.app._poll_monitor()
        self.app.refresh()
        self.assertEqual(self.app._managed_phase, 'stopping')
        self.assertIn('系统级保护：待真实验收', self.app._render_report())
        self.assertEqual(len(self.runtime.stops), 1)


class OfflineRuntimeBackend:
    """No sockets, processes, files or native policy; real runtime owns its threads."""
    def __init__(self):
        self.revoked = False
        self.cleanup_entered = threading.Event()
        self.cleanup_release = threading.Event()
        self.cleanup_release.set()
        self.snapshot_entered = threading.Event()
        self.snapshot_release = threading.Event()
        self.snapshot_release.set()
        self.exits, self.guards = [], []
        self.sequence = 0
        self.initializations = 0
        self.opened_urls = []

    def initialize(self, config, selection, fingerprint, budget, cancelled, journal):
        self.initializations += 1
        self.revoked = False
        self.config = config
        self.selection, self.cancelled = selection, cancelled
        self.binding = core_monitor.BrowserBinding(selection.chrome_executable, selection.user_data_dir,
            selection.profile_directory, 'runtime-generation-' + str(self.initializations), 101, 1000, ((102, 1001),))
        self.owner = (config.manager_port, config.proxy_port, 501, '900', r'C:\pm.exe', 'a'*64)
        key = (fingerprint, 101, 1000, self.binding.session_id)
        self.session = core_monitor.LayeredMonitorSession(config, browser_binding=self.binding, binding_key=key,
            exit_validator=lambda e: any(e is x for x in self.exits),
            guard_validator=lambda e: any(e is x for x in self.guards))
        self.session.start()
        started = time.monotonic()
        result = self.check_manager(config, started + budget.manager_budget_seconds)
        assert self.session.accept_manager_sample(result, started_at=started, completed_at=time.monotonic())
        assert self.session.accept_exit_sample(self.collect_exit('first-' + str(self.initializations)))
        self.lease = self.session.issue_forward_lease(self.read_guard())
        assert self.lease is not None
        return self.session

    def check_manager(self, config, deadline):
        time.sleep(.02)  # Distinct completion instants on Windows' monotonic clock.
        ok = Check('pass', 'offline fixture')
        return Detection(ok, ok, ok, ok, Check('unknown', '未验'), mapping=ok,
                         target_trace=ok, _owner_evidence=self.owner)

    def collect_exit(self, sample_id):
        started = time.monotonic()
        sample = core_monitor.BrowserBindingEvidence(self.binding, sample_id, started, 'pass', 'pass', 'pass',
            self.config.proxy_port, self.owner, self.config.expected_ip, source='runtime', expires_at=started+30,
            request_profile_status='pass', request_profile_directory=self.binding.profile_directory,
            request_profile_source='selected_profile_context')
        self.exits.append(sample)
        return sample

    def open_selected_url(self, url):
        if (self.cancelled.is_set() or self.revoked or url != self.selection.url
                or self.opened_urls or not self.session.accepts_relay_lease(self.lease)):
            raise ValueError('offline navigation intent is not current or uniquely selected')
        self.opened_urls.append(url)  # Records intent only; no browser or network.
        return True

    def read_guard(self):
        started = time.monotonic()
        self.sequence += 1
        proof = core_monitor.LocalGuardEvidence(self.binding, self.owner, self.sequence, started, started,
            started+2, SimpleNamespace(expires_at=started+5, revoked=threading.Event()))
        self.guards.append(proof)
        return proof

    def renew(self, lease, guard):
        self.lease = lease
        return not self.revoked

    def snapshot(self):
        self.snapshot_entered.set()
        self.snapshot_release.wait(2)
        return RelaySnapshot('closed' if self.revoked else 'listening',
            'lease_revoked' if self.revoked else 'lease_active', 0, 'runtime_unverified')

    def revoke(self):
        self.revoked = True

    def cleanup(self, *, quiescent):
        self.cleanup_entered.set()
        return self.cleanup_release.wait(2) and quiescent


class ProductionRuntimeAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.backend = OfflineRuntimeBackend()
        self.runtime = ManagedSessionRuntime(journal_path=self.base/'recovery.json', backend_factory=lambda: self.backend)
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = App(self.root, monitor_runtime=self.runtime, config_path=self.base/'settings.json')
        self.app.config = Config(port=12001, manager_port=12002, expected_ip='192.0.2.41',
            ip_url='https://ip.example/check', mapping_mode='not_required',
            chrome_path=str(self.base/'original/chrome.exe'), user_data_dir=str(self.base/'original-data'),
            chrome_profile='Profile 3')
        self.app.saved = True
        self.target = BrowserSelection('https://claude.ai/', str(self.base/'owned/chrome.exe'),
                                       str(self.base/'new-data'), 'Default')
        self.assertTrue(self.app.select_monitor_target(self.target))

    def tearDown(self):
        self.backend.cleanup_release.set()
        self.backend.snapshot_release.set()
        self.runtime.request_stop()
        if self.runtime._thread is not None:
            self.runtime._thread.join(3)
        if not self.app._managed_closed:
            self.root.destroy()
        self.assertFalse((self.base/'settings.json').exists())
        self.assertFalse((self.base/'recovery.json').exists())
        self.temp.cleanup()

    def wait_for(self, predicate):
        deadline = time.monotonic()+2
        while not predicate() and time.monotonic()<deadline:
            if not self.app._managed_closed:
                self.root.update()
            time.sleep(.005)
        self.assertTrue(predicate())

    def test_actual_runtime_binds_once_and_close_waits_for_actual_cleanup(self):
        self.app.start_monitor()
        self.app.start_monitor()
        self.wait_for(lambda: self.app._monitor_session is not None)
        self.assertIs(self.app._monitor_session, self.runtime.current().session)
        self.assertIs(self.app._monitor_session, self.backend.session)
        self.assertEqual(self.backend.initializations, 1)
        self.assertTrue(self.app._monitor_browser_bound())
        self.assertNotIn('核验未通过', self.app.monitor_summary.get())
        self.wait_for(lambda: len(self.backend.opened_urls) == 1)
        self.assertEqual(self.backend.opened_urls, [self.target.url])
        self.backend.cleanup_release.clear()
        self.app.request_close()
        self.wait_for(self.backend.cleanup_entered.is_set)
        self.assertFalse(self.app._managed_closed)
        self.assertEqual(self.runtime.current().cleanup_status, 'pending')
        self.backend.cleanup_release.set()
        self.wait_for(lambda: self.app._managed_closed)
        self.assertEqual(self.runtime.current().cleanup_status, 'confirmed')

    def test_running_view_is_published_with_session_and_evidence_atomically(self):
        self.backend.snapshot_release.clear()
        self.app.start_monitor()
        self.assertTrue(self.backend.snapshot_entered.wait(1))
        view = self.runtime.current()
        if view.phase == 'running':
            self.assertIsNotNone(view.session, 'running was published before its session')
            self.assertIsNotNone(view.browser_evidence, 'running was published before its exit evidence')
        self.app._poll_monitor()
        self.assertFalse(self.app._managed_stop_requested, 'incomplete startup view cancelled a healthy preparation')
        self.backend.snapshot_release.set()
        self.wait_for(lambda: self.app._monitor_session is not None)
        self.wait_for(lambda: len(self.backend.opened_urls) == 1)
        self.assertEqual(self.backend.opened_urls, [self.target.url])

    def test_stop_during_first_publication_cannot_adopt_late_session(self):
        self.backend.snapshot_release.clear()
        self.app.start_monitor()
        self.assertTrue(self.backend.snapshot_entered.wait(1))
        self.app.stop_monitor()
        self.assertEqual(self.runtime.current().phase, 'stopping')
        self.assertIsNone(self.app._monitor_session)
        self.backend.snapshot_release.set()
        self.wait_for(lambda: self.runtime.current().cleanup_status == 'confirmed')
        self.app._poll_monitor()
        self.assertEqual(self.runtime.current().phase, 'idle')
        self.assertEqual(self.app._managed_phase, 'idle')
        self.assertIsNone(self.app._monitor_session)
        self.assertTrue(self.backend.revoked)


if __name__ == '__main__':
    unittest.main(verbosity=2)
