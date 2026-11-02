import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

root_path = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root_path))
sys.path.insert(0, str(root_path / 'src'))
from src.core.release_trust import Baseline, ReleaseInspection
from src.core import release_trust as trust
from ui.app import App
from ui.release_setup import ReleaseDialog

INSTALLER = 'C:/Selected/setup.exe'
DIRECTORY = 'C:/Selected/Manager'
EXECUTABLE = 'C:\\Selected\\Manager\\Proxy Manager.exe'
HASH = 'a' * 64


def wait_for(root, predicate):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('基准核验未完成')


def accepted_result():
    return ReleaseInspection('pass', 'SECRET raw output', release_source='historical_release_record', package_match='pass', installed_match='pass', owner_match='pass', windows_signature='historical_untrusted', baseline=Baseline(EXECUTABLE, HASH))


class ReleaseSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.path = Path(self.temp.name) / 'settings.json'
        self.app = App(self.root, config_path=self.path)
        self.app.fields['manager_port'].set('23456')
        self.app.fields['port'].set('12345')
        self.calls = []
        def inspector(*args, **kwargs):
            self.calls.append((threading.get_ident(), args, kwargs))
            return accepted_result()
        self.dialog = ReleaseDialog(self.app, inspector=inspector)
        with patch('ui.release_setup.filedialog.askopenfilename', return_value=INSTALLER), patch('ui.release_setup.filedialog.askdirectory', return_value=DIRECTORY):
            self.dialog.choose_installer()
            self.dialog.choose_directory()

    def tearDown(self):
        self.root.update()
        self.root.destroy()
        self.temp.cleanup()

    def test_only_explicit_accept_after_recheck_changes_form_not_disk(self):
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(len(self.calls), 1)
        self.assertNotEqual(self.calls[0][0], threading.get_ident())
        self.assertEqual(self.calls[0][1], (INSTALLER, EXECUTABLE, 23456, 12345))
        self.assertIs(self.calls[0][2]['selected'], True)
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())
        self.assertIn('历史', self.dialog.signature_status.get())
        self.assertIn('未受信任', self.dialog.signature_status.get())
        self.assertNotIn('SECRET', self.dialog.summary.get())
        self.dialog.accept()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.app.fields['manager_executable'].get(), EXECUTABLE)
        self.assertEqual(self.app.fields['manager_sha256'].get(), HASH)
        self.assertFalse(self.path.exists())

    def test_changed_port_or_selection_rejects_old_candidate(self):
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.app.fields['port'].set('54321')
        self.dialog.accept()
        self.root.update()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())

    def test_changed_evidence_during_accept_is_not_applied(self):
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.dialog.inspector = lambda *args, **kwargs: ReleaseInspection('unknown', 'SECRET')
        self.dialog.accept()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())
        self.assertNotIn('SECRET', self.dialog.summary.get())

    def test_unknown_partial_evidence_is_not_accepted(self):
        self.dialog.inspector = lambda *args, **kwargs: ReleaseInspection('unknown', 'SECRET', release_source='historical_release_record', package_match='pass', windows_signature='historical_untrusted')
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(str(self.dialog.accept_button['state']), 'disabled')
        self.assertIn('一致', self.dialog.package_status.get())
        self.assertIn('未确认', self.dialog.installed_status.get())
        self.assertIn('历史', self.dialog.signature_status.get())

    def test_candidate_expiry_rejects_acceptance(self):
        now = [100.0]
        self.dialog.clock = lambda: now[0]
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        now[0] += 61
        self.dialog.accept()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())

    def test_mismatched_baseline_program_cannot_be_accepted(self):
        bad = ReleaseInspection('pass', 'ignored', release_source='historical_release_record', package_match='pass', installed_match='pass', owner_match='pass', windows_signature='historical_untrusted', baseline=Baseline('C:/Other/Proxy Manager.exe', HASH))
        self.dialog.inspector = lambda *args, **kwargs: bad
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(str(self.dialog.accept_button['state']), 'disabled')
        self.assertEqual(self.app.fields['manager_executable'].get(), '')

    def test_form_change_after_accept_restores_original_candidate(self):
        self.app.fields['manager_executable'].set('C:/Old/Proxy Manager.exe')
        self.app.fields['manager_sha256'].set('b' * 64)
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.dialog.accept()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.app.fields['port'].set('54321')
        self.assertEqual(self.app.fields['manager_executable'].get(), 'C:/Old/Proxy Manager.exe')
        self.assertEqual(self.app.fields['manager_sha256'].get(), 'b' * 64)
        self.assertFalse(self.path.exists())

    def test_new_file_selection_revokes_unsaved_candidate(self):
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.dialog.accept()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(self.app.fields['manager_sha256'].get(), HASH)
        with patch('ui.release_setup.filedialog.askdirectory', return_value='C:/Different'):
            self.dialog.choose_directory()
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertFalse(self.path.exists())

    def test_result_from_worker_is_discarded_if_config_changed_while_running(self):
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            release.wait(2)
            return accepted_result()
        self.dialog.inspector = delayed
        try:
            self.dialog.inspect()
            self.assertTrue(entered.wait(1))
            self.app.fields['manager_port'].set('22222')
            release.set()
            wait_for(self.root, lambda: not self.dialog.busy)
            self.assertEqual(str(self.dialog.accept_button['state']), 'disabled')
            self.assertEqual(self.app.fields['manager_sha256'].get(), '')
            self.assertFalse(self.path.exists())
        finally:
            release.set()

    def test_closing_window_during_check_does_not_apply_late_result(self):
        entered, release = threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            entered.set()
            release.wait(2)
            return accepted_result()
        self.dialog.inspector = delayed
        try:
            self.dialog.inspect()
            self.assertTrue(entered.wait(1))
            self.dialog.window.destroy()
            release.set()
            time.sleep(.05)
            self.root.update()
            self.assertEqual(self.app.fields['manager_sha256'].get(), '')
            self.assertFalse(self.path.exists())
        finally:
            release.set()

    def test_actual_core_inspection_with_simulated_file_and_process_checks(self):
        self.dialog.inspector = None
        with patch.object(trust, '_local_file_is_safe', return_value=True), patch.object(trust, '_file_sha256', return_value=trust.INSTALLER_SHA256), patch.object(trust, '_verify_installed_release', return_value=True), patch.object(trust, '_proxy_owner_snapshot', return_value=('synthetic-owner',)):
            self.dialog.inspect()
            wait_for(self.root, lambda: not self.dialog.busy)
            self.assertEqual(str(self.dialog.accept_button['state']), 'normal')
            self.assertIn('历史', self.dialog.signature_status.get())
            self.assertIn('未受信任', self.dialog.signature_status.get())
            self.dialog.accept()
            wait_for(self.root, lambda: not self.dialog.busy)
        self.assertEqual(self.app.fields['manager_sha256'].get(), trust.EXECUTABLE_SHA256)
        self.assertFalse(self.path.exists())

    def test_program_and_fingerprint_fields_are_readonly(self):
        self.assertEqual(str(self.app.entries[2]['state']), 'readonly')
        self.assertEqual(str(self.app.entries[3]['state']), 'readonly')
        self.root.update()
        self.assertTrue(self.dialog.accept_button.winfo_ismapped())
        self.assertLessEqual(self.dialog.accept_button.winfo_rooty() + self.dialog.accept_button.winfo_height(), self.dialog.window.winfo_rooty() + self.dialog.window.winfo_height())

    def _prepare_saved_baseline(self):
        self.app.fields['expected_ip'].set('203.0.113.42')
        self.app.fields['ip_url'].set('https://ip.example/check')
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
        self.dialog.inspect()
        wait_for(self.root, lambda: not self.dialog.busy)
        self.dialog.accept()
        wait_for(self.root, lambda: not self.dialog.busy)

    def test_explicit_save_rechecks_and_then_persists_candidate(self):
        self._prepare_saved_baseline()
        old = self.path.read_bytes()
        with patch('ui.app.messagebox.showinfo'):
            self.assertTrue(self.app.save_settings())
            wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(len(self.calls), 3)
        self.assertNotEqual(self.path.read_bytes(), old)
        from ui.model import load_config
        saved = load_config(self.path)
        self.assertEqual(saved.manager_sha256, HASH)

    def test_save_recheck_failure_preserves_existing_configuration(self):
        state = {'calls': 0}
        def inspector(*args, **kwargs):
            state['calls'] += 1
            return accepted_result() if state['calls'] <= 2 else ReleaseInspection('unknown', 'SECRET')
        self.dialog.inspector = inspector
        self._prepare_saved_baseline()
        old = self.path.read_bytes()
        with patch('ui.app.messagebox.showerror') as error:
            self.assertTrue(self.app.save_settings())
            wait_for(self.root, lambda: not self.app.busy)
        self.assertEqual(self.path.read_bytes(), old)
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertNotIn('SECRET', str(error.call_args))

    def test_edit_during_save_recheck_discards_result_and_keeps_existing_file(self):
        entered, release = threading.Event(), threading.Event()
        count = [0]
        def inspector(*args, **kwargs):
            count[0] += 1
            if count[0] == 3:
                entered.set()
                release.wait(2)
            return accepted_result()
        self.dialog.inspector = inspector
        self._prepare_saved_baseline()
        old = self.path.read_bytes()
        try:
            self.assertTrue(self.app.save_settings())
            self.assertTrue(entered.wait(1))
            self.app.fields['port'].set('54321')
            release.set()
            wait_for(self.root, lambda: not self.app.busy)
            self.assertEqual(self.path.read_bytes(), old)
            self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        finally:
            release.set()


if __name__ == '__main__':
    unittest.main()
