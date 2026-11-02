import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('build_entry', ROOT / 'packaging' / 'build.py')
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        for name in build.APP_FILES:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('safe synthetic source', encoding='utf-8')
        self.stage = self.root / 'stage'

    def test_stage_only_whitelisted_files_and_preserves_existing_config(self):
        private = self.project / 'src' / 'ui' / 'settings.json'
        private.write_text('{"password":"PRIVATE_SECRET","expected_ip":"203.0.113.9"}', encoding='utf-8')
        config = self.root / 'user' / 'settings.json'
        config.parent.mkdir()
        config.write_text('do-not-overwrite', encoding='utf-8')
        copied = build.stage_sources(self.project, self.stage)
        self.assertEqual(set(copied), set(build.APP_FILES))
        self.assertFalse((self.stage / 'src' / 'ui' / 'settings.json').exists())
        self.assertEqual(config.read_text(encoding='utf-8'), 'do-not-overwrite')

    def test_missing_input_and_existing_stage_fail_before_copy(self):
        (self.project / build.APP_FILES[0]).unlink()
        with self.assertRaises(build.BuildError):
            build.stage_sources(self.project, self.stage)
        self.assertFalse(self.stage.exists())
        self.stage.mkdir()
        (self.stage / 'sentinel').write_text('keep', encoding='utf-8')
        with self.assertRaises(build.BuildError):
            build.stage_sources(self.project, self.stage)
        self.assertEqual((self.stage / 'sentinel').read_text(encoding='utf-8'), 'keep')

    def test_build_script_is_in_input_manifest(self):
        self.assertIn('packaging/build.py', build.APP_FILES)

    def test_staged_application_rejects_machine_specific_defaults_and_credentials(self):
        build.stage_sources(self.project, self.stage)
        path = self.stage / 'src/ui/app.py'
        for text in ('proxy_port = 24001', 'manager_port = 22999', 'chrome_profile = "Profile 3"',
                     r'path = "C:\Users\example\Chrome"',
                     'url = "http://synthetic:secret@example.invalid"',
                     'url = "https://synthetic@example.invalid"',
                     'expected_ip = "203.0.113.9"'):
            with self.subTest(kind=text.split('=')[0]):
                path.write_text(text, encoding='utf-8')
                with self.assertRaises(build.BuildError):
                    build.audit_application_defaults(self.stage)
        path.write_text('host = "127.0.0.1"\nmanager_port = 0\nproxy_port = 0\n', encoding='utf-8')
        build.audit_application_defaults(self.stage)

    def test_shortcut_parser_is_in_input_manifest(self):
        self.assertIn('src/browser/shortcut_selection.py', build.APP_FILES)
        self.assertIn('src/ui/shortcut_setup.py', build.APP_FILES)

    def test_guide_is_in_input_manifest(self):
        self.assertIn('src/ui/onboarding.py', build.APP_FILES)

    def test_user_facing_build_excludes_observation_prototype(self):
        stage = self.root / 'business-stage'
        build.stage_sources(ROOT, stage)
        self.assertFalse((stage / 'src/ui/candidate.py').exists())
        self.assertFalse((stage / 'src/browser/evidence_bridge.py').exists())
        self.assertFalse((stage / 'src/browser/trace_extension').exists())
        self.assertFalse((stage / 'src/protection/local_wfp_probe.py').exists())
        self.assertFalse((stage / 'src/protection/evidence').exists())
        self.assertFalse((stage / 'src/ui/monitor_window.py').exists())
        proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                              cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                              capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'], 'passed')

    def test_staged_protection_chain_imports_without_native_or_network_operations(self):
        stage = self.root / 'protection-stage'
        build.stage_sources(ROOT, stage)
        code = '''
import ctypes, importlib, json, socket, subprocess, sys
def forbidden(*args, **kwargs):
    raise AssertionError('protection import attempted an external operation')
class BlockedSocket(socket.socket):
    def __new__(cls, *args, **kwargs):
        return forbidden(*args, **kwargs)
socket.socket = BlockedSocket
subprocess.Popen = forbidden
ctypes.WinDLL = forbidden
sys.path.insert(0, sys.argv[1])
modules = ('src.browser.cdp_pipe', 'src.browser.request_probe',
           'src.protection.session_relay', 'src.protection.relay_identity',
           'src.protection.dedicated_wfp', 'src.protection.managed_session')
for name in modules:
    importlib.import_module(name)
print(json.dumps({'imports': len(modules), 'external_operations': False}))
'''
        proc = subprocess.run([sys.executable, '-I', '-X', 'utf8', '-B', '-c', code, str(stage)],
                              cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                              capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {'imports': 6, 'external_operations': False})
        self.assertTrue((stage / 'src/protection/__init__.py').is_file())
        self.assertFalse((self.root / 'ClaudeLaunchCenter').exists())

    def test_real_staged_launcher_exercises_business_entries_without_user_config(self):
        stage = self.root / 'real-stage'
        build.stage_sources(ROOT, stage)
        user = self.root / 'isolated-user'
        user.mkdir()
        proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                              cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(user)},
                              capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report['scope'], 'imports_tk_business_entry')
        self.assertEqual(report['observation_entry'], 'absent_web_launch_blocked')
        self.assertEqual(report['baseline_manifest'], 'hash_and_schema_validated')
        self.assertEqual(report['release_setup'], 'window_only_no_selection')
        self.assertEqual(report['shortcut_selection'], 'entry_available_fail_closed')
        self.assertEqual(report['default_shortcut'], 'matching_url_and_mismatch_fail_closed')
        self.assertEqual(report['guide'], 'auxiliary_copy_simulated_no_network')
        self.assertEqual(report['first_setup'], 'window_only_no_user_config')
        self.assertEqual(report['home_403'], 'simulated_owner_display_and_launch_blocked')
        self.assertEqual(report['dedicated_browser_scope'], 'unconfirmed_no_monitor_no_block')
        self.assertEqual(report['protection_modules'], 'imported_no_start')
        self.assertEqual(report['production_entry'], 'actual_main_runtime_connected_idle')
        self.assertFalse((user / 'ClaudeLaunchCenter').exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows shortcut self-check')
    def test_staged_selfcheck_with_long_temp_directory(self):
        stage = self.root / 'long-temp-stage'
        build.stage_sources(ROOT, stage)
        long_temp = self.root
        while len(str(long_temp)) < 208:
            long_temp = long_temp / ('t' * max(1, min(50, 208 - len(str(long_temp)) - 1)))
        long_temp.mkdir(parents=True)
        env = {**os.environ, 'LOCALAPPDATA': str(long_temp), 'TEMP': str(long_temp), 'TMP': str(long_temp)}
        proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                              cwd=self.root, env=env, capture_output=True, text=True, encoding='utf-8', timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report['default_shortcut'], 'matching_url_and_mismatch_fail_closed')
        self.assertEqual(report['observation_entry'], 'absent_web_launch_blocked')
        self.assertFalse((long_temp / 'ClaudeLaunchCenter').exists())

    def test_actual_entry_rejects_disconnection_and_swallowed_side_effects(self):
        stage = self.root / 'entry-stage'
        build.stage_sources(ROOT, stage)
        code = '''
import importlib.util, json, os, sys, threading, tkinter as tk
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from src.ui import app as module
spec = importlib.util.spec_from_file_location('entry_under_test', Path(sys.argv[1])/'packaging/launcher.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
mode = sys.argv[2]
original_main = module.main
def altered_main():
    if mode == 'disconnected':
        root = tk.Tk()
        module.App(root, backend=module.LiveBackend())
        root.mainloop()
        return
    try:
        if mode == 'network':
            sys.audit('socket.getaddrinfo', 'example.invalid', 443, 0, 0, 0)
        elif mode == 'native':
            sys.audit('ctypes.dlopen', 'fwpuclnt.dll')
        elif mode == 'process':
            sys.audit('subprocess.Popen', 'forbidden.exe', [], None, None)
        elif mode == 'thread':
            threading.Thread(target=lambda: None).start()
    except RuntimeError:
        pass  # Swallowing a blocked action must not turn the result into a pass.
    original_main()
if mode != 'normal':
    module.main = altered_main
other = tk.Tk()
other.withdraw()
before = (os.environ.get('LOCALAPPDATA'), sys.argv, sys.getprofile(), threading.Thread.start)
try:
    try:
        marker = launcher._check_production_entry()
        result = 'passed'
    except RuntimeError:
        marker, result = None, 'rejected'
    restored = before == (os.environ.get('LOCALAPPDATA'), sys.argv, sys.getprofile(), threading.Thread.start)
    print(json.dumps(dict(result=result, marker=marker, restored=restored, other_root_preserved=bool(other.winfo_exists()))))
finally:
    other.quit()
    other.destroy()
'''
        for mode in ('normal', 'disconnected', 'network', 'native', 'process', 'thread'):
            with self.subTest(mode=mode):
                proc = subprocess.run([sys.executable, '-I', '-X', 'utf8', '-B', '-c', code, str(stage), mode],
                    cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                    capture_output=True, text=True, encoding='utf-8', timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                report = json.loads(proc.stdout)
                self.assertEqual(report['result'], 'passed' if mode == 'normal' else 'rejected')
                self.assertEqual(report['marker'], 'actual_main_runtime_connected_idle' if mode == 'normal' else None)
                self.assertTrue(report['restored'])
                self.assertTrue(report['other_root_preserved'])
        self.assertFalse((self.root / 'ClaudeLaunchCenter').exists())

    def test_staged_missing_baseline_module_or_manifest_cannot_pass(self):
        original = build.APP_FILES
        self.addCleanup(setattr, build, 'APP_FILES', original)
        for omitted, expected_error in [('src/ui/release_setup.py', 'ModuleNotFoundError'),
                                        ('src/ui/onboarding.py', 'ModuleNotFoundError'),
                                        ('src/ui/shortcut_setup.py', 'ModuleNotFoundError'),
                                        ('src/ui/monitor_binding.py', 'ModuleNotFoundError'),
                                        ('src/core/monitoring.py', 'ModuleNotFoundError'),
                                        ('src/browser/session_binding.py', 'ModuleNotFoundError'),
                                        ('src/browser/cdp_pipe.py', 'ModuleNotFoundError'),
                                        ('src/browser/request_probe.py', 'ModuleNotFoundError'),
                                        ('src/protection/session_relay.py', 'ModuleNotFoundError'),
                                        ('src/protection/relay_identity.py', 'ModuleNotFoundError'),
                                        ('src/protection/dedicated_wfp.py', 'ModuleNotFoundError'),
                                        ('src/protection/managed_session.py', 'ModuleNotFoundError'),
                                        ('src/core/release_trust.py', 'ModuleNotFoundError'),
                                        ('src/core/release_v1_679_135_manifest.json', 'FileNotFoundError')]:
            with self.subTest(omitted=omitted):
                build.APP_FILES = tuple(x for x in original if x != omitted)
                stage = self.root / ('without-' + Path(omitted).stem)
                build.stage_sources(ROOT, stage)
                proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                                      cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                                      capture_output=True, text=True, encoding='utf-8', timeout=15)
                self.assertNotEqual(proc.returncode, 0)
                result = json.loads(proc.stdout)
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['failure'], expected_error)
        build.APP_FILES = original

    def test_missing_shortcut_parser_cannot_pass_staged_selfcheck(self):
        original = build.APP_FILES
        self.addCleanup(setattr, build, 'APP_FILES', original)
        build.APP_FILES = tuple(x for x in original if x != 'src/browser/shortcut_selection.py')
        stage = self.root / 'missing-shortcut-stage'
        build.stage_sources(ROOT, stage)
        proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                              cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                              capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report['failure'], 'ModuleNotFoundError')
        self.assertEqual(report['module'], 'src.browser.shortcut_selection')

    def test_frozen_selfcheck_rejects_missing_shortcut_check(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_default_profile_validation(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_guide_validation(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_first_setup_validation(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                 'guide': 'auxiliary_copy_simulated_no_network'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_home_403_validation(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                 'guide': 'auxiliary_copy_simulated_no_network', 'first_setup': 'window_only_no_user_config'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_dedicated_browser_scope(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry',
                 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                 'guide': 'auxiliary_copy_simulated_no_network', 'first_setup': 'window_only_no_user_config',
                 'home_403': 'simulated_owner_display_and_launch_blocked'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_protection_import_check(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry',
                 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                 'guide': 'auxiliary_copy_simulated_no_network', 'first_setup': 'window_only_no_user_config',
                 'home_403': 'simulated_owner_display_and_launch_blocked',
                 'dedicated_browser_scope': 'unconfirmed_no_monitor_no_block'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_missing_actual_production_entry(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry',
                 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated', 'release_setup': 'window_only_no_selection',
                 'shortcut_selection': 'entry_available_fail_closed',
                 'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                 'guide': 'auxiliary_copy_simulated_no_network', 'first_setup': 'window_only_no_user_config',
                 'home_403': 'simulated_owner_display_and_launch_blocked',
                 'dedicated_browser_scope': 'unconfirmed_no_monitor_no_block',
                 'protection_modules': 'imported_no_start'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_staged_corrupt_baseline_manifest_cannot_pass(self):
        stage = self.root / 'corrupt-baseline-stage'
        build.stage_sources(ROOT, stage)
        (stage / 'src/core/release_v1_679_135_manifest.json').write_text('{}', encoding='utf-8')
        proc = subprocess.run([sys.executable, '-I', '-B', str(stage / 'packaging/launcher.py'), '--self-check'],
                              cwd=self.root, env={**os.environ, 'LOCALAPPDATA': str(self.root)},
                              capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)['status'], 'failed')

    def test_core_licenses_are_part_of_allowlisted_sources(self):
        for name in ('Python-PSF.txt', 'Tcl.txt', 'Tk.txt', 'PyInstaller.txt', 'Inno-Setup.txt', 'OpenSSL.txt', 'zlib.txt', 'XZ.txt', 'libmpdec.txt'):
            self.assertIn('packaging/licenses/' + name, build.APP_FILES)

    def test_whitelist_does_not_include_user_configuration_or_browser_profile(self):
        jsons = [x for x in build.APP_FILES if str(x).lower().endswith('.json')]
        self.assertEqual(set(jsons), {'src/core/release_v1_679_135_manifest.json'})
        self.assertTrue(all(not str(x).lower().endswith(('.db', '.log', '.pem')) for x in build.APP_FILES))
        self.assertTrue(all('userdata' not in str(x).lower() for x in build.APP_FILES))

    def test_preflight_reports_missing_inputs(self):
        original = build.PROJECT
        self.addCleanup(setattr, build, 'PROJECT', original)
        build.PROJECT = self.project
        self.assertTrue(build.check_sources())
        (self.project / build.APP_FILES[0]).unlink()
        self.assertFalse(build.check_sources())

    def test_build_environment_excludes_host_search_paths(self):
        supplied = {'PATH': 'C:/private/third-party;C:/other', 'PYTHONPATH': 'C:/private',
                    'PYTHONHOME': 'C:/private/python', 'SystemRoot': 'C:/Windows',
                    'TEMP': 'C:/scratch'}
        env = build.isolated_build_environment(supplied, Path('C:/tool/python.exe'),
                                               Path('C:/tool/site'), Path('C:/tool/inno/ISCC.exe'))
        self.assertNotIn('private', env['PATH'].lower())
        self.assertEqual(env['PYTHONPATH'], str(Path('C:/tool/site')))
        self.assertNotIn('PYTHONHOME', env)
        self.assertEqual(env['PYTHONNOUSERSITE'], '1')
        self.assertEqual(supplied['PYTHONHOME'], 'C:/private/python')

    def test_build_environment_disables_bytecode_for_child_processes(self):
        env = build.isolated_build_environment({**os.environ, 'PYTHONDONTWRITEBYTECODE': '0'},
                                               sys.executable, self.root, self.root / 'ISCC.exe')
        self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
        (self.root / 'bytecode_probe.py').write_text('value = 1\n', encoding='utf-8')
        child = 'import bytecode_probe, sys; print(sys.dont_write_bytecode)'
        parent = 'import subprocess, sys; subprocess.run([sys.executable, "-c", sys.argv[1]], check=True)'
        proc = subprocess.run([sys.executable, '-B', '-c', parent, child], cwd=self.root, env=env,
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), 'True')
        self.assertFalse((self.root / '__pycache__').exists())

    def test_strict_stage_audit_rejects_extra_missing_modified_and_empty_directories(self):
        build.stage_sources(self.project, self.stage)
        hashes = {name: build.hashlib.sha256((self.stage / name).read_bytes()).hexdigest()
                  for name in build.APP_FILES}
        build.audit_stage(self.stage, hashes)
        extra = self.stage / 'extra'
        extra.mkdir()
        with self.assertRaises(build.BuildError):
            build.audit_stage(self.stage, hashes)
        extra.rmdir()
        extra_file = self.stage / 'extra.pyc'
        extra_file.write_bytes(b'cache')
        with self.assertRaises(build.BuildError):
            build.audit_stage(self.stage, hashes)
        extra_file.unlink()
        item = self.stage / build.APP_FILES[0]
        data = item.read_bytes()
        item.write_bytes(data + b'changed')
        with self.assertRaises(build.BuildError):
            build.audit_stage(self.stage, hashes)
        item.unlink()
        with self.assertRaises(build.BuildError):
            build.audit_stage(self.stage, hashes)

    def test_frozen_selfcheck_rejects_missing_business_checks_even_if_process_exits_zero(self):
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps({'status': 'passed', 'scope': 'imports_and_tk_only'}), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_omitted_baseline_even_if_candidate_passes(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_frozen_selfcheck_rejects_omitted_wizard(self):
        value = {'status': 'passed', 'scope': 'imports_tk_business_entry', 'observation_entry': 'absent_web_launch_blocked',
                 'baseline_manifest': 'hash_and_schema_validated'}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
        with mock.patch.object(build.subprocess, 'run', return_value=completed):
            with self.assertRaises(build.BuildError):
                build.verify_frozen(self.root / 'test.exe', self.root, os.environ)

    def test_invalid_version_is_rejected(self):
        for version in ['1.0', '1.0.0 /bad', '../1.0.0', '']:
            with self.subTest(version=version):
                with self.assertRaises(build.BuildError):
                    build.validate_version(version)
        self.assertEqual(build.validate_version('1.2.3'), '1.2.3')

    def test_blocked_build_emits_readable_utf8_and_creates_no_output(self):
        output = self.root / 'should-not-exist'
        proc = subprocess.run([sys.executable, str(ROOT / 'packaging' / 'build.py'), '--build',
                               '--version', 'not-a-version', '--output', str(output)],
                              capture_output=True)
        self.assertEqual(proc.returncode, 2)
        report = json.loads(proc.stdout.decode('utf-8'))
        self.assertEqual(report['status'], 'blocked')
        self.assertIn('版本', report['reason'])
        self.assertFalse(output.exists())

    def test_build_check_does_not_read_or_modify_user_config(self):
        user = self.root / 'user'
        user.mkdir()
        config = user / 'settings.json'
        config.write_text('unchanged', encoding='utf-8')
        proc = subprocess.run([sys.executable, str(ROOT / 'packaging' / 'build.py'), '--check'],
                              env={**os.environ, 'LOCALAPPDATA': str(user)}, text=True,
                              encoding='utf-8', capture_output=True)
        self.assertIn(proc.returncode, (0, 2))
        report = json.loads(proc.stdout)
        self.assertIn(report['status'], ('ready', 'blocked'))
        self.assertEqual(config.read_text(encoding='utf-8'), 'unchanged')
        self.assertNotIn('unchanged', proc.stdout)

class DistributionAuditTests(unittest.TestCase):
    def test_only_core_manifest_is_allowed_and_extension_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            core = root / '_internal' / 'src' / 'core'
            core.mkdir(parents=True)
            (core / 'release_v1_679_135_manifest.json').write_text('{}', encoding='utf-8')
            build.audit_distribution(root)
            extension = root / 'trace_extension'
            extension.mkdir()
            (extension / 'manifest.json').write_text('{}', encoding='utf-8')
            with self.assertRaises(build.BuildError):
                build.audit_distribution(root)

    def test_unexpected_config_and_browser_data_refuse_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'ClaudeLaunchCenter.exe').write_bytes(b'synthetic')
            build.audit_distribution(root)
            (root / 'settings.json').write_text('{"secret":"synthetic"}', encoding='utf-8')
            with self.assertRaises(build.BuildError):
                build.audit_distribution(root)

    def test_installer_portable_test_mode_has_no_registration_or_shortcuts(self):
        template = (ROOT / 'packaging' / 'app.iss').read_text(encoding='utf-8-sig')
        self.assertIn('Uninstallable=not PortableCheck', template)
        self.assertIn('{param:portable|0}', template)
        icons = template.split('[Icons]', 1)[1].split('[', 1)[0]
        self.assertEqual(icons.count('Check: not PortableCheck'), 2)

    def test_installer_template_does_not_delete_config_on_uninstall(self):
        template = (ROOT / 'packaging' / 'app.iss').read_text(encoding='utf-8-sig')
        self.assertIn('{localappdata}\\Programs\\ClaudeLaunchCenter', template)
        self.assertNotIn('[UninstallDelete]', template)
        self.assertNotIn('settings.json', template)

    def test_installer_has_no_automatic_close_restart_or_elevation(self):
        template = (ROOT / 'packaging/app.iss').read_text(encoding='utf-8-sig')
        setup = template.split('[Setup]', 1)[1].split('[Files]', 1)[0]
        directives = dict(line.split('=', 1) for line in setup.splitlines() if '=' in line)
        self.assertEqual(directives.get('CloseApplications'), 'no')
        self.assertEqual(directives.get('RestartApplications'), 'no')
        self.assertEqual(directives.get('PrivilegesRequired'), 'lowest')
        self.assertNotIn('[Run]', template)
        self.assertNotIn('[InstallDelete]', template)


if __name__ == '__main__':
    unittest.main()
