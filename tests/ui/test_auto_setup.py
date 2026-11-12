import hashlib
import os
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
from src.core.release_trust import Baseline, ReleaseInspection, EXECUTABLE_SHA256
from ui.app import App
from ui.model import Config, load_config, save_config
from ui.onboarding import (AutoSetup, PortCandidates, choose_ports, collect_auto_setup, find_installer,
                           find_manager_executable, installer_roots, read_manager_defaults, INSTALLER_NAME)


def wait_for(root, predicate, seconds=3):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('等待超时')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PortChoiceTests(unittest.TestCase):
    proxies = [{'port': 24000, 'zone': 'claude_pc2'}, {'port': 24001, 'zone': 'claude_pc2'}, {'port': 24002, 'zone': 'other'}]

    def test_picks_the_port_of_the_expected_zone_and_skips_the_default_24000(self):
        self.assertEqual(choose_ports((22225, 22999, 24000, 24001, 24002), self.proxies, ' claude_pc2 ', 22999, 24000), (22999, 24001, ''))
        self.assertEqual(choose_ports((22999, 24002), self.proxies, 'other', 22999, 24000), (22999, 24002, ''))
        manager, proxy, note = choose_ports((22999, 24000, 24001), self.proxies, 'claude_pc2', 22999, None)
        self.assertIsNone(proxy)

    def test_only_24000_with_the_zone_is_still_used(self):
        self.assertEqual(choose_ports((22999, 24000), [{'port': 24000, 'zone': 'z'}], 'z', 22999, 24000), (22999, 24000, ''))

    def test_ambiguous_missing_or_unknown_zone_leaves_proxy_port_empty(self):
        two = [{'port': 24001, 'zone': 'z'}, {'port': 24005, 'zone': 'z'}]
        for observed, proxies, zone, expected in (((22999, 24001, 24005), two, 'z', '多个'),
                                                  ((22999, 24001), self.proxies, 'missing', '没有使用这个代理名称'),
                                                  ((22999, 24001), self.proxies, '', '独立预期区域')):
            with self.subTest(zone=zone):
                manager, proxy, note = choose_ports(observed, proxies, zone, 22999, 24000)
                self.assertEqual((manager, proxy), (22999, None))
                self.assertIn(expected, note)

    def test_ports_not_listening_by_the_manager_are_ignored(self):
        manager, proxy, note = choose_ports((22999,), self.proxies, 'claude_pc2', 22999, 24000)
        self.assertIsNone(proxy)
        manager, proxy, note = choose_ports((24001,), self.proxies, 'claude_pc2', 22999, 24000)
        self.assertEqual((manager, proxy), (None, None))
        self.assertIn('22999', note)
        manager, proxy, note = choose_ports((22999, 24001), self.proxies, 'claude_pc2', None, None)
        self.assertEqual((manager, proxy), (None, None))
        self.assertIn('认不出', note)


class ManagerDefaultsTests(unittest.TestCase):
    def test_reads_management_and_default_ports_from_the_installed_defaults_file(self):
        sample = ('const conf = {\n    port: 24000,\n    proxy_port: 44445,\n};\n'
                  'conf.manager_default = Object.assign({}, conf.server_default, {\n    www: 22999,\n    dropin_port: 22225,\n});\n')
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, 'resources', 'app', 'util', 'lpm_config_static.js')
            target.parent.mkdir(parents=True)
            target.write_text(sample, encoding='utf-8')
            self.assertEqual(read_manager_defaults(str(Path(folder, 'Proxy Manager.exe'))), (22999, 24000))
            target.write_text('nothing here', encoding='utf-8')
            self.assertEqual(read_manager_defaults(str(Path(folder, 'Proxy Manager.exe'))), (None, None))
        self.assertEqual(read_manager_defaults('C:\\missing\\Proxy Manager.exe'), (None, None))


class InstallerSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, data):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_finds_by_exact_size_and_fingerprint_and_hashes_nothing_else(self):
        right = b'R' * 64
        self.write('Downloads/other.exe', b'X' * 64)
        self.write('Downloads/small.exe', b'R' * 10)
        self.write('Downloads/note.txt', right)
        target = self.write('Documents/chat-app/received/2026-11/renamed-setup.exe', right)
        hashed = []
        def hash_file(path):
            hashed.append(Path(path).name)
            return sha(Path(path).read_bytes())
        found = find_installer((str(self.base / 'Downloads'), str(self.base / 'Documents')), sha(right), hash_file, size=64)
        self.assertEqual(Path(found), target)
        self.assertEqual(sorted(hashed), ['other.exe', 'renamed-setup.exe'])

    def test_shallow_places_are_searched_first_and_skipped_folders_are_not_entered(self):
        right = b'R' * 32
        self.write('Desktop/deep/a/b/c/d/setup.exe', right)
        shallow = self.write('Downloads/setup.exe', right)
        self.write('Desktop/node_modules/setup2.exe', right)
        found = find_installer((str(self.base / 'Desktop'), str(self.base / 'Downloads')), sha(right),
                               lambda path: sha(Path(path).read_bytes()), size=32)
        self.assertEqual(Path(found), shallow)
        self.assertEqual(find_installer((str(self.base / 'Desktop' / 'node_modules'),), sha(right), lambda p: sha(Path(p).read_bytes()), size=32), str(self.base / 'Desktop' / 'node_modules' / 'setup2.exe'))
        os.remove(self.base / 'Desktop' / 'deep' / 'a' / 'b' / 'c' / 'd' / 'setup.exe')
        os.remove(shallow)
        self.assertEqual(find_installer((str(self.base / 'Desktop'),), sha(right), lambda p: sha(Path(p).read_bytes()), size=32), '')

    def test_time_limit_stops_the_search(self):
        self.write('Downloads/setup.exe', b'R' * 8)
        ticks = iter([0, 1000])
        found = find_installer((str(self.base / 'Downloads'),), sha(b'R' * 8), lambda p: sha(Path(p).read_bytes()),
                               size=8, clock=lambda: next(ticks, 1000))
        self.assertEqual(found, '')

    def test_roots_are_the_user_folders_that_exist(self):
        (self.base / 'Downloads').mkdir()
        (self.base / 'Documents').mkdir()
        roots = installer_roots({'USERPROFILE': str(self.base)})
        self.assertEqual([Path(root).name for root in roots], ['Downloads', 'Documents'])


class ManagerFolderTests(unittest.TestCase):
    def test_single_running_manager_is_used(self):
        path, note = find_manager_executable(('C:\\A\\Proxy Manager.exe', 'c:\\a\\proxy manager.exe'), {})
        self.assertEqual((path, note), ('C:\\A\\Proxy Manager.exe', ''))

    def test_two_different_running_installs_are_not_guessed(self):
        path, note = find_manager_executable(('C:\\A\\Proxy Manager.exe', 'D:\\B\\Proxy Manager.exe'), {})
        self.assertEqual(path, '')
        self.assertIn('不止一个', note)

    def test_default_install_is_used_when_nothing_runs(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'Programs' / '@luminati-ioluminati-proxy' / 'Proxy Manager.exe'
            target.parent.mkdir(parents=True)
            target.write_bytes(b'x')
            self.assertEqual(find_manager_executable((), {'LOCALAPPDATA': folder}), (str(target), ''))
            path, note = find_manager_executable(('C:\\elsewhere\\other.exe',), {'LOCALAPPDATA': folder + 'missing'})
        self.assertEqual(path, '')
        self.assertIn('没找到代理管理器的安装文件夹', note)


class CollectTests(unittest.TestCase):
    exe = 'C:\\Users\\u\\AppData\\Local\\Programs\\@luminati-ioluminati-proxy\\Proxy Manager.exe'

    def collect(self, **overrides):
        options = dict(discover=lambda: PortCandidates('observed', (22999, 24000, 24001)),
                       running=lambda: (self.exe,),
                       fetch=lambda port: [{'port': 24000, 'zone': 'z'}, {'port': 24001, 'zone': 'z'}],
                       roots=lambda environ: ('C:\\Users\\u\\Downloads',),
                       find=lambda roots: 'C:\\Users\\u\\Downloads\\setup.exe',
                       digest=lambda path: EXECUTABLE_SHA256, defaults=lambda path: (22999, 24000),
                       probe=lambda ports: (), environ={})
        options.update(overrides)
        return collect_auto_setup('z', **options)

    def test_hidden_listen_table_falls_back_to_connecting(self):
        probed = []
        def probe(ports):
            probed.append(tuple(ports))
            return tuple(port for port in ports if port in (22999, 24000, 24001))
        result = self.collect(discover=lambda: PortCandidates(), probe=probe)
        self.assertTrue(result.complete, result.notes)
        self.assertEqual((result.manager_port, result.proxy_port), (22999, 24001))
        self.assertEqual(probed[0], (22999,))
        self.assertFalse(any('端口没在工作' in note for note in result.notes))

    def test_fallback_finds_nothing_keeps_the_restart_advice(self):
        result = self.collect(discover=lambda: PortCandidates(), probe=lambda ports: ())
        self.assertTrue(any('端口没在工作' in note for note in result.notes))

    def test_complete_lookup_has_no_notes(self):
        result = self.collect()
        self.assertTrue(result.complete)
        self.assertEqual((result.manager_port, result.proxy_port), (22999, 24001))
        self.assertEqual(result.notes, ())
        self.assertNotIn('setup.exe', repr(result))

    def test_plain_language_notes_for_each_environment_problem(self):
        cases = {
            'not_running': (dict(running=lambda: (), discover=lambda: PortCandidates()), '没检测到正在运行的代理管理器'),
            'not_listening': (dict(discover=lambda: PortCandidates(), probe=lambda ports: ()), '端口没在工作'),
            'unreadable': (dict(running=lambda: None, discover=lambda: PortCandidates()), '读不到代理管理器的运行状态'),
            'upgraded': (dict(digest=lambda path: 'b' * 64), '不是 1.679.135 版本'),
            'no_installer': (dict(find=lambda roots: ''), INSTALLER_NAME),
            'manager_api_down': (dict(fetch=lambda port: (_ for _ in ()).throw(OSError())), '没有使用这个代理名称'),
            'no_defaults_file': (dict(defaults=lambda path: (None, None)), '认不出代理管理器的管理端口'),
        }
        for name, (overrides, expected) in cases.items():
            with self.subTest(name=name):
                result = self.collect(**overrides)
                self.assertFalse(result.complete)
                self.assertTrue(any(expected in note for note in result.notes), result.notes)


class WizardAutoFillTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.path = Path(self.temp.name) / 'config.json'
        self.app = App(self.root, config_path=self.path)
        self.app.open_first_setup()
        self.wizard = self.app._first_setup_dialog
        self.app.fields['expected_zone'].set('z')

    def tearDown(self):
        self.root.update()
        self.root.destroy()
        self.temp.cleanup()

    def test_one_click_fills_ports_and_verified_baseline_without_saving(self):
        executable = 'C:\\Trusted\\Proxy Manager.exe'
        self.wizard.collect = lambda zone: AutoSetup('C:\\Users\\u\\Downloads\\setup.exe', executable, 22999, 24001)
        passed = ReleaseInspection('pass', '', release_source='historical_release_record', package_match='pass',
                                   installed_match='pass', owner_match='pass', windows_signature='historical_untrusted',
                                   baseline=Baseline(executable, 'a' * 64))
        with patch('src.core.release_trust.inspect_release_baseline', return_value=passed) as inspect:
            self.wizard.auto_button.invoke()
            wait_for(self.root, lambda: self.app.fields['manager_sha256'].get() == 'a' * 64)
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(inspect.call_args.args, ('C:\\Users\\u\\Downloads\\setup.exe', executable, 22999, 24001))
        self.assertEqual(self.app.fields['port'].get(), '24001')
        self.assertEqual(self.app.fields['manager_port'].get(), '22999')
        self.assertEqual(self.app.fields['manager_executable'].get(), executable)
        self.assertIn('保存本机配置', self.wizard.auto_status.get())
        self.assertFalse(self.path.exists())
        self.assertFalse(self.app.saved)

    def test_failed_verification_is_not_accepted(self):
        executable = 'C:\\Trusted\\Proxy Manager.exe'
        self.wizard.collect = lambda zone: AutoSetup('C:\\setup.exe', executable, 22999, 24001)
        partial = ReleaseInspection('unknown', '', release_source='historical_release_record', package_match='pass',
                                    windows_signature='historical_untrusted')
        with patch('src.core.release_trust.inspect_release_baseline', return_value=partial):
            self.wizard.auto_button.invoke()
            wait_for(self.root, lambda: self.app._release_dialog is not None and not self.app._release_dialog.busy
                     and '无法确认' in self.app._release_dialog.summary.get())
        release = self.app._release_dialog
        self.assertIn('安装包对了', release.summary.get())
        self.assertEqual(self.app.fields['manager_sha256'].get(), '')
        self.assertEqual(str(release.accept_button['state']), 'disabled')

    def test_incomplete_lookup_shows_notes_and_opens_nothing(self):
        self.wizard.collect = lambda zone: AutoSetup(executable='C:\\T\\Proxy Manager.exe', manager_port=22999,
                                                     notes=('提示甲', '提示乙'))
        self.wizard.auto_button.invoke()
        wait_for(self.root, lambda: not self.wizard.auto_busy)
        self.assertIn('提示甲', self.wizard.auto_status.get())
        self.assertIn('提示乙', self.wizard.auto_status.get())
        self.assertEqual(self.app.fields['manager_port'].get(), '22999')
        self.assertEqual(self.app.fields['port'].get(), '')
        self.assertIsNone(self.app._release_dialog)

    def test_zone_changed_during_lookup_discards_the_result(self):
        started, release = threading.Event(), threading.Event()
        def collect(zone):
            started.set()
            release.wait(2)
            return AutoSetup('C:\\s.exe', 'C:\\T\\Proxy Manager.exe', 22999, 24001)
        self.wizard.collect = collect
        self.wizard.auto_button.invoke()
        self.assertTrue(started.wait(1))
        self.assertEqual(str(self.wizard.auto_button['state']), 'disabled')
        self.app.fields['expected_zone'].set('changed')
        release.set()
        wait_for(self.root, lambda: not self.wizard.auto_busy)
        self.assertIn('配置有变化', self.wizard.auto_status.get())
        self.assertEqual(self.app.fields['port'].get(), '')

    def test_mapping_choice_is_fixed_in_the_wizard(self):
        self.assertEqual(self.app.fields['mapping_mode'].get(), '明确不需要目标映射')
        mapping_entry = next(widget for widget, state in self.wizard._editors if state == 'disabled')
        self.assertEqual(str(mapping_entry['state']), 'disabled')
        self.assertEqual(tuple(mapping_entry['values']), ('明确不需要目标映射',))


class FixedMappingLoadTests(unittest.TestCase):
    def test_old_saved_mapping_choice_loads_as_not_required(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            save_config(path, Config(port=24001, manager_port=22999, expected_ip='203.0.113.42',
                                     ip_url='https://ip.example/check', mapping_mode='required',
                                     expected_zone='z', mapping_targets='192.0.2.6 claude.ai'))
            self.assertEqual(load_config(path).mapping_mode, 'required')
            root = tk.Tk()
            try:
                app = App(root, config_path=path)
                self.assertEqual(app.config.mapping_mode, 'not_required')
                self.assertEqual(app.config.mapping_targets, '')
                self.assertEqual(app.fields['mapping_mode'].get(), '明确不需要目标映射')
                self.assertTrue(app.saved)
            finally:
                root.destroy()


if __name__ == '__main__':
    unittest.main()
