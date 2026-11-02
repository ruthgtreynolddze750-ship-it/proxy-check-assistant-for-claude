import contextlib
import base64
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from src.protection import preflight


class ProtectionPreflightTests(unittest.TestCase):
    def observed(self):
        return {
            'package_ids': ['Claude_pzs8sxrjxfjjc!Claude'],
            'processes': [
                {'pid': 120, 'started': '100', 'role': 'package_root_candidate', 'image_scope': 'package',
                 'tcp_to_proxy': 0, 'tcp_other': 0, 'path': 'PRIVATE_PATH', 'remote': '203.0.113.9'},
                {'pid': 121, 'started': '101', 'role': 'package_child', 'image_scope': 'package',
                 'tcp_to_proxy': 1, 'tcp_other': 0},
            ],
            'proxy': {'listener_count': 1, 'owner_pid': 220, 'owner_started': '90', 'owner_name': 'Proxy Manager'},
            'chrome_process_count': 4,
        }

    def test_observed_data_is_redacted_and_never_claims_protection(self):
        plan = preflight.make_plan(self.observed(), 24001, source='fixture')
        self.assertEqual(plan['desktop']['registered_applications'], ['Claude_pzs8sxrjxfjjc!Claude'])
        self.assertEqual(plan['desktop']['processes'][1]['tcp_to_proxy'], 1)
        self.assertEqual(plan['proxy']['owner_status'], 'observed_name_only_not_trusted')
        self.assertEqual(plan['browser']['isolation'], 'unconfirmed')
        self.assertEqual(plan['protection']['effective'], 'unknown')
        self.assertFalse(plan['protection']['apply_available'])
        self.assertFalse(plan['protection']['may_launch'])
        self.assertIn('existing_flow_revocation_unverified', plan['protection']['blockers'])
        text = json.dumps(plan, ensure_ascii=False)
        self.assertNotIn('PRIVATE_PATH', text)
        self.assertNotIn('203.0.113.9', text)
        self.assertNotIn('path', plan['desktop']['processes'][0])

    def test_unknown_or_ambiguous_input_does_not_become_a_rule_target(self):
        data = self.observed()
        data['package_ids'] = ['arbitrary chrome.exe PRIVATE_PATH']
        data['processes'][0]['started'] = 'not-a-time'
        data['processes'][1]['image_scope'] = 'outside_package'
        plan = preflight.make_plan(data, 24001, source='fixture')
        self.assertEqual(plan['desktop']['registered_applications'], [])
        self.assertEqual(plan['desktop']['snapshot_validity'], 'incomplete_or_malformed')
        self.assertIn('desktop_identity_unconfirmed', plan['protection']['blockers'])
        self.assertIn('process_coverage_unconfirmed', plan['protection']['blockers'])
        self.assertFalse(plan['protection']['may_launch'])
        self.assertNotIn('PRIVATE_PATH', json.dumps(plan))

    def test_proxy_absent_and_collection_error_remain_unknown(self):
        data = self.observed()
        data['proxy'] = {'listener_count': 0}
        plan = preflight.make_plan(data, 24001, source='fixture')
        self.assertEqual(plan['proxy']['owner_status'], 'unknown')
        self.assertIn('proxy_owner_untrusted', plan['protection']['blockers'])
        with mock.patch.object(preflight, '_collect_windows', side_effect=OSError('PRIVATE_SECRET')), \
             mock.patch.object(preflight, '_probe_wfp_exports', return_value={}):
            actual = preflight.inspect(24001)
        self.assertEqual(actual['collection'], 'unavailable')
        self.assertEqual(actual['observation']['error'], 'collector_unavailable')
        self.assertFalse(actual['protection']['may_launch'])
        self.assertNotIn('PRIVATE_SECRET', json.dumps(actual))

    def test_partial_snapshot_never_claims_complete_collection(self):
        data = self.observed()
        del data['chrome_process_count']
        plan = preflight.make_plan(data, 24001, source='fixture')
        self.assertEqual(plan['collection'], 'partial')
        self.assertFalse(plan['protection']['apply_available'])

    def test_bad_ports_rejected_before_collection(self):
        with mock.patch.object(preflight, '_collect_windows') as collect:
            for port in (0, 65536, True, '24001; evil'):
                with self.subTest(port=port), self.assertRaises(ValueError):
                    preflight.inspect(port)
            collect.assert_not_called()

    def test_fixture_and_help_have_no_system_mutation_and_apply_is_unavailable(self):
        for args in (['--help'], ['--proxy-port', '24001', '--fixture', 'desktop-observed']):
            proc = subprocess.run([sys.executable, '-B', '-m', 'src.protection.preflight', *args],
                                  capture_output=True, text=True, encoding='utf-8', timeout=15,
                                  env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
            self.assertEqual(proc.returncode, 0, proc.stderr)
            if '--fixture' in args:
                data = json.loads(proc.stdout)
                self.assertEqual(data['source'], 'fixture')
                self.assertFalse(data['protection']['apply_available'])
        proc = subprocess.run([sys.executable, '-B', '-m', 'src.protection.preflight', '--proxy-port', '24001', '--apply'],
                              capture_output=True, text=True, encoding='utf-8', timeout=15,
                              env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
        self.assertNotEqual(proc.returncode, 0)

    def test_dry_run_uses_only_readonly_collector(self):
        with mock.patch.object(preflight, '_collect_windows', return_value=self.observed()) as collect, \
             mock.patch.object(preflight, '_probe_wfp_exports', return_value={'FwpmEngineOpen0': True}) as probe:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = preflight.main(['--proxy-port', '24001', '--dry-run'])
        collect.assert_called_once_with(24001)
        probe.assert_called_once_with()
        plan = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(plan['source'], 'live_readonly')
        self.assertFalse(plan['protection']['apply_available'])
        self.assertTrue(plan['wfp_api']['exports']['FwpmEngineOpen0'])
        self.assertEqual(plan['wfp_api']['probe_status'], 'observed')
        self.assertEqual(plan['wfp_api']['permissions'], 'unverified')

    def test_fixture_never_accesses_live_system_or_wfp(self):
        with mock.patch.object(preflight, '_collect_windows', side_effect=AssertionError('unexpected live read')), \
             mock.patch.object(preflight, '_probe_wfp_exports', side_effect=AssertionError('unexpected WFP load')), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(preflight.main(['--proxy-port', '24001', '--fixture', 'desktop-observed']), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report['source'], 'fixture')
        self.assertEqual(report['wfp_api']['exports'], {})
        self.assertEqual(report['wfp_api']['probe_status'], 'not_run_fixture')
        self.assertFalse(report['protection']['apply_available'])

    def test_unavailable_wfp_probe_remains_unknown_without_error_leak(self):
        with mock.patch.object(preflight, '_collect_windows', return_value=self.observed()), \
             mock.patch.object(preflight, '_probe_wfp_exports', side_effect=OSError('PRIVATE_SECRET')):
            report = preflight.inspect(24001)
        self.assertEqual(report['wfp_api']['probe_status'], 'unavailable')
        self.assertEqual(report['wfp_api']['exports'], {})
        self.assertFalse(report['protection']['apply_available'])
        self.assertNotIn('PRIVATE_SECRET', json.dumps(report))

    @unittest.skipUnless(os.name == 'nt', 'Windows import probe')
    def test_import_never_loads_wfp_library(self):
        code = ("import ctypes; "
                "ctypes.WinDLL=lambda *a,**k: (_ for _ in ()).throw(AssertionError('unexpected DLL load')); "
                "import src.protection.preflight")
        proc = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True,
                              text=True, encoding='utf-8', timeout=15,
                              env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
        self.assertEqual(proc.returncode, 0, proc.stderr)

    @unittest.skipUnless(os.name == 'nt', 'Windows collector')
    def test_collector_sends_complete_readonly_script_to_windows_powershell(self):
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(self.observed()).encode('utf-8'), stderr=b'')
        with mock.patch.object(preflight.subprocess, 'run', return_value=completed) as run:
            result = preflight._collect_windows(24001)
        args = run.call_args.args[0]
        self.assertIn('-EncodedCommand', args)
        script = base64.b64decode(args[args.index('-EncodedCommand') + 1]).decode('utf-16le')
        self.assertIn('Get-AppxPackage', script)
        self.assertIn('Get-NetTCPConnection', script)
        self.assertNotIn('New-NetFirewallRule', script)
        self.assertNotIn('FwpmFilterAdd', script)
        self.assertEqual(result['proxy']['owner_name'], 'Proxy Manager')

    @unittest.skipUnless(os.name == 'nt', 'Windows export probe')
    def test_wfp_probe_only_resolves_exports_without_calling_them(self):
        import ctypes
        resolved = []
        class FakeLibrary:
            def __getattr__(self, name):
                resolved.append(name)
                def forbidden(*args):
                    raise AssertionError('WFP function was called')
                return forbidden
        with mock.patch.object(ctypes, 'WinDLL', return_value=FakeLibrary()) as load:
            result = preflight._probe_wfp_exports()
        self.assertEqual(set(resolved), set(preflight._WFP_EXPORTS))
        self.assertTrue(all(result.values()))
        self.assertEqual(load.call_args.kwargs['winmode'], 0x00000800)


if __name__ == '__main__':
    unittest.main()
