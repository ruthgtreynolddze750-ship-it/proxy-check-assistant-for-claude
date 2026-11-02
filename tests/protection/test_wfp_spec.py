import json
import os
import subprocess
import sys
import unittest

from src.protection import wfp_spec


class WfpSpecTests(unittest.TestCase):
    def test_candidate_identifies_layers_apis_and_unverified_prerequisites(self):
        spec = wfp_spec.review_spec()
        self.assertFalse(spec['apply_available'])
        self.assertEqual(spec['protection_effective'], 'unknown')
        self.assertEqual(set(spec['connect_layers']), {'FWPM_LAYER_ALE_AUTH_CONNECT_V4', 'FWPM_LAYER_ALE_AUTH_CONNECT_V6'})
        self.assertIn('FwpmFilterAdd0', spec['management_apis'])
        self.assertIn('FWPM_CONDITION_ALE_APP_ID', spec['identity_conditions'])
        self.assertIn('FWPM_CONDITION_ALE_PACKAGE_ID', spec['identity_conditions'])
        self.assertIn('existing_flow_termination_unverified', spec['blockers'])
        self.assertIn('no_global_control', spec['execution_form']['gateway'])

    def test_fixture_route_truth_table_never_claims_live_enforcement(self):
        expected = {
            'locked-proxy': 'model_block', 'active-proxy-v4': 'model_no_project_block',
            'active-proxy-v6': 'model_no_project_block', 'active-direct-v4': 'model_block',
            'active-direct-v6': 'model_block', 'active-wrong-port': 'model_block',
            'active-udp': 'model_block', 'normal-chrome': 'out_of_scope',
            'unknown-identity': 'not_evaluable',
            'active-other-loopback': 'model_block', 'active-v4-mapped-v6': 'model_block',
        }
        for case, decision in expected.items():
            with self.subTest(case=case):
                result = wfp_spec.run_fixture(case)
                self.assertEqual(result['decision'], decision)
                self.assertEqual(result['source'], 'fixture')
                self.assertEqual(result['protection_effective'], 'unknown')
                self.assertFalse(result['apply_available'])

    def test_fault_model_does_not_claim_existing_connection_revoked(self):
        for event in ('watchdog-lost', 'proxy-lost', 'exit-changed', 'check-stale'):
            result = wfp_spec.run_fixture(event)
            self.assertEqual(result['model_state'], 'locked_required')
            self.assertEqual(result['existing_flow'], 'unverified_not_closed_by_fixture')
            self.assertFalse(result['apply_available'])

    def test_rollback_model_rejects_foreign_changed_or_active_objects(self):
        self.assertEqual(wfp_spec.run_fixture('owned-inactive')['rollback'], 'fixture_only_owned_keys')
        for case in ('foreign-owner', 'changed-object', 'active-session', 'unknown-owner',
                     'foreign-filter', 'no-authorization', 'unknown-active-count'):
            with self.subTest(case=case):
                self.assertEqual(wfp_spec.run_fixture(case)['rollback'], 'refuse')

    def test_cli_runs_only_known_fixtures_and_has_no_apply_entrypoint(self):
        env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
        for args in (['--help'], ['--fixture', 'active-proxy-v4']):
            p = subprocess.run([sys.executable, '-B', '-m', 'src.protection.wfp_spec', *args],
                               capture_output=True, text=True, encoding='utf-8', timeout=15, env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            if '--fixture' in args:
                self.assertFalse(json.loads(p.stdout)['apply_available'])
        p = subprocess.run([sys.executable, '-B', '-m', 'src.protection.wfp_spec', '--apply'],
                           capture_output=True, text=True, encoding='utf-8', timeout=15, env=env)
        self.assertNotEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
