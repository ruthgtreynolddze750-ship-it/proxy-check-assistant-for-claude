"""Pure fixture model and review catalog; contains no Windows or WFP calls."""
import argparse
import ipaddress
import json


def review_spec():
    return {
        'source': 'offline_design',
        'status': 'candidate_not_implemented_or_authorized',
        'apply_available': False,
        'protection_effective': 'unknown',
        'execution_form': {
            'management': 'separate_privileged_windows_service_with_wfp_management_api',
            'lease_enforcement_candidate': 'separately_reviewed_signed_kernel_callout',
            'monitor': 'separate_unprivileged_monitor_sends_authenticated_health_to_management',
            'gateway': 'existing_shared_proxy_no_global_control_desktop_channel_termination_unproven',
            'current_installer_contains_any_of_these': False,
        },
        'management_apis': [
            'FwpmEngineOpen0', 'FwpmEngineClose0', 'FwpmProviderAdd0', 'FwpmSubLayerAdd0',
            'FwpmTransactionBegin0', 'FwpmFilterAdd0', 'FwpmTransactionCommit0', 'FwpmTransactionAbort0',
            'FwpmFilterGetByKey0', 'FwpmFilterCreateEnumHandle0', 'FwpmFilterEnum0',
            'FwpmFilterDestroyEnumHandle0', 'FwpmFreeMemory0', 'FwpmFilterDeleteByKey0',
            'FwpmSubLayerDeleteByKey0', 'FwpmProviderDeleteByKey0',
        ],
        'connect_layers': ['FWPM_LAYER_ALE_AUTH_CONNECT_V4', 'FWPM_LAYER_ALE_AUTH_CONNECT_V6'],
        'identity_conditions': ['FWPM_CONDITION_ALE_APP_ID', 'FWPM_CONDITION_ALE_PACKAGE_ID'],
        'route_conditions': ['FWPM_CONDITION_IP_PROTOCOL', 'FWPM_CONDITION_IP_REMOTE_ADDRESS',
                             'FWPM_CONDITION_IP_REMOTE_PORT'],
        'reauthorization_candidate': 'FWP_CONDITION_FLAG_IS_REAUTHORIZE',
        'rule_design': [
            {'id': 'baseline-block-remote-v4-v6', 'action': 'FWP_ACTION_BLOCK',
             'scope': 'verified_desktop_identity', 'condition': 'destination_not_exact_verified_loopback',
             'persistence': 'candidate_persistent', 'implemented': False},
            {'id': 'baseline-block-wrong-loopback-port', 'action': 'FWP_ACTION_BLOCK',
             'scope': 'verified_desktop_identity', 'condition': 'loopback_destination_and_port_not_verified_proxy',
             'persistence': 'candidate_persistent', 'implemented': False},
            {'id': 'baseline-block-udp', 'action': 'FWP_ACTION_BLOCK',
             'scope': 'verified_desktop_identity', 'condition': 'udp_even_when_loopback',
             'persistence': 'candidate_persistent', 'implemented': False},
            {'id': 'lock-gate', 'action': 'FWP_ACTION_BLOCK',
             'scope': 'verified_desktop_identity', 'condition': 'all_connections_while_unhealthy',
             'persistence': 'unresolved_must_fail_closed_on_restart_or_lease_loss', 'implemented': False},
        ],
        'arbitration': 'no_broad_permit_rule_existing_policy_may_still_block_proxy',
        'existing_connections': 'reauthorization_and_per_flow_termination_require_independent_real_validation',
        'rollback': ['inventory_before_apply', 'verify_project_provider_and_sublayer_ownership_and_exact_filter_keys',
                     'require_no_active_protected_session_and_separate_authorization',
                     'delete_only_verified_project_filters_then_owned_sublayer_then_owned_provider',
                     'record_each_result_and_never_delete_unknown_or_foreign_objects'],
        'blockers': ['sdk_abi_and_layer_condition_compatibility_unverified', 'msix_package_sid_and_full_trust_mapping_unverified',
                     'all_child_process_coverage_unverified', 'shared_dns_and_proxy_scope_unverified',
                     'persistent_and_boot_filter_lifecycle_unverified', 'existing_flow_termination_unverified',
                     'kernel_callout_lease_and_driver_signature_unverified', 'privileged_installation_not_authorized',
                     'browser_profile_instance_isolation_unconfirmed'],
        'limitations': ['fixture_only_no_windows_calls_or_real_filters',
                        'ale_connect_alone_does_not_prove_dns_udp_existing_flow_or_loopback_coverage',
                        'provider_exit_change_may_precede_poll_detection',
                        'plain_app_id_or_pid_cannot_separate_chrome_profiles'],
    }


_ROUTE_CASES = {
    'locked-proxy': ('locked', 'protected', 'tcp', '127.0.0.1', 12345),
    'active-proxy-v4': ('active', 'protected', 'tcp', '127.0.0.1', 12345),
    'active-proxy-v6': ('active', 'protected', 'tcp', '::1', 12345),
    'active-direct-v4': ('active', 'protected', 'tcp', '192.0.2.1', 12345),
    'active-direct-v6': ('active', 'protected', 'tcp', '2001:db8::1', 12345),
    'active-wrong-port': ('active', 'protected', 'tcp', '127.0.0.1', 12346),
    'active-udp': ('active', 'protected', 'udp', '127.0.0.1', 12345),
    'active-other-loopback': ('active', 'protected', 'tcp', '127.0.0.2', 12345),
    'active-v4-mapped-v6': ('active', 'protected', 'tcp', '::ffff:127.0.0.1', 12345),
    'normal-chrome': ('active', 'ordinary_browser', 'tcp', '192.0.2.1', 12345),
    'unknown-identity': ('active', 'unknown', 'tcp', '127.0.0.1', 12345),
}
_FAULTS = ('watchdog-lost', 'proxy-lost', 'exit-changed', 'check-stale')
_ROLLBACKS = {
    'owned-inactive': (True, True, True, 0, True),
    'foreign-owner': (False, True, True, 0, True),
    'unknown-owner': (None, True, True, 0, True),
    'changed-object': (True, False, True, 0, True),
    'foreign-filter': (True, True, False, 0, True),
    'active-session': (True, True, True, 1, True),
    'unknown-active-count': (True, True, True, None, True),
    'no-authorization': (True, True, True, 0, False),
}
_CASES = tuple(_ROUTE_CASES) + _FAULTS + tuple(_ROLLBACKS)


def run_fixture(case):
    if case not in _CASES:
        raise ValueError('unknown fixture')
    result = {'source': 'fixture', 'case': case, 'apply_available': False,
              'protection_effective': 'unknown', 'system_action': 'none'}
    if case in _ROUTE_CASES:
        state, identity, protocol, destination, port = _ROUTE_CASES[case]
        if identity == 'ordinary_browser':
            decision = 'out_of_scope'
        elif identity == 'unknown':
            decision = 'not_evaluable'
        elif (state != 'active' or protocol != 'tcp'
              or ipaddress.ip_address(destination) not in (ipaddress.ip_address('127.0.0.1'), ipaddress.ip_address('::1'))
              or port != 12345):
            decision = 'model_block'
        else:
            decision = 'model_no_project_block'
        result.update({'model_state': state, 'decision': decision,
                       'boundary': 'synthetic_identity_and_destination_not_a_wfp_result'})
    elif case in _FAULTS:
        result.update({'model_state': 'locked_required', 'existing_flow': 'unverified_not_closed_by_fixture',
                       'boundary': 'fault_transition_is_requirement_not_operational_watchdog'})
    else:
        provider_owned, object_matches, filters_owned, active_sessions, authorized = _ROLLBACKS[case]
        permitted = (provider_owned is True and object_matches is True and filters_owned is True
                     and type(active_sessions) is int and active_sessions == 0 and authorized is True)
        result.update({'rollback': 'fixture_only_owned_keys' if permitted else 'refuse',
                       'boundary': 'synthetic_ownership_only_no_actual_deletion'})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='纯离线 WFP 候选设计与固定样本；没有 WFP 应用入口。')
    parser.add_argument('--fixture', choices=_CASES, help='选择固定合成样本；不会读取真实系统')
    args = parser.parse_args(argv)
    print(json.dumps(run_fixture(args.fixture) if args.fixture else review_spec(), ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
