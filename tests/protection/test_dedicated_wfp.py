import copy
from dataclasses import replace
import importlib
import ipaddress
import unittest
from unittest.mock import patch


try:
    wfp = importlib.import_module('src.protection.dedicated_wfp')
except ModuleNotFoundError:
    wfp = None


class FakeEngine:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.pending = None
        self.fail_add = None
        self.corrupt_read = None
        self.active = False
        self.change_before_commit = False
        self.guard_count = 0
        self.source = 'offline_fixture'

    def identity(self, target, excluded):
        return wfp.ApplicationIdentity(target.executable, target.user_data_dir,
            ('fixed-file-identity',), 'a' * 64, b'dedicated-app-id',
            tuple((path, b'ordinary-app-id') for path in excluded), self.source)

    def guard(self, plan):
        self.calls.append('guard')
        self.guard_count += 1
        if self.active or (self.change_before_commit and self.guard_count > 1):
            raise wfp.PolicyError('dedicated_process_active_or_unknown')

    def capabilities(self):
        self.calls.append('capabilities')
        return wfp.REQUIRED_FIELDS

    def sublayer_weights(self):
        return frozenset(obj['weight'] for obj in self.objects.values() if obj['kind'] == 'sublayer')

    def begin(self):
        self.calls.append('begin')
        self.pending = copy.deepcopy(self.objects)

    def add(self, obj):
        self.calls.append('add:' + obj['kind'])
        if obj['key'] == self.fail_add:
            raise wfp.PolicyError('injected_add_failure')
        self.pending[obj['key']] = copy.deepcopy(obj)

    def get(self, kind, key):
        self.calls.append('get:' + kind)
        value = copy.deepcopy((self.pending if self.pending is not None else self.objects).get(key))
        if value and key == self.corrupt_read:
            value['flags'] = 0
        return value

    def delete(self, kind, key):
        self.calls.append('delete:' + kind)
        del self.pending[key]

    def commit(self):
        self.calls.append('commit')
        self.objects = self.pending
        self.pending = None

    def abort(self):
        self.calls.append('abort')
        self.pending = None


class DedicatedWfpTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(wfp, 'dedicated WFP implementation is missing')
        self.engine = FakeEngine()
        target = wfp.DedicatedTarget(r'C:\dedicated\chrome.exe', r'C:\dedicated\User Data')
        self.plan = wfp.prepare_plan(target, 49152,
            excluded_executables=(r'C:\ordinary\chrome.exe',), backend=self.engine)

    def approval(self, action='apply', plan=None):
        return wfp.PlanApproval((plan or self.plan).digest, action)

    def test_default_and_wrong_authorization_cannot_begin_transaction(self):
        for approval in (None, wfp.PlanApproval('0' * 64, 'apply'), self.approval('rollback')):
            self.engine.calls.clear()
            with self.assertRaisesRegex(wfp.PolicyError, 'authorization_required'):
                wfp.apply_plan(self.plan, approval=approval, backend=self.engine)
            self.assertEqual(self.engine.calls, [])
        with self.assertRaisesRegex(wfp.PolicyError, 'authorization_required'):
            wfp.rollback_plan(self.plan, backend=self.engine)

    def test_policy_complement_has_no_permit_and_only_app_scoped_blocks(self):
        filters = [x for x in wfp.plan_objects(self.plan) if x['kind'] == 'filter']
        self.assertEqual(len(filters), 4)
        for obj in filters:
            self.assertEqual(obj['action'], wfp.FWP_ACTION_BLOCK)
            self.assertIn((wfp.APP_ID, wfp.EQUAL, wfp.BLOB, b'dedicated-app-id'.hex()), obj['conditions'])
        def blocked(app_id, family, address, port, protocol):
            incoming = {wfp.APP_ID: app_id.hex(), wfp.PORT: port, wfp.PROTOCOL: protocol,
                        wfp.ADDRESS: int(ipaddress.ip_address(address))}
            for obj in filters:
                if obj['layer'] != (wfp.V4 if family == 4 else wfp.V6):
                    continue
                matches = []
                for key, match, datatype, value in obj['conditions']:
                    self.assertIn(match, (wfp.EQUAL, wfp.NOT_EQUAL))
                    matches.append(incoming[key] == value if match == wfp.EQUAL else incoming[key] != value)
                if all(matches):
                    return True
            return False
        for family, address, port, protocol, expected in (
            (4, '127.0.0.1', 49152, 6, False),
            (4, '127.0.0.1', 49151, 6, True),
            (4, '127.0.0.2', 49152, 6, True),
            (4, '192.0.2.7', 49152, 6, True),
            (4, '127.0.0.1', 49152, 17, True),
            (4, '127.0.0.1', 49152, 1, True),
            (6, '::1', 49152, 6, True)):
            self.assertEqual(blocked(b'dedicated-app-id', family,
                address, port, protocol), expected)
            self.assertFalse(blocked(b'ordinary-app-id', family,
                address, port, protocol))

    def test_plan_has_unique_keys_and_digest_binds_every_relevant_choice(self):
        objects = wfp.plan_objects(self.plan)
        self.assertEqual(len({obj['key'] for obj in objects}), 6)
        self.assertNotEqual(replace(self.plan, relay_port=49153).digest, self.plan.digest)
        self.assertNotEqual(replace(self.plan, deployment_id=str(wfp.uuid.uuid4())).digest, self.plan.digest)
        self.assertNotIn('dedicated-app-id', repr(self.plan))

    def test_invalid_ports_and_missing_excluded_application_rejected(self):
        for port in (0, 65536, True, '49152'):
            with self.assertRaises(wfp.PolicyError):
                wfp.prepare_plan(wfp.DedicatedTarget('x', 'y'), port,
                    excluded_executables=('z',), backend=self.engine)
        with self.assertRaises(wfp.PolicyError):
            wfp.prepare_plan(wfp.DedicatedTarget('x', 'y'), 49152,
                excluded_executables=(), backend=self.engine)

    def test_transaction_applies_exact_objects_and_reads_them_back(self):
        receipt = wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertEqual(receipt['status'], 'objects_read_back')
        self.assertFalse(receipt['protection_verified'])
        self.assertEqual(self.engine.objects, {x['key']: x for x in wfp.plan_objects(self.plan)})
        self.assertEqual(self.engine.calls.count('commit'), 1)
        self.assertGreaterEqual(self.engine.calls.count('guard'), 2)

    def test_existing_key_is_never_replaced(self):
        obj = wfp.plan_objects(self.plan)[0]
        self.engine.objects[obj['key']] = obj
        with self.assertRaisesRegex(wfp.PolicyError, 'object_key_collision'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertFalse(any(x.startswith('add:') for x in self.engine.calls))

    def test_add_failure_aborts_without_partial_commit(self):
        self.engine.fail_add = wfp.plan_objects(self.plan)[3]['key']
        with self.assertRaisesRegex(wfp.PolicyError, 'injected_add_failure'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertEqual(self.engine.objects, {})
        self.assertIn('abort', self.engine.calls)
        self.assertNotIn('commit', self.engine.calls)

    def test_mismatched_readback_aborts(self):
        self.engine.corrupt_read = wfp.plan_objects(self.plan)[3]['key']
        with self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertEqual(self.engine.objects, {})

    def test_active_or_new_process_refuses_apply_and_rollback(self):
        self.engine.active = True
        with self.assertRaisesRegex(wfp.PolicyError, 'dedicated_process_active_or_unknown'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertNotIn('begin', self.engine.calls)
        self.engine.active = False
        self.engine.change_before_commit = True
        self.engine.guard_count = 0
        with self.assertRaises(wfp.PolicyError):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertEqual(self.engine.objects, {})

    def test_rollback_only_deletes_matching_owned_objects_in_dependency_order(self):
        wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.engine.objects['foreign'] = {'kind': 'provider', 'key': 'foreign'}
        self.engine.calls.clear()
        receipt = wfp.rollback_plan(self.plan, approval=self.approval('rollback'), backend=self.engine)
        self.assertEqual(receipt['status'], 'objects_absent')
        self.assertEqual(list(self.engine.objects), ['foreign'])
        self.assertEqual([x for x in self.engine.calls if x.startswith('delete:')],
            ['delete:filter'] * 4 + ['delete:sublayer', 'delete:provider'])

    def test_modified_object_or_active_session_refuses_rollback_without_deletion(self):
        wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.engine.calls.clear()
        self.engine.active = True
        with self.assertRaises(wfp.PolicyError):
            wfp.rollback_plan(self.plan, approval=self.approval('rollback'), backend=self.engine)
        self.assertFalse(any(x.startswith('delete:') for x in self.engine.calls))
        self.engine.active = False
        self.engine.objects[wfp.plan_objects(self.plan)[2]['key']]['flags'] = 0
        with self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch'):
            wfp.rollback_plan(self.plan, approval=self.approval('rollback'), backend=self.engine)
        self.assertFalse(any(x.startswith('delete:') for x in self.engine.calls))

    def test_native_abi_has_documented_x64_layout(self):
        self.assertEqual(wfp.abi_sizes(), {'GUID': 16, 'Blob': 16, 'Value': 16,
            'Condition': 40, 'Provider': 64, 'SubLayer': 72, 'Filter': 200,
            'Layer': 72, 'Field': 16, 'Session': 72})

    def test_native_object_marshalling_preserves_full_policy_and_host_order(self):
        for obj in wfp.plan_objects(self.plan):
            native, keep = wfp._pack_object(obj)
            self.assertTrue(keep)
            self.assertEqual(wfp._unpack_object(obj['kind'], native), obj)
        self.assertEqual(wfp.Filter.providerData.offset, 48)
        self.assertEqual(wfp.Filter.filterCondition.offset, 120)
        self.assertEqual(wfp.Filter.action.offset, 128)
        self.assertEqual(wfp.Filter.context.offset, 152)
        self.assertEqual(wfp.Filter.filterId.offset, 176)
        self.assertEqual(wfp.Filter.effectiveWeight.offset, 184)
        native, keep = wfp._pack_object(wfp.plan_objects(self.plan)[3])
        values = {wfp._guid_text(native.filterCondition[i].fieldKey):
                  wfp._read_value(native.filterCondition[i].conditionValue)
                  for i in range(native.numFilterConditions)}
        self.assertEqual(values[wfp.ADDRESS], 0x7F000001)

    def test_native_write_methods_reject_before_accessing_any_dll_function(self):
        native = object.__new__(wfp.NativeWfp)
        native._permission = None
        native._transaction = False
        native.handle = wfp.PTR(1)
        for call in (native.begin, native.commit, native.abort,
                     lambda: native.add({}), lambda: native.delete('filter', 'invalid')):
            with self.assertRaisesRegex(wfp.PolicyError, 'authorization_required'):
                call()

    def test_engine_close_releases_pending_transaction_after_abort_failure(self):
        native = object.__new__(wfp.NativeWfp)
        native._permission = None
        native._transaction = True
        native.handle = wfp.PTR(1)
        calls = []
        native._call = lambda name, *args: calls.append(name)
        native.close()
        self.assertEqual(calls, ['FwpmEngineClose0'])
        self.assertFalse(native._transaction)
        self.assertFalse(native.handle.value)

    def test_missing_native_field_support_blocks_before_transaction(self):
        self.engine.capabilities = lambda: {}
        with self.assertRaisesRegex(wfp.PolicyError, 'native_layer_condition_unconfirmed'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertNotIn('begin', self.engine.calls)

    def test_same_app_id_and_partial_owned_set_are_rejected(self):
        identity = replace(self.plan.identity, excluded=(('ordinary', self.plan.identity.app_id),))
        with self.assertRaisesRegex(wfp.PolicyError, 'shared_application_plan'):
            wfp.plan_objects(replace(self.plan, identity=identity))
        self.engine.objects[wfp.plan_objects(self.plan)[0]['key']] = wfp.plan_objects(self.plan)[0]
        with self.assertRaisesRegex(wfp.PolicyError, 'object_mismatch'):
            wfp.rollback_plan(self.plan, approval=self.approval('rollback'), backend=self.engine)
        self.assertFalse(any(x.startswith('delete:') for x in self.engine.calls))

    def test_post_commit_mismatch_retains_objects_and_reports_unknown(self):
        commit = self.engine.commit
        def corrupt_after_commit():
            commit()
            self.engine.corrupt_read = wfp.plan_objects(self.plan)[2]['key']
        self.engine.commit = corrupt_after_commit
        with self.assertRaisesRegex(wfp.PolicyError, 'commit_or_post_commit_state_unknown'):
            wfp.apply_plan(self.plan, approval=self.approval(), backend=self.engine)
        self.assertEqual(len(self.engine.objects), 6)
        self.assertFalse(any(x.startswith('delete:') for x in self.engine.calls))

    def test_close_failure_is_not_swallowed_inside_callers_exception_handler(self):
        class OwnedFake(FakeEngine):
            def _grant(self, *args):
                pass
            def _revoke(self):
                pass
            def close(self):
                raise wfp.PolicyError('simulated_close_failure')
        with patch.object(wfp, 'NativeWfp', OwnedFake):
            try:
                raise ValueError('unrelated_outer_error')
            except ValueError:
                with self.assertRaisesRegex(wfp.PolicyError, 'engine_close_failed') as caught:
                    wfp.apply_plan(self.plan, approval=self.approval())
        self.assertTrue(caught.exception.operation_state['committed'])
        self.assertTrue(caught.exception.operation_state['objects_verified'])
        self.assertEqual(len(caught.exception.engine.objects), 6)

    def test_abort_and_close_errors_preserve_original_failure_and_owned_handle(self):
        class OwnedFake(FakeEngine):
            def _grant(self, *args):
                pass
            def _revoke(self):
                pass
            def add(self, obj):
                raise wfp.PolicyError('original_add_failure')
            def abort(self):
                raise wfp.PolicyError('abort_failure')
            def close(self):
                raise wfp.PolicyError('close_failure')
        with patch.object(wfp, 'NativeWfp', OwnedFake):
            with self.assertRaises(wfp.PolicyError) as caught:
                wfp.apply_plan(self.plan, approval=self.approval())
        error = caught.exception
        self.assertIn('abort_failure', str(error))
        self.assertIn('original_add_failure', str(error.__cause__))
        self.assertTrue(any('close_failure' in note for note in error.__notes__))
        self.assertFalse(error.operation_state['committed'])
        self.assertIsNotNone(error.engine)

    def test_unused_raw_context_union_tail_does_not_change_semantic_readback(self):
        obj = wfp.plan_objects(self.plan)[2]
        native, keep = wfp._pack_object(obj)
        wfp.C.memmove(wfp.C.addressof(native.context) + 8, b'\xaa' * 8, 8)
        self.assertEqual(native.context.rawContext, 0)
        self.assertEqual(wfp._unpack_object('filter', native), obj)
        native.context.rawContext = 1
        self.assertNotEqual(wfp._unpack_object('filter', native), obj)

    def test_cancellation_is_preserved_when_owned_engine_close_also_fails(self):
        class OwnedFake(FakeEngine):
            def _grant(self, *args):
                pass
            def _revoke(self):
                pass
            def add(self, obj):
                raise KeyboardInterrupt('cancel_requested')
            def close(self):
                raise wfp.PolicyError('close_failure')
        with patch.object(wfp, 'NativeWfp', OwnedFake):
            with self.assertRaises(KeyboardInterrupt) as caught:
                wfp.apply_plan(self.plan, approval=self.approval())
        self.assertIn('abort', caught.exception.engine.calls)
        self.assertFalse(caught.exception.operation_state['committed'])

    def test_shape_failure_preserves_minimal_metadata_and_strict_rejection(self):
        cases = (
            ('flags', lambda f: setattr(f, 'flags', 97)),  # PERSISTENT | INDEXED | DISABLED.
            ('weight_type', lambda f: setattr(f.weight, 'type', 0)),
            ('reserved_present', lambda f: setattr(f, 'reserved', wfp.C.pointer(wfp.GUID()))),
            ('condition_count', lambda f: setattr(f, 'numFilterConditions', 17)))
        for branch, mutate in cases:
            native, keep = wfp._pack_object(wfp.plan_objects(self.plan)[2])
            mutate(native)
            with self.assertRaisesRegex(wfp.PolicyError, 'native_filter_shape_unexpected') as caught:
                wfp._unpack_object('filter', native)
            self.assertEqual(caught.exception.shape_mismatches, (branch,))
            self.assertEqual(set(caught.exception.native_shape),
                {'flags', 'weight_type', 'reserved_present', 'condition_count'})
            self.assertIn(branch, str(caught.exception))
            self.assertNotIn('dedicated-app-id', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
