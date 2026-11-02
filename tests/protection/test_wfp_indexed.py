"""R21 recorded shape reproduced in memory; never load or call native WFP."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from src.protection import dedicated_wfp as wfp
from test_dedicated_wfp import FakeEngine
from test_wfp_readback import ReadEngine


class IndexedEngine(FakeEngine):
    def __init__(self):
        super().__init__()
        self.returned_flags = 65

    def get(self, kind, key):
        obj = super().get(kind, key)
        if obj is not None and kind == 'filter':
            obj['flags'] = self.returned_flags
        return obj


class IndexedReadbackTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(wfp.NativeWfp, '__init__',
            side_effect=AssertionError('native construction forbidden in offline tests')))
        self.engine = IndexedEngine()
        self.plan = wfp.prepare_plan(wfp.DedicatedTarget(r'C:\dedicated\chrome.exe',r'C:\dedicated\Fresh'),
            49152, excluded_executables=(r'C:\ordinary\chrome.exe',), backend=self.engine)
        self.objects = wfp.plan_objects(self.plan)

    def test_recorded_flags_65_shape_is_decoded_without_losing_raw_flags(self):
        native, keep = wfp._pack_object(self.objects[2])
        native.flags = 65
        self.assertEqual((native.weight.type,bool(native.reserved),native.numFilterConditions),(4,False,2))
        actual = wfp._unpack_object('filter',native)
        self.assertEqual(actual['flags'],65)
        self.assertEqual(dict(actual,flags=1),self.objects[2])

    def test_all_four_filters_accept_only_optional_indexed_output_and_preserve_plans(self):
        original = copy.deepcopy(self.objects)
        for expected in self.objects[2:]:
            for flags in (1,65):
                with self.subTest(filter=expected['name'],flags=flags):
                    native, keep = wfp._pack_object(expected);native.flags=flags
                    actual = wfp._unpack_object('filter',native)
                    reader = ReadEngine(self.plan);reader.objects[expected['key']]=actual
                    wfp._read_exact(reader,self.objects)
                    self.assertEqual(actual['flags'],flags)
        self.assertEqual(self.objects,original)
        self.assertTrue(all(obj['flags']==1 for obj in self.objects))

    def test_every_other_flag_bit_and_missing_persistence_are_rejected_for_each_filter(self):
        rejected = [0,64] + [base | (1 << bit) for base in (1,65) for bit in range(32) if bit not in (0,6)]
        for expected in self.objects[2:]:
            for flags in rejected:
                native, keep = wfp._pack_object(expected);native.flags=flags
                with self.subTest(filter=expected['name'],flags=flags):
                    with self.assertRaises(wfp.PolicyError) as caught:wfp._unpack_object('filter',native)
                    self.assertIn('flags',caught.exception.shape_mismatches)
                    self.assertEqual(caught.exception.native_shape['flags'],flags)

    def test_other_native_shape_checks_remain_strict_with_indexed_output(self):
        mutations=(('weight_type',lambda v:setattr(v.weight,'type',0)),
            ('reserved_present',lambda v:setattr(v,'reserved',wfp.C.pointer(wfp.GUID()))),
            ('condition_count',lambda v:setattr(v,'numFilterConditions',17)))
        for expected in self.objects[2:]:
            for name,mutate in mutations:
                native, keep=wfp._pack_object(expected);native.flags=65;mutate(native)
                with self.subTest(filter=expected['name'],field=name):
                    with self.assertRaises(wfp.PolicyError) as caught:wfp._unpack_object('filter',native)
                    self.assertEqual(caught.exception.shape_mismatches,(name,))

    def test_indexed_exception_never_applies_to_provider_or_sublayer(self):
        for expected in self.objects[:2]:
            reader=ReadEngine(self.plan);reader.objects[expected['key']]['flags']=65
            with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):wfp._read_exact(reader,self.objects)

    def test_all_policy_fields_remain_exact_when_indexed_is_present(self):
        mutations={
            'provider':lambda o:o.update(provider=wfp.V4),
            'layer':lambda o:o.update(layer='00000000-0000-0000-0000-000000000000'),
            'sublayer':lambda o:o.update(sublayer=wfp.V4),
            'action':lambda o:o.update(action=0x1002),
            'weight':lambda o:o.update(weight=o['weight']+1),
            'raw_context':lambda o:o.update(raw_context=1),
            'action_key':lambda o:o.update(action_key=wfp.V4),
            'data':lambda o:o.update(data='00'),
            'name':lambda o:o.update(name='changed'),
            'description':lambda o:o.update(description='changed'),
            'key':lambda o:o.update(key=wfp.V4),
            'appid':lambda o:o.update(conditions=tuple((key,match,kind,'00' if key==wfp.APP_ID else value)
                for key,match,kind,value in o['conditions'])),
            'match_type':lambda o:o.update(conditions=tuple((key,match^1,kind,value)
                for key,match,kind,value in o['conditions'])),
            'condition_type':lambda o:o.update(conditions=tuple((key,match,kind+1,value)
                for key,match,kind,value in o['conditions'])),
            'condition_count':lambda o:o.update(conditions=o['conditions'][:-1]),
            'unexpected_field':lambda o:o.update(unexpected=True)}
        for expected in self.objects[2:]:
            for field,mutate in mutations.items():
                reader=ReadEngine(self.plan);actual=reader.objects[expected['key']];actual['flags']=65;mutate(actual)
                with self.subTest(filter=expected['name'],field=field):
                    with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):wfp._read_exact(reader,self.objects)

    def test_indexed_four_filter_apply_and_matching_rollback_are_offline_only(self):
        wfp.apply_plan(self.plan,approval=wfp.PlanApproval(self.plan.digest,'apply'),backend=self.engine)
        self.assertEqual(len(self.engine.objects),6)
        self.engine.calls.clear()
        result=wfp.rollback_plan(self.plan,approval=wfp.PlanApproval(self.plan.digest,'rollback'),backend=self.engine)
        self.assertEqual(result['status'],'objects_absent')
        self.assertEqual(self.engine.objects,{})
        self.assertEqual(self.engine.calls.count('delete:filter'),4)

    def test_unknown_flags_block_apply_and_rollback_without_mutating_existing_objects(self):
        self.engine.returned_flags=97
        with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):
            wfp.apply_plan(self.plan,approval=wfp.PlanApproval(self.plan.digest,'apply'),backend=self.engine)
        self.assertNotIn('commit',self.engine.calls);self.assertEqual(self.engine.objects,{})
        self.engine.returned_flags=65
        wfp.apply_plan(self.plan,approval=wfp.PlanApproval(self.plan.digest,'apply'),backend=self.engine)
        before=copy.deepcopy(self.engine.objects);self.engine.calls.clear();self.engine.returned_flags=97
        with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):
            wfp.rollback_plan(self.plan,approval=wfp.PlanApproval(self.plan.digest,'rollback'),backend=self.engine)
        self.assertFalse(any(call.startswith('delete:') for call in self.engine.calls))
        self.assertEqual(self.engine.objects,before)

    def test_native_delete_guard_uses_same_exact_policy_comparison_without_dll_calls(self):
        native=object.__new__(wfp.NativeWfp)
        native._permission=(self.plan,wfp.PlanApproval(self.plan.digest,'rollback'),'rollback')
        native._transaction=True;native.handle=wfp.PTR(1);calls=[]
        native._call=lambda name,*args:calls.append(name)  # Recorded only; no DLL loaded.
        for expected in self.objects[2:]:
            actual=dict(expected,flags=65)
            native.get=lambda kind,key:copy.deepcopy(actual)
            native.delete('filter',expected['key'])
            actual['action']=0x1002
            with self.assertRaisesRegex(wfp.PolicyError,'unplanned_or_changed_object_delete'):
                native.delete('filter',expected['key'])
        self.assertEqual(calls,['FwpmFilterDeleteByKey0']*4)

    def test_readback_issuer_accepts_indexed_but_revokes_on_any_other_flag(self):
        engine=ReadEngine(self.plan)
        for expected in self.objects[2:]:engine.objects[expected['key']]['flags']=65
        reader=wfp.PolicyReadbackVerifier(self.plan,backend_factory=lambda:engine,clock=lambda:10)
        proof=reader.read()
        self.assertTrue(reader.accepts(proof));self.assertEqual(proof.source,'injected')
        self.assertFalse(proof.protection_verified)
        canonical=hashlib.sha256(json.dumps(self.objects,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(proof.objects_digest,canonical)
        engine.objects[self.objects[-1]['key']]['flags']=97
        with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):reader.read()
        self.assertFalse(reader.accepts(proof))


if __name__=='__main__':unittest.main()
