from dataclasses import replace
import unittest
from unittest.mock import patch

from src.protection import dedicated_wfp as wfp
from test_dedicated_wfp import FakeEngine


class WeightEngine(FakeEngine):
    def __init__(self):
        super().__init__()
        self.weights = {32768}
        self.simulate_late_adjustment = False

    def sublayer_weights(self):
        return frozenset(self.weights)

    def add(self, obj):
        super().add(obj)
        if obj['kind'] == 'sublayer' and self.simulate_late_adjustment:
            self.pending[obj['key']]['weight'] += 1


class SublayerWeightTests(unittest.TestCase):
    def plan(self, engine):
        return wfp.prepare_plan(wfp.DedicatedTarget(r'C:\dedicated\chrome.exe',r'C:\dedicated\Empty'),
            49152,excluded_executables=(r'C:\ordinary\chrome.exe',),backend=engine)

    def test_real_collision_delta_is_avoided_in_reviewed_plan(self):
        engine = WeightEngine();plan = self.plan(engine)
        self.assertEqual(wfp.plan_objects(plan)[1]['weight'],32769)
        self.assertEqual(plan.sublayer_weight,32769)
        self.assertNotEqual(plan.digest,replace(plan,sublayer_weight=32770).digest)
        wfp.apply_plan(plan,approval=wfp.PlanApproval(plan.digest,'apply'),backend=engine)

    def test_weight_claimed_after_preparation_rejects_before_add(self):
        engine = WeightEngine();plan = self.plan(engine)
        engine.weights.add(32769);engine.calls.clear()
        with self.assertRaisesRegex(wfp.PolicyError,'sublayer_weight_in_use'):
            wfp.apply_plan(plan,approval=wfp.PlanApproval(plan.digest,'apply'),backend=engine)
        self.assertFalse(any(call.startswith('add:') for call in engine.calls))

    def test_unexpected_native_weight_still_aborts_without_commit(self):
        engine = WeightEngine();plan = self.plan(engine);engine.simulate_late_adjustment=True
        with self.assertRaisesRegex(wfp.PolicyError,'object_mismatch'):
            wfp.apply_plan(plan,approval=wfp.PlanApproval(plan.digest,'apply'),backend=engine)
        self.assertIn('abort',engine.calls);self.assertNotIn('commit',engine.calls)
        self.assertEqual(engine.objects,{})

    def test_bounded_range_exhaustion_does_not_raise_privilege_or_choose_random_weight(self):
        engine = WeightEngine();engine.weights=set(range(32768,33024))
        with self.assertRaisesRegex(wfp.PolicyError,'sublayer_weight_unavailable'):
            self.plan(engine)

    def test_prepare_preserves_primary_and_cancellation_when_close_also_fails(self):
        for primary in (wfp.PolicyError('enumeration_failed'), KeyboardInterrupt('cancelled')):
            engine = WeightEngine()
            def fail_weights(): raise primary
            def fail_close(): raise OSError('close_failed')
            engine.sublayer_weights, engine.close = fail_weights, fail_close
            with patch.object(wfp, 'NativeWfp', return_value=engine):
                with self.assertRaises(type(primary)) as caught:
                    self.plan(None)
            self.assertIs(caught.exception, primary)
            self.assertIs(caught.exception.engine, engine)
            self.assertTrue(any('close_failed' in note for note in caught.exception.__notes__))

    def test_prepare_close_failure_on_success_retains_handle(self):
        engine = WeightEngine()
        def fail_close(): raise OSError('close_failed')
        engine.close = fail_close
        with patch.object(wfp, 'NativeWfp', return_value=engine):
            with self.assertRaisesRegex(wfp.PolicyError, 'prepare_close_failed') as caught:
                self.plan(None)
        self.assertIs(caught.exception.engine, engine)


if __name__=='__main__':unittest.main()
