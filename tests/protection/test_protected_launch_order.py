"""Protected launch: fresh exit evidence, then only the activation, so forwarding opens inside 30 s."""
import inspect
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import backend
from src.core.backend import Check, Detection
from src.protection.desktop_session import DesktopProtectionRuntime, NativeDesktopBackend
from src.ui.desktop_presentation import reason_label
from test_desktop_protection import CFG, FAST, FakeBackend, FakeRelay, wait_for

APP_ID = 'Claude_pzs8sxrjxfjjc!Claude'


class DeadlineRelay(FakeRelay):
    def authorize(self, deadline, owner, *, new_owner=False):
        if deadline <= time.monotonic():
            return False
        return super().authorize(deadline, owner, new_owner=new_owner)


class OrderedBackend(FakeBackend):
    def __init__(self):
        super().__init__()
        self.calls, self.checks, self.launch_delay = [], [], 0.0
        self.relay = DeadlineRelay()

    def desktop_check(self, config):
        self.calls.append('check')
        result = self.checks.pop(0) if self.checks else 'pass'
        return result if not self.running_state else 'fail'

    def detect(self, config, *, deadline, cancelled):
        if self.applied and not self.launches:
            self.calls.append('detect')
        return super().detect(config, deadline=deadline, cancelled=cancelled)

    def apply(self, plan):
        self.calls.append('apply')
        super().apply(plan)

    def launch(self, config, app_id, port):
        self.calls.append('launch')
        time.sleep(self.launch_delay)
        return super().launch(config, app_id, port)


class ProtectedLaunchOrderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.backend = OrderedBackend()
        self.runtime = DesktopProtectionRuntime(journal_path=Path(self.temp.name) / 'desktop-recovery.json',
                                                budget=FAST, backend=self.backend)

    def tearDown(self):
        self.runtime.abandon()
        self.temp.cleanup()

    def settle(self, phase):
        self.assertTrue(self.runtime.request_start(CFG, APP_ID, 'r1'))
        self.assertTrue(wait_for(lambda: self.runtime.current().phase == phase, 8), self.runtime.current())
        return self.runtime.current()

    def test_running_check_then_fresh_evidence_then_activation_after_the_rules(self):
        self.settle('running')
        after_rules = self.backend.calls[self.backend.calls.index('apply') + 1:]
        self.assertEqual(after_rules[:3], ['check', 'detect', 'launch'])

    def test_slow_activation_inside_the_evidence_window_still_opens_forwarding(self):
        self.backend.launch_delay = 1.5
        self.settle('running')
        self.assertEqual(self.backend.relay.state, 'forwarding')

    def test_activation_past_the_evidence_window_never_forwards(self):
        self.backend.launch_delay = 3.2
        view = self.settle('fused')
        self.assertEqual(view.reason_code, 'relay_not_authorized')
        self.assertNotEqual(self.backend.relay.state, 'forwarding')
        self.assertEqual(self.backend.rolled_back, 0)

    def test_desktop_started_after_the_rules_blocks_the_launch_and_removes_the_rules(self):
        self.backend.checks = ['pass', 'fail']
        view = self.settle('failed')
        self.assertEqual(view.reason_code, 'desktop_running')
        self.assertEqual(self.backend.launches, 0)
        self.assertEqual(self.backend.rolled_back, 1)


class NativeLaunchTests(unittest.TestCase):
    def activate(self, port, error=None):
        with patch.object(backend, 'detect', side_effect=AssertionError('no second detection')) as detect, \
                patch.object(backend, '_claude_running', side_effect=AssertionError('checked before')), \
                patch.object(backend, 'discover_desktop', side_effect=AssertionError('checked before')), \
                patch.object(backend, '_activate_application', return_value=77, side_effect=error) as activate:
            pid = NativeDesktopBackend().launch(CFG, APP_ID, port)
        detect.assert_not_called()
        return pid, activate

    def test_only_activates_with_the_relay_port(self):
        pid, activate = self.activate(45678)
        activate.assert_called_once_with(APP_ID, '--proxy-server=http://127.0.0.1:45678')
        self.assertEqual(pid, 77)

    def test_invalid_port_never_activates(self):
        for port in (0, 65536, '45678', None):
            with self.subTest(port=port):
                pid, activate = self.activate(port)
                activate.assert_not_called()
                self.assertIsNone(pid)

    def test_activation_error_returns_no_pid(self):
        pid, _ = self.activate(45678, OSError('application activation failed'))
        self.assertIsNone(pid)


class NormalLaunchTests(unittest.TestCase):
    def test_normal_launch_is_the_original_form(self):
        self.assertEqual(list(inspect.signature(backend.launch_desktop).parameters), ['config', 'app_user_model_id'])
        ok = Check('pass', 'ok')
        result = Detection(ok, ok, ok, ok, Check('unknown', ''), mapping=ok, _owner_evidence=('o',), target_trace=ok)
        with patch.object(backend, '_claude_running', return_value=ok), \
                patch.object(backend, 'discover_desktop', return_value=('App!Claude',)), \
                patch.object(backend, 'detect', return_value=result) as detect, \
                patch.object(backend, '_proxy_owner_snapshot', return_value=('o',)), \
                patch.object(backend, '_activate_application', return_value=99) as activate:
            outcome = backend.launch_desktop(CFG, 'App!Claude')
        detect.assert_called_once_with(CFG)
        activate.assert_called_once_with('App!Claude', '--proxy-server=http://127.0.0.1:24001')
        self.assertEqual(outcome.pid, 99)


class LabelTests(unittest.TestCase):
    def test_unauthorized_forwarding_has_its_own_label(self):
        self.assertEqual(reason_label('relay_not_authorized'), '转发授权未确认')

    def test_preparing_event_is_not_unconfirmed(self):
        self.assertEqual(reason_label('preparing'), '已开始')
        self.assertEqual(reason_label('relay_lease_expired'), '转发已停止（授权到期）')


if __name__ == '__main__':
    unittest.main()
