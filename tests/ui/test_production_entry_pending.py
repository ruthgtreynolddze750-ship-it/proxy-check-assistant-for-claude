"""Actual startup regression; no production providers or sessions are injected."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class ProductionEntryPendingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.ui import app as module
        from src.protection.managed_session import ManagedSessionRuntime
        settings = Path(os.environ['LOCALAPPDATA']) / 'ClaudeLaunchCenter/settings.json'
        def digest():
            return hashlib.sha256(settings.read_bytes()).hexdigest() if settings.exists() else None
        before = digest()
        cls.observation = {}
        active = [False]
        attempts = []
        callback_errors = []

        def audit(event, args):
            if not active[0]:
                return
            if event in ('socket.connect', 'socket.connect_ex', 'socket.getaddrinfo',
                         'subprocess.Popen', 'os.system', 'os.startfile', 'os.startfile/2'):
                attempts.append(event)
                raise RuntimeError('Startup acceptance forbids network or child processes')
            if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
                path = Path(os.fsdecode(args[0]))
                mode, flags = args[1], args[2]
                writing = ((isinstance(mode, str) and any(c in mode for c in 'wax+')) or
                           (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)))
                if path.name.lower() in ('cookies', 'cookies-journal') or (writing and path.resolve() == settings.resolve()):
                    attempts.append('cookie_or_settings_access')
                    raise RuntimeError('Cookie access and settings writes forbidden')

        sys.addaudithook(audit)
        previous_profile, previous_argv = sys.getprofile(), sys.argv

        def observe(app):
            try:
                cls.observation = {
                    'binding_provider_connected': app._monitor_binding_provider is not None,
                    'relay_provider_connected': callable(app._monitor_relay_snapshot),
                    'factory_is_default_rejection': app._monitor_factory is module._default_monitor_factory,
                    'actual_runtime': isinstance(app._monitor_runtime, ManagedSessionRuntime),
                    'same_runtime_adapter': (app._managed_adapter.runtime is app._monitor_runtime
                        and app._monitor_binding_provider is app._managed_adapter
                        and getattr(app._monitor_factory, '__self__', None) is app._managed_adapter
                        and getattr(app._monitor_relay_snapshot, '__self__', None) is app._managed_adapter),
                    'session_created_at_startup': app._monitor_session is not None,
                    'buttons': {name: str(widget['state']) for name, widget in (
                        ('start', app.start_monitor_button), ('stop', app.stop_monitor_button),
                        ('resume', app.resume_monitor_button))},
                    'summary': app.monitor_summary.get(),
                }
            finally:
                app.root.quit()  # Other test-created Tk roots must not prolong this mainloop.
                app.root.destroy()

        def profile(frame, event, arg):
            if event == 'return' and frame.f_code is module.App.__init__.__code__:
                sys.setprofile(previous_profile)
                app = frame.f_locals['self']
                app.root.report_callback_exception = lambda kind, value, tb: callback_errors.append(kind.__name__)
                app.root.after(100, lambda: observe(app))

        try:
            active[0] = True
            sys.argv = [str(ROOT / 'packaging/launcher.py')]
            spec = importlib.util.spec_from_file_location('r25_entry_under_test', ROOT / 'packaging/launcher.py')
            launcher = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(launcher)
            sys.setprofile(profile)
            cls.launcher_exit = launcher.main()
        finally:
            sys.setprofile(previous_profile)
            sys.argv = previous_argv
            active[0] = False
        cls.observation.update(settings_unchanged=before == digest(), side_effect_attempts=attempts,
                               callback_errors=callback_errors)
        if callback_errors or 'binding_provider_connected' not in cls.observation:
            raise AssertionError('Actual startup observation did not complete')

    def test_formal_entry_connects_production_binding_provider(self):
        self.assertTrue(self.observation['binding_provider_connected'],
                        'Formal main still has no production binding provider')
        self.assertFalse(self.observation['factory_is_default_rejection'],
                         'Formal main still uses the rejecting monitor factory')

    def test_formal_entry_connects_same_runtime_relay_snapshot(self):
        self.assertTrue(self.observation['relay_provider_connected'],
                        'Formal main still has no relay snapshot callback')
        self.assertTrue(self.observation['actual_runtime'])
        self.assertTrue(self.observation['same_runtime_adapter'])

    def test_startup_preserves_settings_and_has_no_live_actions(self):
        self.assertEqual(self.launcher_exit, 0)
        self.assertEqual(self.observation['side_effect_attempts'], [])
        self.assertEqual(self.observation['callback_errors'], [])
        self.assertTrue(self.observation['settings_unchanged'])
        self.assertFalse(self.observation['session_created_at_startup'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
