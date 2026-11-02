import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('portable_build', ROOT / 'packaging' / 'build_portable.py')
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)


class PortableRuntimeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name) / 'runtime'
        for name in portable.REQUIRED_RUNTIME:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic')
        for name in ['Lib/site-packages/settings.json', 'Lib/site-packages/password.py',
                     'Lib/__pycache__/private.pyc', 'Lib/credentials.json', 'tcl/tcl8.6/private.db',
                     'DLLs/private.pem']:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('SECRET', encoding='utf-8')

    def test_runtime_excludes_site_packages_and_private_data(self):
        items = portable.runtime_files(self.runtime)
        self.assertTrue(set(portable.REQUIRED_RUNTIME).issubset(items))
        self.assertFalse(any('site-packages' in x or 'private' in x or 'credentials' in x for x in items))
        self.assertFalse(any(x.endswith(('.json', '.db', '.pem', '.pyc')) for x in items))

    def test_portable_launcher_uses_copied_tcl_not_user_environment(self):
        helper_spec = importlib.util.spec_from_file_location('portable_launcher', ROOT / 'packaging' / 'portable_launcher.py')
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        env = {'TCL_LIBRARY': 'old', 'TK_LIBRARY': 'old', 'OTHER': 'keep'}
        prepared = helper.prepare_environment(self.runtime, env)
        self.assertEqual(prepared['TCL_LIBRARY'], str(self.runtime / 'tcl' / 'tcl8.6'))
        self.assertEqual(prepared['TK_LIBRARY'], str(self.runtime / 'tcl' / 'tk8.6'))
        self.assertEqual(env['TCL_LIBRARY'], 'old')
        self.assertEqual(prepared['OTHER'], 'keep')

    def test_tcl_index_files_are_included_without_file_extensions(self):
        for name in ('tcl/tcl8.6/tclIndex', 'tcl/tk8.6/tclIndex'):
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic index', encoding='utf-8')
        items = portable.runtime_files(self.runtime)
        self.assertIn('tcl/tcl8.6/tclIndex', items)
        self.assertIn('tcl/tk8.6/tclIndex', items)

    def test_missing_required_runtime_fails_before_output(self):
        (self.runtime / 'DLLs/_tkinter.pyd').unlink()
        with self.assertRaises(portable.PortableBuildError):
            portable.runtime_files(self.runtime)

    def test_existing_output_never_overwritten(self):
        destination = Path(self.temp.name) / 'existing'
        destination.mkdir()
        marker = destination / 'sentinel'
        marker.write_text('unchanged', encoding='utf-8')
        with self.assertRaises(portable.PortableBuildError):
            portable.build(self.runtime, destination, '0.1.0')
        self.assertEqual(marker.read_text(encoding='utf-8'), 'unchanged')


if __name__ == '__main__':
    unittest.main()
