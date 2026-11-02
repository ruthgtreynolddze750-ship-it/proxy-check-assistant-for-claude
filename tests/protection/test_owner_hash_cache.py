"""R32: the fast guard reuses the manager executable digest while the file identity is unchanged."""
from contextlib import contextmanager
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.core import backend
from src.protection import relay_identity as identity


class OwnerHashCacheTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.exe = Path(directory.name) / 'pm.exe'
        self.exe.write_bytes(b'proxy-manager-v1')
        self.config = SimpleNamespace(manager_executable=str(self.exe), manager_port=22999, proxy_port=24001,
                                      manager_sha256=hashlib.sha256(b'proxy-manager-v1').hexdigest())
        getattr(identity, '_HASH_CACHE', {}).clear()
        self.addCleanup(lambda: getattr(identity, '_HASH_CACHE', {}).clear())

        @contextmanager
        def process(pid):
            yield {'path': str(self.exe), 'created': '900'}
        self.enterContext(patch.object(identity, '_tcp_rows', return_value=[]))
        self.enterContext(patch.object(identity, '_listener_pid', return_value=501))
        self.enterContext(patch.object(identity, '_process', process))
        self.hash = self.enterContext(patch.object(identity, '_file_sha256', side_effect=backend._file_sha256))

    def test_unchanged_file_is_hashed_once(self):
        owners = [identity._native_proxy_owner(self.config) for _ in range(5)]
        self.assertIsNotNone(owners[0])
        self.assertEqual(owners, [owners[0]] * 5)
        self.assertEqual(self.hash.call_count, 1)

    def test_changed_file_is_rehashed_and_rejected(self):
        self.assertIsNotNone(identity._native_proxy_owner(self.config))
        self.exe.write_bytes(b'proxy-manager-v2-other-size')
        self.assertIsNone(identity._native_proxy_owner(self.config))
        self.assertEqual(self.hash.call_count, 2)

    def test_same_size_content_change_with_new_mtime_is_rehashed(self):
        self.assertIsNotNone(identity._native_proxy_owner(self.config))
        self.exe.write_bytes(b'proxy-manager-v9')
        stat = self.exe.stat()
        os.utime(self.exe, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10**9))
        self.assertIsNone(identity._native_proxy_owner(self.config))
        self.assertEqual(self.hash.call_count, 2)

    def test_file_changed_while_hashing_is_not_cached(self):
        def hash_then_change(path):
            digest = backend._file_sha256(path)
            self.exe.write_bytes(b'proxy-manager-v1-and-more')
            return digest
        self.hash.side_effect = hash_then_change
        self.assertIsNone(identity._native_proxy_owner(self.config))
        self.assertEqual(getattr(identity, '_HASH_CACHE', {}), {})

    def test_wrong_configured_digest_stays_unconfirmed(self):
        config = SimpleNamespace(**{**vars(self.config), 'manager_sha256': 'b' * 64})
        self.assertIsNone(identity._native_proxy_owner(config))
        self.assertIsNone(identity._native_proxy_owner(config))
        self.assertIsNotNone(identity._native_proxy_owner(self.config))

    def test_stat_failure_is_unconfirmed(self):
        self.assertIsNotNone(identity._native_proxy_owner(self.config))
        with patch.object(identity.os, 'stat', side_effect=OSError('denied')):
            self.assertIsNone(identity._native_proxy_owner(self.config))

    def test_manager_sample_still_hashes_every_time(self):
        rows = [{'pid': 501, 'started': '900', 'path': str(self.exe)}]
        with patch.object(backend, '_capture_listener_owners', return_value=(rows, rows)), \
                patch.object(backend, '_file_sha256', side_effect=backend._file_sha256) as full:
            self.assertIsNotNone(backend._proxy_owner_snapshot(self.config))
            self.assertIsNotNone(backend._proxy_owner_snapshot(self.config))
        self.assertEqual(full.call_count, 2)


if __name__ == '__main__':
    unittest.main()
