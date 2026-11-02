import inspect
import threading
import time
import unittest
from unittest.mock import patch
from src.core import backend


class DetectionCancellationTests(unittest.TestCase):
    def test_stop_between_steps_does_not_begin_another_network_check(self):
        self.assertIn('cancelled', inspect.signature(backend.detect).parameters,
                      '检测没有生产取消边界')
        event = threading.Event()
        config = backend.Config(25001, 25002, '203.0.113.1', 'https://example.test/ip')
        def first(*args):
            event.set()
            return backend.Check('pass', '合成')
        with patch.object(backend, '_proxy_owner_snapshot', return_value=(1, 2)), \
                patch.object(backend, '_manager', first), \
                patch.object(backend, '_port', side_effect=AssertionError('取消后启动下一次网络检查')):
            with self.assertRaises(backend.DetectionCancelled):
                backend.detect(config, deadline=time.monotonic()+1, cancelled=event)


if __name__ == '__main__':
    unittest.main()
