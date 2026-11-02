import unittest
from src.browser.socks_relay_model import inspect_socks_exchange


class FixtureStream:
    def __init__(self, chunks, fail_send=False):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False
        self.fail_send = fail_send

    def sendall(self, data):
        if self.fail_send:
            raise OSError('synthetic transport failure')
        self.sent.append(data)

    def recv(self, size):
        if not self.chunks:
            return b''
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def close(self):
        self.closed = True


class SocksRelayModelTests(unittest.TestCase):
    def test_matching_socks5_exchange_is_only_candidate(self):
        stream = FixtureStream([b'\x05\x00', b'\x05\x00\x00\x01', b'\x7f\x00\x00\x01\x12\x34'])
        result = inspect_socks_exchange(stream, 'proxy.example', 44445)
        self.assertEqual(result.diagnostic, 'candidate')
        self.assertEqual(stream.sent, [b'\x05\x01\x00', b'\x05\x01\x00\x03\x0dproxy.example\xad\x9d'])
        self.assertTrue(stream.closed)
        self.assertEqual(result.proxy_status, 'unconfirmed')
        self.assertFalse(result.may_launch)

    def test_unavailable_or_rejected_socks_never_falls_back(self):
        for stream in [FixtureStream([], fail_send=True), FixtureStream([b'\x05\xff']),
                       FixtureStream([b'\x05\x00', b'\x05\x05\x00\x01']),
                       FixtureStream([b'\x05\x00', b'\x05\x00\x00\x01', b'\x7f'])]:
            with self.subTest(sent=stream.sent):
                result = inspect_socks_exchange(stream, 'proxy.example', 44445)
                self.assertEqual(result.diagnostic, 'rejected')
                self.assertTrue(stream.closed)
                self.assertFalse(result.may_launch)
                self.assertLessEqual(len(stream.sent), 2)

    def test_invalid_endpoint_rejected_without_sending(self):
        for host, port in [('', 44445), ('x' * 256, 44445), ('proxy.example', 0), ('bad host', 44445)]:
            stream = FixtureStream([])
            result = inspect_socks_exchange(stream, host, port)
            self.assertEqual(result.diagnostic, 'rejected')
            self.assertEqual(stream.sent, [])
            self.assertTrue(stream.closed)


if __name__ == '__main__':
    unittest.main()
