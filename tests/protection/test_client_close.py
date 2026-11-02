"""R30: in production forwarding, a connection the dedicated Chrome itself drops ends only that stream;
every other failure still closes the whole relay. All OS/network boundaries are injected."""
import socket
import unittest
from unittest.mock import patch

import test_worker_diagnostics as wd
from src.protection import session_relay as sr

CLIENT_CLOSED = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


class Sock(wd.FakeSocket):
    def __init__(self, role, recv=(), send_error=None, shutdown_error=None):
        super().__init__(role)
        self.items, self.send_error, self.shutdown_error = list(recv), send_error, shutdown_error

    def recv(self, *args):
        item = self.items.pop(0) if self.items else b''
        if isinstance(item, BaseException):
            raise item
        return item

    def send(self, data):
        if self.send_error is not None:
            raise self.send_error
        return len(data)

    def shutdown(self, how):
        if self.shutdown_error is not None and how == socket.SHUT_WR:
            raise self.shutdown_error


def scenario(side, operation, error):
    """Sockets whose `side` fails at `operation` (recv / send / half_close) with `error`."""
    other = 'upstream' if side == 'client' else 'client'
    failing = {'recv': dict(recv=[error('SECRET')]), 'send': dict(send_error=error('SECRET')),
               'half_close': dict(shutdown_error=error('SECRET'))}[operation]
    sockets = {side: Sock(side, **failing), other: Sock(other, recv=[b'x'] if operation == 'send' else [])}
    return sockets['client'], sockets['upstream']


class ClientCloseTests(unittest.TestCase):
    setUp = wd.WorkerDiagnosticTests.setUp
    relay = wd.WorkerDiagnosticTests.relay
    detail = wd.WorkerDiagnosticTests.detail

    def connect(self, relay, backend, client, upstream):
        binding = backend.binding
        relay._verifier = wd.SimpleNamespace(
            client=lambda *a: wd.ri.ClientProof(client.getpeername(), client.getsockname(), 102, 1001,
                binding.executable, binding.root_pid, binding.root_created, self.now[0]),
            listener=lambda *a: wd.ri.ProxyProof(backend.owner, self.now[0]),
            upstream=lambda *a: wd.ri.ProxyProof(backend.owner, self.now[0], upstream.getsockname(),
                                                 upstream.getpeername()))
        relay._sockets.add(client)
        relay._clients.add(client)
        select = lambda reads, writes, errors, timeout: (list(reads), list(writes), [])
        with patch.object(sr.socket, 'socket', return_value=upstream), patch.object(sr.select, 'select', select):
            relay._connection(client, relay._generation)

    def test_chrome_side_drop_ends_only_that_stream(self):
        stages = {'recv': 'client_recv', 'send': 'client_send', 'half_close': 'client_half_close'}
        for operation in stages:
            for error in CLIENT_CLOSED:
                with self.subTest(operation=operation, error=error.__name__):
                    relay, backend, _ = self.relay()
                    client, upstream = scenario('client', operation, error)
                    self.connect(relay, backend, client, upstream)
                    self.assertEqual((relay._state, relay._reason, relay._generation), ('listening', 'lease_active', 7))
                    self.assertFalse(relay._active_policy.revoked.is_set())
                    self.assertIsNone(self.detail(relay))
                    self.assertTrue(client.closed and upstream.closed)
                    self.assertNotIn(client, relay._clients)

    def test_relay_keeps_accepting_streams_after_repeated_chrome_drops(self):
        relay, backend, _ = self.relay()
        for _ in range(20):
            self.connect(relay, backend, *scenario('client', 'recv', ConnectionResetError))
        self.assertEqual(relay._state, 'listening')
        self.assertFalse(relay._clients)
        client, upstream = Sock('client', recv=[b'GET']), Sock('upstream', recv=[b'OK'])
        self.connect(relay, backend, client, upstream)
        self.assertEqual((relay._state, relay._reason), ('listening', 'lease_active'))

    def test_upstream_side_errors_still_close_whole_relay(self):
        stages = {'recv': 'upstream_recv', 'send': 'upstream_send', 'half_close': 'upstream_half_close'}
        codes = {ConnectionResetError: 'connection_reset', ConnectionAbortedError: 'connection_aborted',
                 BrokenPipeError: 'broken_pipe'}
        for operation, stage in stages.items():
            for error in CLIENT_CLOSED:
                with self.subTest(operation=operation, error=error.__name__):
                    relay, backend, _ = self.relay()
                    self.connect(relay, backend, *scenario('upstream', operation, error))
                    self.assertEqual((relay._state, relay._reason), ('closed', 'worker_error'))
                    self.assertTrue(relay._active_policy.revoked.is_set())
                    self.assertEqual((self.detail(relay).stage, self.detail(relay).error_code), (stage, codes[error]))

    def test_other_chrome_side_errors_still_close_whole_relay(self):
        for error in (TimeoutError, OSError, ConnectionRefusedError):
            with self.subTest(error=error.__name__):
                relay, backend, _ = self.relay()
                self.connect(relay, backend, *scenario('client', 'recv', error))
                self.assertEqual((relay._state, relay._reason), ('closed', 'worker_error'))
                self.assertTrue(relay._active_policy.revoked.is_set())

    def test_diagnostic_stream_drop_still_fails(self):
        relay, _, _ = self.relay()
        relay._state = 'diagnostic'
        client, upstream = scenario('client', 'recv', ConnectionResetError)
        select = lambda reads, writes, errors, timeout: (list(reads), list(writes), [])
        with patch.object(relay, '_connection_live', return_value=True), \
             patch.object(relay, '_budget', side_effect=lambda generation, wanted: wanted), \
             patch.object(relay, '_count_bytes', return_value=True), \
             patch.object(sr.select, 'select', select), self.assertRaises(ConnectionResetError):
            relay._pump(client, upstream, relay._generation)


if __name__ == '__main__':
    unittest.main()
