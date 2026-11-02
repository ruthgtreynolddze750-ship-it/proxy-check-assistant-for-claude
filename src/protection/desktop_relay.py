"""Loopback relay for one protected desktop launch (R33).

The listener lives for the whole protection session because the desktop's
--proxy-server port is fixed at launch. A fuse only pauses forwarding: every stream
is closed and new connections are refused until a fresh lease arrives.
"""
from dataclasses import dataclass
import math
import select
import socket
import threading
import time

from src.core.backend import Config
from .relay_identity import ProxyProof, WindowsRelayVerifier
from .session_relay import _CLIENT_DROPPED, _close_socket


@dataclass(frozen=True)
class DesktopRelaySnapshot:
    state: str          # reserved / forwarding / paused / closed
    reason_code: str
    active_connections: int
    port: int | None
    rejected_connections: int = 0


class DesktopRelay:
    MAX_CLIENTS = 64

    def __init__(self, config, *, admit, verifier=None, max_lease_seconds=2.0, clock=time.monotonic):
        if (not isinstance(config, Config) or type(config.proxy_port) is not int
                or not 0 < config.proxy_port <= 65535 or not callable(admit)
                or type(max_lease_seconds) not in (int, float) or not math.isfinite(max_lease_seconds)
                or not 0 < max_lease_seconds <= 2):
            raise ValueError('桌面端转发参数无效')
        self._config, self._admit = config, admit
        self._verifier = WindowsRelayVerifier() if verifier is None else verifier
        self._max_lease, self._clock = max_lease_seconds, clock
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._listener = None
        self._port = None
        self._clients, self._sockets = set(), set()
        self._state, self._reason = 'unbound', 'not_started'
        self._deadline = None
        self._owner = None
        self._generation = 0
        self._rejected = 0

    def snapshot(self):
        with self._lock:
            return DesktopRelaySnapshot(self._state, self._reason, len(self._clients), self._port, self._rejected)

    @property
    def port(self):
        return self._port

    def reserve(self):
        with self._lock:
            if self._state != 'unbound':
                raise ValueError('桌面端转发口已预留')
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                listener.bind(('127.0.0.1', 0))
                listener.settimeout(0.05)
                listener.listen(self.MAX_CLIENTS)
            except BaseException:
                _close_socket(listener)
                raise
            self._listener, self._port = listener, listener.getsockname()[1]
            self._state, self._reason = 'reserved', 'port_reserved_no_forwarding'
        threading.Thread(target=self._watch, name='desktop-relay-watch', daemon=True).start()
        threading.Thread(target=self._accept, name='desktop-relay-accept', daemon=True).start()
        return self._port

    def authorize(self, deadline, owner, *, new_owner=False):
        """Open or extend forwarding until deadline (capped by the lease limit); False if not allowed.

        new_owner adopts a re-verified Proxy Manager, and only while forwarding is paused.
        """
        now = self._clock()
        if (type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= now
                or not isinstance(owner, tuple)):
            return False
        with self._lock:
            if self._state not in ('reserved', 'paused', 'forwarding'):
                return False
            if (self._owner is not None and owner != self._owner
                    and not (new_owner and self._state == 'paused')):
                self._pause_locked('proxy_owner_changed')
                return False
            self._owner = owner
            self._deadline = min(deadline, now + self._max_lease)
            if self._state != 'forwarding':
                self._generation += 1
                self._state, self._reason = 'forwarding', 'lease_active'
            return True

    def _pause_locked(self, reason):
        if self._state in ('closed', 'unbound'):
            return
        self._state, self._reason = 'paused', reason
        self._deadline = None
        self._generation += 1
        sockets = tuple(self._sockets)
        self._sockets.clear()
        self._clients.clear()
        for sock in sockets:
            _close_socket(sock)

    def pause(self, reason):
        with self._lock:
            if self._state in ('forwarding', 'reserved', 'paused'):
                self._pause_locked(reason)

    def close(self, reason='stopped'):
        with self._lock:
            if self._state == 'closed':
                return
            self._pause_locked(reason)
            self._state = 'closed'
            listener, self._listener = self._listener, None
            self._closed.set()
        if listener is not None:
            _close_socket(listener)

    def _live_locked(self, generation=None):
        if self._state != 'forwarding' or (generation is not None and generation != self._generation):
            return False
        if self._clock() >= self._deadline:
            self._pause_locked('lease_expired')
            return False
        return True

    def _live(self, generation=None):
        with self._lock:
            return self._live_locked(generation)

    def _pause_generation(self, reason, generation):
        with self._lock:
            if generation == self._generation and self._state == 'forwarding':
                self._pause_locked(reason)

    def _watch(self):
        try:
            while not self._closed.wait(0.01):
                self._live()
        except BaseException:
            self.pause('watchdog_error')

    def _accept(self):
        try:
            while not self._closed.is_set():
                with self._lock:
                    listener = self._listener
                if listener is None:
                    return
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._closed.is_set():
                        return
                    raise
                with self._lock:
                    if not self._live_locked() or len(self._clients) >= self.MAX_CLIENTS:
                        self._rejected = min(self._rejected + 1, 2**31 - 1)
                        _close_socket(client)
                        continue
                    self._sockets.add(client)
                    self._clients.add(client)
                    generation = self._generation
                threading.Thread(target=self._connection, args=(client, generation),
                                 name='desktop-relay-stream', daemon=True).start()
        except BaseException:
            if not self._closed.is_set():
                self.pause('acceptor_error')

    def _connection(self, client, generation):
        upstream = None
        try:
            if not self._admit(client.getpeername(), client.getsockname()) or not self._live(generation):
                with self._lock:
                    self._rejected = min(self._rejected + 1, 2**31 - 1)
                return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self._lock:
                if not self._live_locked(generation):
                    return
                self._sockets.add(upstream)
                upstream.settimeout(min(2.0, max(0.001, self._deadline - self._clock())))
                owner = self._owner
            upstream.connect(('127.0.0.1', self._config.proxy_port))
            proof = self._verifier.upstream(self._config, upstream)
            if (not isinstance(proof, ProxyProof) or proof.owner != owner
                    or proof.server_endpoint != ('127.0.0.1', self._config.proxy_port)
                    or proof.client_endpoint != upstream.getsockname()):
                self._pause_generation('upstream_unconfirmed', generation)
                return
            self._pump(client, upstream, generation)
        except BaseException:
            self._pause_generation('worker_error', generation)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    _close_socket(sock)
            with self._lock:
                self._sockets.discard(client)
                self._sockets.discard(upstream)
                self._clients.discard(client)

    def _pump(self, client, upstream, generation):
        # As R30: the desktop dropping one of its own streams ends only that stream; upstream errors fuse.
        sockets = (client, upstream)
        for sock in sockets:
            sock.setblocking(False)
        pending = {client: bytearray(), upstream: bytearray()}
        reading = set(sockets)
        write_closed = set()
        while self._live(generation):
            for source, destination in ((client, upstream), (upstream, client)):
                if source not in reading and not pending[destination] and destination not in write_closed:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except _CLIENT_DROPPED:
                        if destination is not client:
                            raise
                        return
                    write_closed.add(destination)
            if not reading and not any(pending.values()):
                return
            readable = [s for s in reading if len(pending[upstream if s is client else client]) < 65536]
            writable = [s for s in sockets if pending[s]]
            ready_read, ready_write, errors = select.select(readable, writable, sockets, 0.01)
            if errors or not self._live(generation):
                return
            for source in ready_read:
                destination = upstream if source is client else client
                try:
                    data = source.recv(65536 - len(pending[destination]))
                except BlockingIOError:
                    continue
                except _CLIENT_DROPPED:
                    if source is not client:
                        raise
                    return
                if data:
                    pending[destination].extend(data)
                else:
                    reading.discard(source)
            for destination in ready_write:
                try:
                    sent = destination.send(pending[destination])
                except BlockingIOError:
                    continue
                except _CLIENT_DROPPED:
                    if destination is not client:
                        raise
                    return
                if sent <= 0:
                    return
                del pending[destination][:sent]
