"""One-use local candidate channel; it cannot establish identity or proxy status."""
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import hmac
import hashlib
import json
import re
import secrets
import socket
import threading
import time
import uuid

_TARGET = 'https://claude.ai/cdn-cgi/trace'
_PATH = '/v1/evidence'
_CHALLENGE_PATH = '/v1/challenge?nonce='
_FIELDS = {'version', 'nonce', 'session_id', 'target', 'diagnostic', 'page_echo', 'target_request', 'proof'}
_active_guard = threading.Lock()


class BridgeBusy(Exception):
    pass


class BridgeInputError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class BridgeOffer:
    port: int
    token: str
    session_id: str

    def __repr__(self):
        return 'BridgeOffer(<redacted>)'

    def pairing_code(self):
        return f'{self.port}:{self.token}'


@dataclass(frozen=True)
class BridgeResult:
    diagnostic: str = 'unconfirmed'
    identity_status: str = 'unconfirmed'
    proxy_status: str = 'unconfirmed'
    may_launch: bool = False


def _uuid4(value):
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


class _Server(ThreadingMixIn, HTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args):
        self._connections = set()
        self._connection_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(4)
        self._accepting = True
        super().__init__(*args)

    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(3)
        with self._connection_lock:
            self._connections.add(conn)
            if not self._accepting:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return conn, addr

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            with self._connection_lock:
                self._connections.discard(request)

    def abort_requests(self):
        with self._connection_lock:
            self._accepting = False
            for conn in self._connections:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        pass


class _Handler(BaseHTTPRequestHandler):
    server_version = 'LocalEvidence'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _respond(self, code, accepted=False, proof=None):
        message = {'accepted': accepted, 'identity_status': 'unconfirmed',
                   'proxy_status': 'unconfirmed', 'may_launch': False}
        if proof is not None:
            message['proof'] = proof
        body = json.dumps(message, separators=(',', ':')).encode('ascii')
        self.send_response(code)
        if self.headers.get_all('Origin', []) == [self.server.bridge.origin]:
            self.send_header('Access-Control-Allow-Origin', self.server.bridge.origin)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _source_valid(self):
        return (self.client_address[0] == '127.0.0.1' and
                self.headers.get_all('Origin', []) == [self.server.bridge.origin] and
                self.headers.get_all('Host', []) == [f'127.0.0.1:{self.server.server_port}'] and
                not self.headers.get_all('Transfer-Encoding', []))

    def do_POST(self):
        bridge = self.server.bridge
        try:
            if (self.path != _PATH or not self._source_valid() or
                len(self.headers.get_all('Content-Length', [])) != 1 or
                len(self.headers.get_all('Content-Type', [])) != 1 or
                self.headers['Content-Type'].split(';', 1)[0].strip().lower() != 'text/plain'):
                bridge.reject()
                self._respond(403)
                return
            length_text = self.headers['Content-Length']
            if not re.fullmatch(r'[0-9]{1,4}', length_text) or not 1 <= int(length_text) <= 4096:
                bridge.reject()
                self._respond(403)
                return
            data = self.rfile.read(int(length_text))
            if len(data) != int(length_text):
                bridge.reject()
                self._respond(403)
                return
            payload = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))
            if bridge.accept(payload):
                self._respond(200, True)
            else:
                self._respond(403)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            bridge.reject()
            try:
                self._respond(403)
            except OSError:
                pass

    def do_GET(self):
        bridge = self.server.bridge
        nonce = self.path[len(_CHALLENGE_PATH):] if self.path.startswith(_CHALLENGE_PATH) else ''
        if not self._source_valid() or not _uuid4(nonce) or self.headers.get_all('Content-Length', []):
            bridge.reject()
            self._respond(403)
            return
        proof = bridge.issue_challenge(nonce)
        if proof is None:
            self._respond(403)
        else:
            self._respond(200, True, proof)


class EvidenceBridge:
    """Caller must supply the chosen extension ID and session ID; no OS identity is inferred."""
    def __init__(self, extension_id, session_id, *, ttl_seconds=60, clock=time.monotonic):
        if (not isinstance(extension_id, str) or not re.fullmatch(r'[a-p]{32}', extension_id)
                or not _uuid4(session_id) or type(ttl_seconds) not in (int, float)
                or not 0 < ttl_seconds <= 60 or not callable(clock)):
            raise BridgeInputError('扩展、会话或有效期不正确。')
        self.origin = 'chrome-extension://' + extension_id
        self._session_id = session_id
        self._ttl = ttl_seconds
        self._clock = clock
        self._mutex = threading.Lock()
        self._lifecycle_mutex = threading.Lock()
        self._server = None
        self._thread = None
        self._timer = None
        self._token = None
        self._candidate = False
        self._nonce = None
        self._failures = 0
        self._issued = None
        self._owns_guard = False
        self._closed = False

    @classmethod
    def from_invitation(cls, invitation, **options):
        if not isinstance(invitation, str):
            raise BridgeInputError('邀请信息不正确。')
        match = re.fullmatch(r'([a-p]{32})\.([0-9a-f-]{36})', invitation)
        if not match:
            raise BridgeInputError('邀请信息不正确。')
        return cls(match.group(1), match.group(2), **options)

    def start(self):
        with self._lifecycle_mutex:
            if self._server is not None or self._closed or not _active_guard.acquire(blocking=False):
                raise BridgeBusy('已有活动通道或此通道不可重启。')
            self._owns_guard = True
            thread_started = False
            try:
                self._issued = self._clock()
                self._token = secrets.token_urlsafe(32)
                self._server = _Server(('127.0.0.1', 0), _Handler)
                self._server.bridge = self
                self._thread = threading.Thread(target=self._server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
                self._thread.start()
                thread_started = True
                self._timer = threading.Timer(self._ttl, self.close)
                self._timer.daemon = True
                self._timer.start()
                return BridgeOffer(self._server.server_port, self._token, self._session_id)
            except Exception:
                if self._server is not None:
                    if thread_started:
                        self._server.abort_requests()
                        self._server.shutdown()
                        self._thread.join()
                    self._server.server_close()
                self._token = None
                self._server = None
                self._owns_guard = False
                _active_guard.release()
                raise

    def _fresh(self):
        now = self._clock()
        return self._issued is not None and self._issued <= now <= self._issued + self._ttl

    def reject(self):
        with self._mutex:
            self._failures += 1
            if self._failures >= 5 or not self._fresh():
                self._token = None
                self._candidate = False

    def issue_challenge(self, nonce):
        with self._mutex:
            if not self._fresh() or self._token is None or self._nonce is not None:
                return None
            self._nonce = nonce
            message = f'bridge-v1|server|{nonce}|{self._session_id}'
            return hmac.new(self._token.encode('ascii'), message.encode('utf-8'), hashlib.sha256).hexdigest()

    def accept(self, payload):
        with self._mutex:
            if not self._fresh():
                self._token = None
                self._candidate = False
                return False
            ok = (self._token is not None and self._nonce is not None
                  and isinstance(payload, dict) and set(payload) == _FIELDS
                  and type(payload['version']) is int and payload['version'] == 1
                  and payload['nonce'] == self._nonce and payload['session_id'] == self._session_id
                  and payload['target'] == _TARGET and payload['diagnostic'] == 'candidate'
                  and payload['page_echo'] == 'seen' and payload['target_request'] == 'observed'
                  and isinstance(payload['proof'], str) and re.fullmatch(r'[0-9a-f]{64}', payload['proof']) is not None)
            if ok:
                message = f'bridge-v1|client|{self._nonce}|{self._session_id}|{_TARGET}|candidate|seen|observed'
                expected = hmac.new(self._token.encode('ascii'), message.encode('utf-8'), hashlib.sha256).hexdigest()
                ok = hmac.compare_digest(payload['proof'], expected)
            if not ok:
                self._failures += 1
                if self._failures >= 5:
                    self._token = None
                    self._candidate = False
                return False
            self._token = None
            self._nonce = None
            self._candidate = True
            return True

    def result(self):
        with self._mutex:
            if self._issued is None or not self._fresh():
                self._token = None
                self._candidate = False
            return BridgeResult('candidate' if self._candidate else 'unconfirmed')

    def close(self):
        with self._lifecycle_mutex:
            with self._mutex:
                self._token = None
                self._candidate = False
                self._nonce = None
                self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if self._server is not None:
                self._server.abort_requests()
                self._server.shutdown()
                self._server.server_close()
                if self._thread is not None:
                    self._thread.join()
                self._server = None
            if self._owns_guard:
                self._owns_guard = False
                _active_guard.release()

    def cancel(self):
        self.close()
