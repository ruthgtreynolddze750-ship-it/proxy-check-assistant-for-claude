"""Fail-closed primitives for a native-host integration prototype."""
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import ntpath
import re
import secrets
import struct
import threading
import time
import uuid

TARGET = 'https://claude.ai/cdn-cgi/trace'
MAX_FRAME = 4096


@dataclass(frozen=True, repr=False)
class ProcessRef:
    pid: int
    created: int

    def __repr__(self):
        return 'ProcessRef(<redacted>)'


@dataclass(frozen=True, repr=False)
class ProcessNode:
    pid: int
    created: int
    parent_pid: int
    image: str

    def __repr__(self):
        return 'ProcessNode(<redacted>)'


@dataclass(frozen=True, repr=False)
class BindingOffer:
    session_id: str
    secret: bytes

    def __repr__(self):
        return 'BindingOffer(<redacted>)'


@dataclass(frozen=True)
class BindingResult:
    transport: str = 'unknown'
    identity_status: str = 'unknown'
    request_status: str = 'unknown'
    proxy_status: str = 'unknown'
    may_launch: bool = False


def new_profile_marker():
    return secrets.token_hex(32)


def _extension_id(value):
    return isinstance(value, str) and re.fullmatch(r'[a-p]{32}', value) is not None


def _uuid4(value):
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _valid_ref(value):
    return (isinstance(value, ProcessRef) and type(value.pid) is int and value.pid > 0 and
            type(value.created) is int and value.created > 0)


def _valid_chain(chain, selected):
    if not isinstance(chain, (tuple, list)) or not 2 <= len(chain) <= 8:
        return False
    if not all(isinstance(x, ProcessNode) and type(x.pid) is int and x.pid > 0 and
               type(x.created) is int and x.created > 0 and type(x.parent_pid) is int and
               x.parent_pid >= 0 and isinstance(x.image, str) and x.image for x in chain):
        return False
    if len({x.pid for x in chain}) != len(chain):
        return False
    for child, parent in zip(chain, chain[1:]):
        if child.parent_pid != parent.pid or parent.created > child.created:
            return False
    browsers = [x for x in chain[1:] if x.image.casefold() == 'chrome.exe']
    return (len(browsers) == 1 and browsers[0].pid == selected.pid and
            browsers[0].created == selected.created)


def binding_proof(secret, extension_id, session_id, marker, request_id, target, browser):
    if not isinstance(secret, bytes) or len(secret) != 32 or not _valid_ref(browser):
        raise ValueError('invalid proof inputs')
    message = f'native-v1|{extension_id}|{session_id}|{marker}|{request_id}|{target}|{browser.pid}|{browser.created}'
    return hmac.new(secret, message.encode('utf-8'), hashlib.sha256).hexdigest()


class BindingSession:
    """Candidate correlation only; caller assertions are not browser attestations."""
    def __init__(self, extension_id, profile_marker, browser, *, consent=False, clock=time.monotonic, ttl_seconds=60):
        if (consent is not True or not _extension_id(extension_id) or not isinstance(profile_marker, str) or
                re.fullmatch(r'[0-9a-f]{64}', profile_marker) is None or not _valid_ref(browser) or
                not callable(clock) or type(ttl_seconds) not in (int, float) or not 0 < ttl_seconds <= 60):
            raise ValueError('invalid binding inputs')
        self._id = extension_id
        self._marker = profile_marker
        self._browser = browser
        self._clock = clock
        self._issued = clock()
        self._ttl = ttl_seconds
        self._session_id = str(uuid.uuid4())
        self._secret = secrets.token_bytes(32)
        self._offered = False
        self._lock = threading.Lock()
        self._timer = threading.Timer(ttl_seconds, self.close)
        self._timer.daemon = True
        try:
            self._timer.start()
        except Exception:
            self._secret = None
            raise

    def offer(self):
        with self._lock:
            try:
                now = self._clock()
                fresh = math.isfinite(self._issued) and math.isfinite(now) and 0 <= now - self._issued <= self._ttl
            except (TypeError, ValueError, OverflowError, OSError, RuntimeError):
                fresh = False
            if self._offered or self._secret is None or not fresh:
                if not fresh:
                    self._secret = None
                    if self._timer is not None:
                        self._timer.cancel()
                        self._timer = None
                raise ValueError('binding offer unavailable')
            self._offered = True
            return BindingOffer(self._session_id, self._secret)

    def attempt(self, *, origin, session_id, profile_marker, request_id, target, proof, chain_before, chain_after):
        with self._lock:
            secret, self._secret = self._secret, None
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            try:
                now = self._clock()
                ok = (self._offered and secret is not None and math.isfinite(self._issued) and math.isfinite(now)
                      and 0 <= now - self._issued <= self._ttl and origin == f'chrome-extension://{self._id}/'
                      and session_id == self._session_id and profile_marker == self._marker and _uuid4(request_id)
                      and target == TARGET and isinstance(proof, str) and re.fullmatch(r'[0-9a-f]{64}', proof)
                      and chain_before == chain_after and _valid_chain(chain_before, self._browser))
                if ok:
                    expected = binding_proof(secret, self._id, session_id, profile_marker, request_id, target, self._browser)
                    ok = hmac.compare_digest(proof, expected)
                return BindingResult('candidate' if ok else 'unknown')
            except (TypeError, ValueError, OverflowError, OSError, RuntimeError):
                return BindingResult()

    def close(self):
        with self._lock:
            self._secret = None
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


def host_manifest(executable, extension_id):
    if (not _extension_id(extension_id) or not isinstance(executable, str) or
            not re.match(r'^[A-Za-z]:[\\/]', executable) or
            ':' in ntpath.splitdrive(executable)[1] or
            any(ord(c) < 32 or c in '%"' for c in executable) or
            any(p == '..' for p in re.split(r'[\\/]', executable)) or
            ntpath.splitext(executable)[1].casefold() != '.exe'):
        raise ValueError('invalid host executable or extension id')
    return {'name': 'org.claude_detector.observer', 'description': 'Offline research prototype',
            'path': ntpath.normpath(executable), 'type': 'stdio',
            'allowed_origins': [f'chrome-extension://{extension_id}/']}


def _read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def read_frame(stream):
    header = _read_exact(stream, 4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError('truncated header')
    size = struct.unpack('<I', header)[0]
    if not 1 <= size <= MAX_FRAME:
        raise ValueError('invalid frame length')
    body = _read_exact(stream, size)
    if len(body) != size:
        raise ValueError('truncated frame')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))
        if not isinstance(value, dict):
            raise ValueError('message must be an object')
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError('invalid frame') from exc


def write_frame(stream, value):
    raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    if not 1 <= len(raw) <= MAX_FRAME:
        raise ValueError('invalid output length')
    stream.write(struct.pack('<I', len(raw)) + raw)
    if hasattr(stream, 'flush'):
        stream.flush()
