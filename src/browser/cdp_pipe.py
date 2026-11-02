"""Bounded CDP JSON framing over inherited anonymous Windows pipe handles."""
import json
import os
import subprocess
import threading
import time


class ProbeError(RuntimeError):
    """Only fixed reason codes may cross the browser boundary."""


_SPAWN_LOCK = threading.Lock()
MAX_MESSAGE = 65536
PROFILE_EXPRESSION = "document.getElementById('profile_path')?.textContent"
PROFILE_EVALUATION = {
    'expression': PROFILE_EXPRESSION, 'returnByValue': True, 'generatePreview': False,
    'includeCommandLineAPI': False, 'userGesture': False, 'awaitPromise': False,
    'throwOnSideEffect': False, 'allowUnsafeEvalBlockedByCSP': False,
    'replMode': False, 'timeout': 250,
}


def _profile_read_error(reason, reply):
    def shape(container, key):
        if key not in container:
            return 'missing'
        return {dict: 'object', list: 'array', str: 'string', int: 'number', float: 'number',
                bool: 'boolean', type(None): 'null'}.get(type(container[key]), 'other')

    value = reply.get('result')
    value = value if isinstance(value, dict) else {}
    details = reply.get('exceptionDetails')
    details = details if isinstance(details, dict) else {}
    exception = details.get('exception')
    exception = exception if isinstance(exception, dict) else value
    remote_type, error_class = value.get('type'), exception.get('className')
    text, description = details.get('text'), exception.get('description')
    # These flags report fixed text markers, not an inferred cause or raw exception content.
    markers = '\n'.join(item.casefold() for item in (text, description) if isinstance(item, str))
    error = ProbeError(reason)
    error.profile_read_diagnostic = {
        'branch': ('exception_details' if 'exceptionDetails' in reply else
                   'remote_object_shape' if reason == 'profile_read_rejected' else 'value_contract'),
        'remote_object_shape': shape(reply, 'result'),
        'remote_type': remote_type if remote_type in ('object', 'function', 'undefined', 'string',
            'number', 'boolean', 'symbol', 'bigint') else 'missing' if 'type' not in value else 'other',
        'value_shape': shape(value, 'value'),
        'value_length': len(value['value']) if isinstance(value.get('value'), str) else None,
        'object_id_present': 'objectId' in value,
        'exception_details_shape': shape(reply, 'exceptionDetails'),
        'exception_class': error_class if error_class in ('Error', 'EvalError', 'RangeError',
            'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'AggregateError', 'DOMException')
            else 'missing' if 'className' not in exception else 'other',
        'exception_text_length': len(text) if isinstance(text, str) else None,
        'exception_description_length': len(description) if isinstance(description, str) else None,
        'csp_marker_present': 'content security policy' in markers or 'unsafe-eval' in markers,
        'side_effect_marker_present': 'possible side-effect in debug-evaluate' in markers,
    }
    return error


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError('duplicate_protocol_key')
        result[key] = value
    return result


class PipeTransport:
    def __init__(self, read_fd, write_fd):
        self._read, self._write = read_fd, write_fd
        self._buffer = bytearray()
        self._closed = False
        self._lock = threading.Lock()
        self.cancelled = None
        os.set_blocking(read_fd, False)
        os.set_blocking(write_fd, False)

    def send(self, message, deadline):
        payload = json.dumps(message, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode() + b'\0'
        if len(payload) > 4096:
            raise ProbeError('command_too_large')
        offset = 0
        while offset < len(payload):
            if self.cancelled is not None and self.cancelled.is_set():
                raise ProbeError('protocol_cancelled')
            if time.monotonic() >= deadline:
                raise ProbeError('pipe_timeout')
            with self._lock:
                if self._closed:
                    raise ProbeError('pipe_closed')
                try:
                    offset += os.write(self._write, payload[offset:])
                except BlockingIOError:
                    pass
                except OSError:
                    raise ProbeError('pipe_write_failed') from None
            if offset < len(payload):
                time.sleep(.005)

    def receive(self, deadline):
        while time.monotonic() < deadline:
            if self.cancelled is not None and self.cancelled.is_set():
                raise ProbeError('protocol_cancelled')
            with self._lock:
                if self._closed:
                    raise ProbeError('pipe_closed')
                boundary = self._buffer.find(0)
                if boundary >= 0:
                    raw = bytes(self._buffer[:boundary])
                    del self._buffer[:boundary+1]
                    try:
                        message = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                        if not isinstance(message, dict):
                            raise ValueError()
                        return message
                    except (ValueError, UnicodeError, RecursionError):
                        raise ProbeError('invalid_protocol_message') from None
                try:
                    part = os.read(self._read, min(4096, MAX_MESSAGE + 1 - len(self._buffer)))
                    if not part:
                        raise ProbeError('pipe_disconnected')
                    self._buffer.extend(part)
                    if len(self._buffer) > MAX_MESSAGE:
                        raise ProbeError('protocol_message_too_large')
                except BlockingIOError:
                    pass
                except OSError:
                    raise ProbeError('pipe_read_failed') from None
            time.sleep(.005)
        raise ProbeError('pipe_timeout')

    def close(self):
        with self._lock:
            self._closed = True
            self._buffer.clear()
            errors = []
            for name in ('_read', '_write'):
                descriptor = getattr(self, name)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                        setattr(self, name, None)
                    except BaseException as error:
                        errors.append(error)
            if errors:
                failure = errors[0]
                failure.cleanup_errors = tuple(errors)
                if len(errors) > 1:
                    failure.add_note('additional_pipe_close_failed:' + type(errors[1]).__name__)
                raise failure


def spawn_with_pipe(arguments):
    """Internal primitive. The caller must authorize the owned child lifecycle."""
    if os.name != 'nt':
        raise ProbeError('windows_required')
    import msvcrt
    child_read, parent_write = os.pipe()
    parent_read, child_write = os.pipe()
    remaining = {child_read, parent_write, parent_read, child_write}
    try:
        read_handle, write_handle = (msvcrt.get_osfhandle(fd) for fd in (child_read, child_write))
        if not all(0 < handle <= 0xffffffff for handle in (read_handle, write_handle)):
            raise ProbeError('pipe_handle_out_of_range')
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {'handle_list': [read_handle, write_handle]}
        transport = PipeTransport(parent_read, parent_write)
        with _SPAWN_LOCK:
            os.set_handle_inheritable(read_handle, True)
            os.set_handle_inheritable(write_handle, True)
            try:
                process = subprocess.Popen(arguments(read_handle, write_handle), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           close_fds=True, startupinfo=startup,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
            finally:
                os.set_handle_inheritable(read_handle, False)
                os.set_handle_inheritable(write_handle, False)
        os.close(child_read)
        remaining.remove(child_read)
        os.close(child_write)
        remaining.remove(child_write)
        remaining.clear()
        return process, transport
    except (OSError, ValueError, TypeError):
        raise ProbeError('pipe_spawn_failed') from None
    finally:
        for fd in remaining:
            os.close(fd)


class CdpChannel:
    def __init__(self, transport):
        self.transport = transport
        self.on_event = None
        self._next = 0
        self._pending = {}
        self._replies = {}
        self._events = 0
        self.cancelled = None

    def send(self, method, params, deadline, session_id=None, *, wait=False):
        if self.cancelled is not None and self.cancelled.is_set():
            raise ProbeError('protocol_cancelled')
        if time.monotonic() >= deadline:
            raise ProbeError('protocol_timeout')
        if method == 'Runtime.evaluate':
            unique = params.get('uniqueContextId') if isinstance(params, dict) else None
            if (not isinstance(unique, str) or not 0 < len(unique) <= 256 or not session_id
                    or params != dict(PROFILE_EVALUATION, uniqueContextId=unique)):
                raise ProbeError('profile_expression_required')
        self._next += 1
        if len(self._pending) >= 16:
            raise ProbeError('too_many_pending_commands')
        message = {'id': self._next, 'method': method, 'params': params}
        if session_id is not None:
            message['sessionId'] = session_id
        self._pending[self._next] = (session_id, wait)
        self.transport.send(message, deadline)
        return self._next

    def pump(self, deadline):
        if self.cancelled is not None and self.cancelled.is_set():
            raise ProbeError('protocol_cancelled')
        if time.monotonic() >= deadline:
            raise ProbeError('protocol_timeout')
        try:
            message = self.transport.receive(deadline)
        except (OSError, ValueError, TimeoutError):
            raise ProbeError('protocol_read_failed') from None
        if 'id' in message:
            command_id = message['id']
            if type(command_id) is not int or command_id not in self._pending:
                raise ProbeError('unexpected_protocol_reply')
            session, wait = self._pending.pop(command_id)
            if message.get('sessionId') != session:
                raise ProbeError('protocol_session_mismatch')
            if 'error' in message or not isinstance(message.get('result'), dict):
                raise ProbeError('protocol_command_rejected')
            if wait:
                self._replies[command_id] = message['result']
        elif isinstance(message.get('method'), str):
            self._events += 1
            if self._events > 512:
                raise ProbeError('protocol_event_limit')
            if self.on_event:
                self.on_event(message)
        else:
            raise ProbeError('invalid_protocol_message')

    def command(self, method, params, deadline, session_id=None):
        key = self.send(method, params, deadline, session_id, wait=True)
        while key not in self._replies:
            self.pump(deadline)
        return self._replies.pop(key)

    def flush(self, deadline):
        while self._pending:
            self.pump(deadline)

    def read_profile_path(self, unique_context_id, deadline, session_id):
        result = self.command('Runtime.evaluate',
            dict(PROFILE_EVALUATION, uniqueContextId=unique_context_id), deadline, session_id)
        value = result.get('result', {})
        if 'exceptionDetails' in result or not isinstance(value, dict):
            raise _profile_read_error('profile_read_rejected', result)
        if value.get('type') == 'undefined':
            return ''
        text = value.get('value')
        if (value.get('type') != 'string' or not isinstance(text, str) or len(text) > 4096
                or 'objectId' in value):
            raise _profile_read_error('profile_read_invalid', result)
        return text
