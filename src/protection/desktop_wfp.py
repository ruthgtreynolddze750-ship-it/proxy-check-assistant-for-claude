"""Explicit-plan WFP rules for one protected Claude desktop launch (R33); no import effects.

Same four block rules as the dedicated Chrome plan, once per desktop executable. The
dedicated Chrome module is reused only for its native engine and exact object matching.
"""
from dataclasses import asdict, dataclass, field
import hashlib
import ipaddress
import json
import math
import ntpath
import os
import stat
import threading
import uuid

from src.browser.shortcut_selection import _fixed_local_path, _without_links
from .dedicated_wfp import (V4, V6, APP_ID, PROTOCOL, ADDRESS, PORT, EQUAL, NOT_EQUAL, UINT8, UINT16,
                            UINT32, BLOB, FWP_ACTION_BLOCK, PERSISTENT, SUBLAYER_WEIGHT, FILTER_WEIGHT,
                            PolicyError, NativeWfp, _check_capabilities, _matches_object, _read_exact)


PROJECT_NAMESPACE = uuid.UUID('f1a80def-ba82-433b-ace5-3651acfbbef4')
ROLES = ('desktop', 'claude_code')
JOURNAL_SCHEMA = 1


@dataclass(frozen=True)
class DesktopApp:
    role: str
    executable: str = field(repr=False)
    file_identity: tuple = field(repr=False)
    sha256: str
    app_id: bytes = field(repr=False)


@dataclass(frozen=True)
class DesktopPolicyPlan:
    apps: tuple
    relay_port: int
    deployment_id: str
    sublayer_weight: int = SUBLAYER_WEIGHT
    source: str = 'windows_wfp'

    @property
    def digest(self):
        body = json.dumps(asdict(self), sort_keys=True, separators=(',', ':'),
                          default=lambda value: value.hex()).encode('utf-8')
        return hashlib.sha256(b'claude-desktop-wfp/v1\0' + body).hexdigest()

    @property
    def executables(self):
        return tuple(app.executable for app in self.apps)


@dataclass(frozen=True)
class PlanApproval:
    plan_digest: str
    action: str


def path_key(value):
    return ntpath.normcase(ntpath.normpath(value))


def _check_plan(plan):
    if (not isinstance(plan, DesktopPolicyPlan) or type(plan.relay_port) is not int
            or not 1 <= plan.relay_port <= 65535 or type(plan.sublayer_weight) is not int
            or not SUBLAYER_WEIGHT <= plan.sublayer_weight < SUBLAYER_WEIGHT + 256
            or plan.source not in ('windows_wfp', 'injected')
            or not isinstance(plan.apps, tuple) or not 1 <= len(plan.apps) <= 8
            or any(not isinstance(app, DesktopApp) or app.role not in ROLES or not app.app_id
                   or not isinstance(app.executable, str) or not ntpath.isabs(app.executable)
                   for app in plan.apps)
            or [app.role for app in plan.apps].count('desktop') != 1 or plan.apps[0].role != 'desktop'
            or len({path_key(app.executable) for app in plan.apps}) != len(plan.apps)
            or len({app.app_id for app in plan.apps}) != len(plan.apps)):
        raise PolicyError('invalid_desktop_plan')
    try:
        if str(uuid.UUID(plan.deployment_id)) != plan.deployment_id:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise PolicyError('invalid_deployment_id') from None


def file_identity(path):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise PolicyError('desktop_executable_invalid')
    return (info.st_size, info.st_mtime_ns, info.st_ino, info.st_dev)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_app(engine, role, path):
    try:
        if (role not in ROLES or not isinstance(path, str) or not _fixed_local_path(path)
                or not _without_links(path, stat.S_ISREG)
                or ntpath.basename(path).lower() != 'claude.exe'):
            raise PolicyError('desktop_executable_invalid')
        before = file_identity(path)
        digest = _sha256(path)
        app_id = engine.app_id(path)
        if file_identity(path) != before:
            raise PolicyError('desktop_executable_changed')
        return DesktopApp(role, path, before, digest, app_id)
    except (ValueError, OSError):
        raise PolicyError('desktop_identity_unavailable') from None


def prepare_plan(executables, relay_port, *, deployment_id=None, backend=None):
    """executables: ((role, path), ...) with the packaged desktop first."""
    if type(relay_port) is not int or not 1 <= relay_port <= 65535 or not isinstance(executables, (tuple, list)):
        raise PolicyError('invalid_plan_input')
    own = backend is None
    engine = NativeWfp() if own else backend
    try:
        weights = engine.sublayer_weights()
        if (not isinstance(weights, (set, frozenset))
                or any(type(weight) is not int or not 0 <= weight <= 65535 for weight in weights)):
            raise PolicyError('sublayer_weights_unconfirmed')
        weight = next((candidate for candidate in range(SUBLAYER_WEIGHT, SUBLAYER_WEIGHT+256)
                       if candidate not in weights), None)
        if weight is None:
            raise PolicyError('sublayer_weight_unavailable')
        apps = tuple(_collect_app(engine, role, path) for role, path in executables)
        plan = DesktopPolicyPlan(apps, relay_port, deployment_id or str(uuid.uuid4()), weight,
                                 'windows_wfp' if own else 'injected')
        _check_plan(plan)
        _check_capabilities(engine)
        return plan
    finally:
        if own:
            engine.close()


_RULES = ('non-tcp', 'other-address', 'other-port', 'ipv6')


def plan_objects(plan):
    _check_plan(plan)
    key = lambda name: str(uuid.uuid5(PROJECT_NAMESPACE, plan.deployment_id + '/' + name))
    marker = ('claude-desktop-wfp/v1/' + plan.deployment_id + '/' + plan.digest).encode().hex()
    common = {'flags': PERSISTENT, 'data': marker, 'description': 'Explicit protected desktop plan ' + plan.digest}
    provider = dict(common, kind='provider', key=key('provider'), name='Claude desktop WFP provider', service=None)
    sublayer = dict(common, kind='sublayer', key=key('sublayer'), name='Claude desktop WFP sublayer',
                    provider=provider['key'], weight=plan.sublayer_weight)
    filters = []
    for index, desktop_app in enumerate(plan.apps):
        app = (APP_ID, EQUAL, BLOB, desktop_app.app_id.hex())
        extras = ((PROTOCOL, NOT_EQUAL, UINT8, 6),
                  (ADDRESS, NOT_EQUAL, UINT32, int(ipaddress.IPv4Address('127.0.0.1'))),
                  (PORT, NOT_EQUAL, UINT16, plan.relay_port), None)
        for rule, extra in zip(_RULES, extras):
            name = f'app{index}-{rule}'
            filters.append(dict(common, kind='filter', key=key(name), name='Claude desktop WFP ' + name,
                                provider=provider['key'], layer=V6 if extra is None else V4,
                                sublayer=sublayer['key'], weight=FILTER_WEIGHT, action=FWP_ACTION_BLOCK,
                                conditions=tuple(sorted((app,) if extra is None else (app, extra))),
                                raw_context=0, action_key='00000000-0000-0000-0000-000000000000'))
    return (provider, sublayer, *filters)


def _authorize(plan, approval, action):
    _check_plan(plan)
    if (not isinstance(approval, PlanApproval) or approval.plan_digest != plan.digest
            or approval.action != action):
        raise PolicyError('authorization_required')


class DesktopNativeWfp(NativeWfp):
    """Native engine whose writes are bound to one explicit desktop plan."""
    def _grant(self, plan, approval, action):
        _authorize(plan, approval, action)
        if self._permission is not None or plan.source != 'windows_wfp':
            raise PolicyError('native_plan_required')
        self._permission = (plan, approval, action)

    def _writable(self, action=None):
        if self._permission is None:
            raise PolicyError('authorization_required')
        plan, approval, operation = self._permission
        _authorize(plan, approval, operation)
        if action is not None and action != operation:
            raise PolicyError('authorization_required')
        if not self.handle.value:
            raise PolicyError('engine_closed')
        return plan

    def add(self, obj):
        from .dedicated_wfp import API_NAMES, U64, _pack_object, C
        plan = self._writable('apply')
        if not self._transaction or obj not in plan_objects(plan):
            raise PolicyError('unplanned_object_write')
        value, keep = _pack_object(obj)
        args = [self.handle, C.byref(value), None]
        filter_id = U64()
        if obj['kind'] == 'filter':
            args.append(C.byref(filter_id))
        self._call('Fwpm' + API_NAMES[obj['kind']] + 'Add0', *args)

    def delete(self, kind, key):
        from .dedicated_wfp import API_NAMES, _guid, C
        plan = self._writable('rollback')
        expected = next((o for o in plan_objects(plan) if o['kind'] == kind and o['key'] == key), None)
        if not self._transaction or expected is None or not _matches_object(self.get(kind, key), expected):
            raise PolicyError('unplanned_or_changed_object_delete')
        guid = _guid(key)
        self._call('Fwpm' + API_NAMES[kind] + 'DeleteByKey0', self.handle, C.byref(guid))


def _identity_unchanged(engine, plan):
    for app in plan.apps:
        if file_identity(app.executable) != app.file_identity or engine.app_id(app.executable) != app.app_id:
            raise PolicyError('desktop_identity_changed')


def _execute(plan, approval, action, backend, processes_absent):
    """processes_absent(plan) must return True; rules never change under a running desktop."""
    _authorize(plan, approval, action)
    own = backend is None
    engine = DesktopNativeWfp() if own else backend
    begun = committed = commit_attempted = False
    failure = None
    try:
        if isinstance(engine, DesktopNativeWfp):
            engine._grant(plan, approval, action)
        _check_capabilities(engine)
        if action == 'apply':
            _identity_unchanged(engine, plan)
        if processes_absent(plan) is not True:
            raise PolicyError('desktop_process_active_or_unknown')
        objects = plan_objects(plan)
        engine.begin()
        begun = True
        if action == 'apply' and plan.sublayer_weight in engine.sublayer_weights():
            raise PolicyError('sublayer_weight_in_use')
        existing = [engine.get(o['kind'], o['key']) for o in objects]
        if action == 'apply':
            if any(o is not None for o in existing):
                raise PolicyError('object_key_collision')
            for obj in objects:
                engine.add(obj)
            _read_exact(engine, objects)
        else:
            if all(o is None for o in existing):
                engine.abort()
                begun = False
                return {'status': 'objects_absent', 'plan_digest': plan.digest}
            if any(not _matches_object(actual, expected) for actual, expected in zip(existing, objects)):
                raise PolicyError('object_mismatch')
            for obj in reversed(objects):
                engine.delete(obj['kind'], obj['key'])
            _read_exact(engine, objects, absent=True)
        if processes_absent(plan) is not True:
            raise PolicyError('desktop_process_active_or_unknown')
        commit_attempted = True
        engine.commit()
        committed = True
        _read_exact(engine, objects, absent=action == 'rollback')
        return {'status': 'objects_read_back' if action == 'apply' else 'objects_absent',
                'plan_digest': plan.digest}
    except BaseException as error:
        failure = error
        if begun and not committed:
            try:
                engine.abort()
            except BaseException as abort_error:
                raise PolicyError('transaction_abort_failed_state_unknown:' + str(abort_error)) from error
        if commit_attempted:
            raise PolicyError('commit_or_post_commit_state_unknown:' + str(error)) from error
        raise
    finally:
        if isinstance(engine, DesktopNativeWfp):
            engine._revoke()
        if own:
            try:
                engine.close()
            except BaseException as close_error:
                if failure is None:
                    raise PolicyError('engine_close_failed:' + str(close_error)) from close_error


def apply_plan(plan, *, approval=None, backend=None, processes_absent):
    return _execute(plan, approval, 'apply', backend, processes_absent)


def rollback_plan(plan, *, approval=None, backend=None, processes_absent):
    return _execute(plan, approval, 'rollback', backend, processes_absent)


def objects_absent(plan, *, backend=None):
    own = backend is None
    engine = NativeWfp() if own else backend
    try:
        return all(engine.get(item['kind'], item['key']) is None for item in plan_objects(plan))
    finally:
        if own:
            engine.close()


@dataclass(frozen=True)
class DesktopPolicyReadback:
    plan_digest: str
    relay_port: int
    observed_at: float
    expires_at: float
    source: str


class DesktopPolicyVerifier:
    """Read-only short-lived receipts: objects exactly present and every executable unchanged."""
    def __init__(self, plan, *, clock, backend_factory=None, max_age_seconds=5):
        _check_plan(plan)
        if (not callable(clock) or (backend_factory is not None and not callable(backend_factory))
                or type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds)
                or not 0 < max_age_seconds <= 5):
            raise PolicyError('invalid_readback_parameters')
        if backend_factory is None and plan.source != 'windows_wfp':
            raise PolicyError('native_identity_required')
        self.plan = plan
        self._factory, self._clock, self._age = backend_factory, clock, max_age_seconds
        self._proof = None
        self._closed = False
        self._lock = threading.Lock()

    def read(self):
        with self._lock:
            self._proof = None
            if self._closed:
                raise PolicyError('readback_verifier_closed')
            started = self._clock()
            engine = NativeWfp() if self._factory is None else self._factory()
            try:
                _check_capabilities(engine)
                _identity_unchanged(engine, self.plan)
                objects = plan_objects(self.plan)
                _read_exact(engine, objects)
                _identity_unchanged(engine, self.plan)
            finally:
                engine.close()
            ended = self._clock()
            if not started <= ended < started + self._age:
                raise PolicyError('readback_expired')
            proof = DesktopPolicyReadback(self.plan.digest, self.plan.relay_port, started, started + self._age,
                                          'native_wfp' if self._factory is None else 'injected')
            self._proof = proof
            return proof

    def accepts(self, proof):
        with self._lock:
            now = self._clock()
            return (not self._closed and proof is not None and proof is self._proof
                    and proof.observed_at <= now < proof.expires_at)

    def close(self):
        with self._lock:
            self._closed = True
            self._proof = None


def journal_record(plan):
    return {'schema': JOURNAL_SCHEMA, 'plan_digest': plan.digest, 'deployment_id': plan.deployment_id,
            'relay_port': plan.relay_port, 'sublayer_weight': plan.sublayer_weight, 'source': plan.source,
            'apps': [{'role': app.role, 'executable': app.executable, 'file_identity': list(app.file_identity),
                      'sha256': app.sha256, 'app_id': app.app_id.hex()} for app in plan.apps],
            'objects': json.loads(json.dumps(plan_objects(plan)))}


def plan_from_journal(record):
    """Rebuild the exact applied plan; the executables may have changed since (an update)."""
    try:
        if not isinstance(record, dict) or record.get('schema') != JOURNAL_SCHEMA:
            raise ValueError()
        apps = tuple(DesktopApp(item['role'], item['executable'], tuple(item['file_identity']),
                                item['sha256'], bytes.fromhex(item['app_id'])) for item in record['apps'])
        plan = DesktopPolicyPlan(apps, record['relay_port'], record['deployment_id'],
                                 record['sublayer_weight'], record['source'])
        if (plan.digest != record['plan_digest']
                or json.loads(json.dumps(plan_objects(plan))) != record['objects']):
            raise ValueError()
        return plan
    except (ValueError, TypeError, KeyError, AttributeError, PolicyError):
        raise PolicyError('desktop_journal_invalid') from None
