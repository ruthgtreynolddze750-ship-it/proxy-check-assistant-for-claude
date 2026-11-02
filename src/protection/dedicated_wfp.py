"""Explicit-plan WFP candidate for one dedicated Chrome executable; no import effects."""
import ctypes as C
from dataclasses import asdict, dataclass, field
import hashlib
import ipaddress
import json
import math
import ntpath
import os
from pathlib import Path
import stat
import threading
import time
import uuid

from src.browser.session_binding import DedicatedTarget, _target_fingerprint, capture_process_snapshot
from src.browser.shortcut_selection import _fixed_local_path, _without_links


V4 = 'c38d57d1-05a7-4c33-904f-7fbceee60e82'
V6 = '4a72393b-319f-44bc-84c3-ba54dcb3b6b4'
APP_ID = 'd78e1e87-8644-4ea5-9437-d809ecefc971'
PROTOCOL = '3971ef2b-623e-4f9a-8cb1-6e79b806b9a7'
ADDRESS = 'b235ae9a-1d64-49b8-a44c-5ff3d9095045'
PORT = 'c35a604d-d22b-4e1a-91b4-68f674ee674b'
EQUAL, NOT_EQUAL = 0, 10
UINT8, UINT16, UINT32, UINT64, BLOB = 1, 2, 3, 4, 12
FWP_ACTION_BLOCK = 0x1001
PERSISTENT = 1
FILTER_INDEXED = 0x40
SUBLAYER_WEIGHT = 0x8000
FILTER_WEIGHT = 0x8000000000000000
PROJECT_NAMESPACE = uuid.UUID('d3a95df4-9748-46c2-8eef-48226bc28fbe')
REQUIRED_FIELDS = {V4: {APP_ID: BLOB, PROTOCOL: UINT8, ADDRESS: UINT32, PORT: UINT16},
                   V6: {APP_ID: BLOB}}
NOT_FOUND = {'filter': 0x80320003, 'provider': 0x80320005, 'sublayer': 0x80320007}


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApplicationIdentity:
    executable: str = field(repr=False)
    user_data_dir: str = field(repr=False)
    fingerprint: tuple = field(repr=False)
    executable_sha256: str
    app_id: bytes = field(repr=False)
    excluded: tuple = field(repr=False)
    source: str


@dataclass(frozen=True)
class PolicyPlan:
    identity: ApplicationIdentity = field(repr=False)
    relay_port: int
    deployment_id: str
    sublayer_weight: int = SUBLAYER_WEIGHT

    @property
    def digest(self):
        body = json.dumps(asdict(self), sort_keys=True, separators=(',', ':'),
                          default=lambda value: value.hex()).encode('utf-8')
        return hashlib.sha256(b'claude-dedicated-wfp/v1\0' + body).hexdigest()

    @property
    def target(self):
        return DedicatedTarget(self.identity.executable, self.identity.user_data_dir)


@dataclass(frozen=True)
class PlanApproval:
    plan_digest: str
    action: str


def _check_plan(plan):
    if (not isinstance(plan, PolicyPlan) or type(plan.relay_port) is not int
            or not 1 <= plan.relay_port <= 65535 or not plan.identity.app_id
            or type(plan.sublayer_weight) is not int
            or not SUBLAYER_WEIGHT <= plan.sublayer_weight < SUBLAYER_WEIGHT + 256
            or not plan.identity.excluded or any(app == plan.identity.app_id for _, app in plan.identity.excluded)):
        raise PolicyError('invalid_or_shared_application_plan')
    try:
        if str(uuid.UUID(plan.deployment_id)) != plan.deployment_id:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise PolicyError('invalid_deployment_id') from None


def prepare_plan(target, relay_port, *, excluded_executables, deployment_id=None, backend=None):
    if (type(relay_port) is not int or not 1 <= relay_port <= 65535
            or not isinstance(excluded_executables, (tuple, list)) or not excluded_executables):
        raise PolicyError('invalid_plan_input')
    own = backend is None
    engine = NativeWfp() if own else backend
    failure = None
    try:
        weights = engine.sublayer_weights()
        if (not isinstance(weights, (set, frozenset))
                or any(type(weight) is not int or not 0 <= weight <= 65535 for weight in weights)):
            raise PolicyError('sublayer_weights_unconfirmed')
        weight = next((candidate for candidate in range(SUBLAYER_WEIGHT, SUBLAYER_WEIGHT+256)
                       if candidate not in weights), None)
        if weight is None:
            raise PolicyError('sublayer_weight_unavailable')
        plan = PolicyPlan(engine.identity(target, tuple(excluded_executables)), relay_port,
                          deployment_id or str(uuid.uuid4()), weight)
        _check_plan(plan)
        _check_capabilities(engine)
        return plan
    except BaseException as error:
        failure = error
        raise
    finally:
        if own:
            try:
                engine.close()
            except BaseException as error:
                if failure is None:
                    failure = PolicyError('prepare_close_failed')
                    failure.engine = engine
                    raise failure from error
                failure.add_note('prepare_close_failed:' + str(error))
                failure.engine = engine


def plan_objects(plan):
    _check_plan(plan)
    key = lambda name: str(uuid.uuid5(PROJECT_NAMESPACE, plan.deployment_id + '/' + name))
    marker = ('claude-dedicated-wfp/v1/' + plan.deployment_id + '/' + plan.digest).encode().hex()
    common = {'flags': PERSISTENT, 'data': marker, 'description': 'Explicit dedicated Chrome plan ' + plan.digest}
    provider = dict(common, kind='provider', key=key('provider'), name='Claude dedicated WFP provider', service=None)
    sublayer = dict(common, kind='sublayer', key=key('sublayer'), name='Claude dedicated WFP sublayer',
                    provider=provider['key'], weight=plan.sublayer_weight)
    app = (APP_ID, EQUAL, BLOB, plan.identity.app_id.hex())
    rules = [('non-tcp', V4, (PROTOCOL, NOT_EQUAL, UINT8, 6)),
             ('other-address', V4, (ADDRESS, NOT_EQUAL, UINT32, int(ipaddress.IPv4Address('127.0.0.1')))),
             ('other-port', V4, (PORT, NOT_EQUAL, UINT16, plan.relay_port)), ('ipv6', V6, None)]
    filters = [dict(common, kind='filter', key=key(name), name='Claude dedicated WFP ' + name,
                    provider=provider['key'], layer=layer, sublayer=sublayer['key'],
                    weight=FILTER_WEIGHT, action=FWP_ACTION_BLOCK,
                    conditions=tuple(sorted((app,) if extra is None else (app, extra))),
                    raw_context=0, action_key='00000000-0000-0000-0000-000000000000')
               for name, layer, extra in rules]
    return (provider, sublayer, *filters)


def review_plan(plan):
    return {'plan_digest': plan.digest, 'deployment_id': plan.deployment_id,
            'sublayer_weight': plan.sublayer_weight,
            'executable': plan.identity.executable, 'user_data_dir': plan.identity.user_data_dir,
            'executable_sha256': plan.identity.executable_sha256,
            'application_id_sha256': hashlib.sha256(plan.identity.app_id).hexdigest(),
            'excluded_executables': [path for path, _ in plan.identity.excluded],
            'relay_endpoint': '127.0.0.1:' + str(plan.relay_port), 'source': plan.identity.source,
            'objects': plan_objects(plan), 'protection_verified': False,
            'authorization': 'separate explicit plan-digest approval required for apply and rollback'}


def _check_capabilities(engine):
    actual = engine.capabilities()
    if any(actual.get(layer, {}).get(key) != datatype
           for layer, fields in REQUIRED_FIELDS.items() for key, datatype in fields.items()):
        raise PolicyError('native_layer_condition_unconfirmed')


def _authorize(plan, approval, action):
    _check_plan(plan)
    if (not isinstance(approval, PlanApproval) or approval.plan_digest != plan.digest
            or approval.action != action):
        raise PolicyError('authorization_required')


def _filter_flags_valid(flags):
    return type(flags) is int and flags in (PERSISTENT, PERSISTENT | FILTER_INDEXED)


def _matches_object(actual, expected):
    """Match policy exactly, allowing only the filter's optional lookup-index bit.

    Native Get retains raw flags. INDEXED is classification lookup metadata, not
    permission to accept DISABLED, action-right, context, boot-time or unknown bits.
    """
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        return False
    if expected.get('kind') == 'filter':
        if (type(expected.get('flags')) is not int or expected['flags'] != PERSISTENT
                or not _filter_flags_valid(actual.get('flags'))):
            return False
        return dict(actual, flags=PERSISTENT) == expected
    return actual == expected


def _read_exact(engine, objects, absent=False):
    for obj in objects:
        actual = engine.get(obj['kind'], obj['key'])
        if (actual is not None if absent else not _matches_object(actual, obj)):
            raise PolicyError('object_mismatch')


def _execute(plan, approval, action, backend):
    _authorize(plan, approval, action)
    own = backend is None
    engine = NativeWfp() if own else backend
    begun = committed = commit_attempted = objects_verified = False
    failure = None
    try:
        if isinstance(engine, NativeWfp):
            engine._grant(plan, approval, action)
        _check_capabilities(engine)
        engine.guard(plan)
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
                objects_verified = True
                return {'status': 'objects_absent', 'plan_digest': plan.digest, 'protection_verified': False}
            if any(not _matches_object(actual, expected) for actual, expected in zip(existing, objects)):
                raise PolicyError('object_mismatch')
            for obj in reversed(objects):
                engine.delete(obj['kind'], obj['key'])
            _read_exact(engine, objects, absent=True)
        engine.guard(plan)
        commit_attempted = True
        engine.commit()
        committed = True
        _read_exact(engine, objects, absent=action == 'rollback')
        objects_verified = True
        return {'status': 'objects_read_back' if action == 'apply' else 'objects_absent',
                'plan_digest': plan.digest, 'protection_verified': False}
    except BaseException as error:
        failure = error
        if begun and not committed:
            try:
                engine.abort()
            except BaseException as abort_error:
                failure = PolicyError('transaction_abort_failed_state_unknown:' + str(abort_error))
                raise failure from error
        if commit_attempted:
            failure = PolicyError('commit_or_post_commit_state_unknown:' + str(error))
            raise failure from error
        raise
    finally:
        state = {'plan_digest': plan.digest, 'action': action, 'commit_attempted': commit_attempted,
                 'committed': committed, 'objects_verified': objects_verified}
        if failure is not None:
            failure.operation_state = state
        if isinstance(engine, NativeWfp):
            engine._revoke()
        if own:
            try:
                engine.close()
            except BaseException as close_error:
                if failure is None:
                    failure = PolicyError('engine_close_failed:' + str(close_error))
                    failure.operation_state, failure.engine = state, engine
                    raise failure from close_error
                failure.add_note('engine_close_failed:' + str(close_error))
                failure.engine = engine


def apply_plan(plan, *, approval=None, backend=None):
    return _execute(plan, approval, 'apply', backend)


def rollback_plan(plan, *, approval=None, backend=None):
    return _execute(plan, approval, 'rollback', backend)


@dataclass(frozen=True)
class PolicyReadback:
    plan_digest: str
    deployment_id: str
    relay_port: int
    executable_sha256: str
    application_id_sha256: str
    object_keys: tuple[str, ...]
    objects_digest: str
    observed_at: float
    expires_at: float
    source: str
    protection_verified: bool = False


class PolicyReadbackVerifier:
    """Read-only, short-lived receipts; never asserts effective traffic blocking.

    Consumers must retain this issuer and call accepts on the original receipt.
    This is an in-process contract, not a security boundary against Python code.
    """
    def __init__(self, plan, *, backend_factory=None, clock=time.monotonic, max_age_seconds=5):
        _check_plan(plan)
        if (not callable(clock) or (backend_factory is not None and not callable(backend_factory))
                or type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds)
                or not 0 < max_age_seconds <= 5):
            raise PolicyError('invalid_readback_parameters')
        self.plan = plan
        self._factory, self._clock, self._age = backend_factory, clock, max_age_seconds
        self._proof = None
        self._closed = False
        self._lock = threading.RLock()

    def read(self):
        from .relay_identity import _guard_stage
        with self._lock:
            self._proof = None
            if self._closed:
                raise PolicyError('readback_verifier_closed')
            started = self._clock()
            if type(started) not in (int, float) or not math.isfinite(started):
                raise PolicyError('readback_clock_invalid')
            with _guard_stage('policy_engine_open'):
                engine = NativeWfp() if self._factory is None else self._factory()
            failure = None
            try:
                if self._factory is None and self.plan.identity.source != 'windows_wfp':
                    raise PolicyError('native_identity_required')
                with _guard_stage('policy_capabilities'):
                    _check_capabilities(engine)
                excluded = tuple(path for path, _ in self.plan.identity.excluded)
                with _guard_stage('policy_identity_before'):
                    if engine.identity(self.plan.target, excluded) != self.plan.identity:
                        raise PolicyError('application_identity_changed')
                objects = plan_objects(self.plan)
                with _guard_stage('policy_objects_before'):
                    _read_exact(engine, objects)
                with _guard_stage('policy_objects_after'):
                    _read_exact(engine, objects)
                with _guard_stage('policy_identity_after'):
                    if engine.identity(self.plan.target, excluded) != self.plan.identity:
                        raise PolicyError('application_identity_changed')
            except BaseException as error:
                failure = error
                raise
            finally:
                try:
                    with _guard_stage('policy_engine_close'):
                        engine.close()
                except BaseException as error:
                    if failure is None:
                        failure = PolicyError('readback_close_failed')
                        failure.engine = engine
                        raise failure from error
                    failure.add_note('readback_close_failed:' + str(error))
                    failure.engine = engine
            ended = self._clock()
            if (type(ended) not in (int, float) or not math.isfinite(ended)
                    or not started <= ended < started + self._age):
                raise PolicyError('readback_expired')
            digest = hashlib.sha256(json.dumps(objects, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            proof = PolicyReadback(self.plan.digest, self.plan.deployment_id, self.plan.relay_port,
                self.plan.identity.executable_sha256, hashlib.sha256(self.plan.identity.app_id).hexdigest(),
                tuple(o['key'] for o in objects), digest, started, started + self._age,
                'native_wfp' if self._factory is None else 'injected')
            self._proof = proof
            return proof

    def accepts(self, proof):
        with self._lock:
            now = self._clock()
            return (not self._closed and isinstance(proof, PolicyReadback) and proof is self._proof
                    and type(now) in (int, float) and math.isfinite(now)
                    and proof.observed_at <= now < proof.expires_at
                    and proof.plan_digest == self.plan.digest)

    def close(self):
        with self._lock:
            self._closed = True
            self._proof = None


U8, U16, U32, U64, PTR = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64, C.c_void_p


class GUID(C.Structure):
    _fields_ = [('Data1', U32), ('Data2', U16), ('Data3', U16), ('Data4', U8 * 8)]


class Blob(C.Structure):
    _fields_ = [('size', U32), ('data', C.POINTER(U8))]


class Display(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('description', C.c_wchar_p)]


class ValueUnion(C.Union):
    _fields_ = [('uint8', U8), ('uint16', U16), ('uint32', U32), ('uint64', C.POINTER(U64)),
                ('byteBlob', C.POINTER(Blob)), ('pointer', PTR)]


class Value(C.Structure):
    _fields_ = [('type', U32), ('value', ValueUnion)]


class Condition(C.Structure):
    _fields_ = [('fieldKey', GUID), ('matchType', U32), ('conditionValue', Value)]


class Action(C.Structure):
    _fields_ = [('type', U32), ('key', GUID)]


class Context(C.Union):
    _fields_ = [('rawContext', U64), ('providerContextKey', GUID)]


class Provider(C.Structure):
    _fields_ = [('providerKey', GUID), ('displayData', Display), ('flags', U32),
                ('providerData', Blob), ('serviceName', C.c_wchar_p)]


class SubLayer(C.Structure):
    _fields_ = [('subLayerKey', GUID), ('displayData', Display), ('flags', U32),
                ('providerKey', C.POINTER(GUID)), ('providerData', Blob), ('weight', U16)]


class Filter(C.Structure):
    _fields_ = [('filterKey', GUID), ('displayData', Display), ('flags', U32),
                ('providerKey', C.POINTER(GUID)), ('providerData', Blob), ('layerKey', GUID),
                ('subLayerKey', GUID), ('weight', Value), ('numFilterConditions', U32),
                ('filterCondition', C.POINTER(Condition)), ('action', Action), ('context', Context),
                ('reserved', C.POINTER(GUID)), ('filterId', U64), ('effectiveWeight', Value)]


class Field(C.Structure):
    _fields_ = [('fieldKey', C.POINTER(GUID)), ('type', U32), ('dataType', U32)]


class Layer(C.Structure):
    _fields_ = [('layerKey', GUID), ('displayData', Display), ('flags', U32), ('numFields', U32),
                ('field', C.POINTER(Field)), ('defaultSubLayerKey', GUID), ('layerId', U16)]


class Session(C.Structure):
    _fields_ = [('sessionKey', GUID), ('displayData', Display), ('flags', U32),
                ('txnWaitTimeoutInMSec', U32), ('processId', U32), ('sid', PTR),
                ('username', C.c_wchar_p), ('kernelMode', C.c_int32)]


STRUCTS = {'provider': Provider, 'sublayer': SubLayer, 'filter': Filter}
API_NAMES = {'provider': 'Provider', 'sublayer': 'SubLayer', 'filter': 'Filter'}


def abi_sizes():
    return {cls.__name__: C.sizeof(cls) for cls in
            (GUID, Blob, Value, Condition, Provider, SubLayer, Filter, Layer, Field, Session)}


def _guid(value):
    return GUID.from_buffer_copy(uuid.UUID(value).bytes_le)


def _guid_text(value):
    return str(uuid.UUID(bytes_le=bytes(value)))


def _blob_bytes(value):
    if value.size > 65536 or (value.size and not value.data):
        raise PolicyError('native_blob_invalid')
    return C.string_at(value.data, value.size) if value.size else b''


def _make_blob(data):
    array = (U8 * len(data)).from_buffer_copy(data)
    return Blob(len(data), array), array


def _value(data_type, value, keep):
    result = Value()
    result.type = data_type
    if data_type in (UINT8, UINT16, UINT32):
        setattr(result.value, {UINT8: 'uint8', UINT16: 'uint16', UINT32: 'uint32'}[data_type], value)
    elif data_type == UINT64:
        number = U64(value)
        keep.append(number)
        result.value.uint64 = C.pointer(number)
    elif data_type == BLOB:
        blob, array = _make_blob(bytes.fromhex(value))
        keep.extend((blob, array))
        result.value.byteBlob = C.pointer(blob)
    else:
        raise PolicyError('unsupported_value_type')
    return result


def _read_value(value):
    if value.type in (UINT8, UINT16, UINT32):
        return getattr(value.value, {UINT8: 'uint8', UINT16: 'uint16', UINT32: 'uint32'}[value.type])
    if value.type == UINT64 and value.value.uint64:
        return value.value.uint64.contents.value
    if value.type == BLOB and value.value.byteBlob:
        return _blob_bytes(value.value.byteBlob.contents).hex()
    raise PolicyError('native_value_type_unexpected')


def _pack_object(obj):
    result = STRUCTS[obj['kind']]()
    keep = [result]
    setattr(result, {'provider': 'providerKey', 'sublayer': 'subLayerKey', 'filter': 'filterKey'}[obj['kind']], _guid(obj['key']))
    result.displayData = Display(obj['name'], obj['description'])
    result.flags = obj['flags']
    blob, array = _make_blob(bytes.fromhex(obj['data']))
    result.providerData = blob
    keep.extend((blob, array))
    if obj['kind'] == 'provider':
        result.serviceName = obj['service']
    else:
        provider = _guid(obj['provider'])
        keep.append(provider)
        result.providerKey = C.pointer(provider)
        if obj['kind'] == 'sublayer':
            result.weight = obj['weight']
        else:
            result.layerKey, result.subLayerKey = _guid(obj['layer']), _guid(obj['sublayer'])
            result.weight = _value(UINT64, obj['weight'], keep)
            conditions = (Condition * len(obj['conditions']))()
            for slot, (key, match, datatype, val) in zip(conditions, obj['conditions']):
                slot.fieldKey, slot.matchType = _guid(key), match
                slot.conditionValue = _value(datatype, val, keep)
            keep.append(conditions)
            result.numFilterConditions, result.filterCondition = len(conditions), conditions
            result.action = Action(obj['action'], _guid(obj['action_key']))
            result.context.rawContext = obj['raw_context']
    return result, keep


def _unpack_object(kind, value):
    result = {'kind': kind, 'key': _guid_text(getattr(value,
        {'provider': 'providerKey', 'sublayer': 'subLayerKey', 'filter': 'filterKey'}[kind])),
        'name': value.displayData.name, 'description': value.displayData.description,
        'flags': value.flags, 'data': _blob_bytes(value.providerData).hex()}
    if kind == 'provider':
        result['service'] = value.serviceName
        return result
    if not value.providerKey:
        raise PolicyError('native_provider_reference_missing')
    result['provider'] = _guid_text(value.providerKey.contents)
    if kind == 'sublayer':
        result['weight'] = value.weight
        return result
    if (not _filter_flags_valid(value.flags) or value.weight.type != UINT64
            or value.reserved or value.numFilterConditions > 16):
        shape = {'flags': value.flags, 'weight_type': value.weight.type,
                 'reserved_present': bool(value.reserved), 'condition_count': value.numFilterConditions}
        mismatches = tuple(name for name, matches in (
            ('flags', _filter_flags_valid(value.flags)), ('weight_type', value.weight.type == UINT64),
            ('reserved_present', not value.reserved), ('condition_count', value.numFilterConditions <= 16))
            if not matches)
        error = PolicyError('native_filter_shape_unexpected:' + json.dumps(
            {'mismatches': mismatches, 'shape': shape}, sort_keys=True, separators=(',', ':')))
        error.native_shape, error.shape_mismatches = shape, mismatches
        raise error
    if value.numFilterConditions and not value.filterCondition:
        raise PolicyError('native_filter_conditions_missing')
    conditions = []
    for index in range(value.numFilterConditions):
        condition = value.filterCondition[index]
        conditions.append((_guid_text(condition.fieldKey), condition.matchType,
                           condition.conditionValue.type, _read_value(condition.conditionValue)))
    result.update(layer=_guid_text(value.layerKey), sublayer=_guid_text(value.subLayerKey),
                  weight=_read_value(value.weight), action=value.action.type,
                  action_key=_guid_text(value.action.key), raw_context=value.context.rawContext,
                  conditions=tuple(sorted(conditions)))
    return result


class NativeWfp:
    """x64 user-mode API; write methods require a bound explicit plan and transaction."""
    def __init__(self):
        if os.name != 'nt' or C.sizeof(PTR) != 8 or C.sizeof(C.c_wchar) != 2:
            raise PolicyError('windows_x64_abi_required')
        expected = {'GUID': 16, 'Blob': 16, 'Value': 16, 'Condition': 40, 'Provider': 64,
                    'SubLayer': 72, 'Filter': 200, 'Layer': 72, 'Field': 16, 'Session': 72}
        if abi_sizes() != expected:
            raise PolicyError('native_abi_unconfirmed')
        self.dll = C.WinDLL('fwpuclnt.dll', winmode=0x800)
        self.handle, self._permission, self._transaction = PTR(), None, False
        self._bind('FwpmEngineOpen0', [C.c_wchar_p, U32, PTR, C.POINTER(Session), C.POINTER(PTR)])
        self._bind('FwpmEngineClose0', [PTR])
        self._bind('FwpmFreeMemory0', [C.POINTER(PTR)], result=None)
        self._bind('FwpmGetAppIdFromFileName0', [C.c_wchar_p, C.POINTER(C.POINTER(Blob))])
        self._bind('FwpmLayerGetByKey0', [PTR, C.POINTER(GUID), C.POINTER(C.POINTER(Layer))])
        self._bind('FwpmSubLayerCreateEnumHandle0', [PTR, PTR, C.POINTER(PTR)])
        self._bind('FwpmSubLayerEnum0', [PTR, PTR, U32,
            C.POINTER(C.POINTER(C.POINTER(SubLayer))), C.POINTER(U32)])
        self._bind('FwpmSubLayerDestroyEnumHandle0', [PTR, PTR])
        self._bind('FwpmTransactionBegin0', [PTR, U32])
        for action in ('Commit', 'Abort'):
            self._bind('FwpmTransaction' + action + '0', [PTR])
        for kind, cls in STRUCTS.items():
            name = API_NAMES[kind]
            self._bind('Fwpm' + name + 'GetByKey0', [PTR, C.POINTER(GUID), C.POINTER(C.POINTER(cls))])
            self._bind('Fwpm' + name + 'DeleteByKey0', [PTR, C.POINTER(GUID)])
            args = [PTR, C.POINTER(cls), PTR] + ([C.POINTER(U64)] if kind == 'filter' else [])
            self._bind('Fwpm' + name + 'Add0', args)
        session = Session()
        session.txnWaitTimeoutInMSec = 3000
        self._call('FwpmEngineOpen0', None, 0xFFFFFFFF, None, C.byref(session), C.byref(self.handle))

    def _bind(self, name, args, result=U32):
        fn = getattr(self.dll, name)
        fn.argtypes, fn.restype = args, result

    def _call(self, name, *args):
        code = getattr(self.dll, name)(*args)
        if code:
            raise PolicyError(name + ':0x' + format(code, '08x'))

    def _free(self, pointer):
        value = C.cast(pointer, PTR)
        self.dll.FwpmFreeMemory0(C.byref(value))

    def close(self):
        if self.handle.value:
            # Microsoft documents that closing this session aborts its pending transaction.
            self._call('FwpmEngineClose0', self.handle)
            self.handle = PTR()
            self._transaction = False
            self._permission = None

    def app_id(self, path):
        pointer = C.POINTER(Blob)()
        self._call('FwpmGetAppIdFromFileName0', path, C.byref(pointer))
        try:
            if not pointer:
                raise PolicyError('application_id_missing')
            return _blob_bytes(pointer.contents)
        finally:
            self._free(pointer)

    def identity(self, target, excluded):
        try:
            fingerprint = _target_fingerprint(target)
            ids = []
            for path in excluded:
                if (not _fixed_local_path(path) or not _without_links(path, stat.S_ISREG)
                        or ntpath.basename(path).lower() != 'chrome.exe'):
                    raise PolicyError('excluded_application_invalid')
                ids.append((path, self.app_id(path)))
            digest = hashlib.sha256(Path(target.executable).read_bytes()).hexdigest()
            if _target_fingerprint(target) != fingerprint:
                raise PolicyError('application_changed')
            return ApplicationIdentity(target.executable, target.user_data_dir, fingerprint,
                                       digest, self.app_id(target.executable), tuple(ids), 'windows_wfp')
        except (ValueError, OSError):
            raise PolicyError('application_identity_unavailable') from None

    def capabilities(self):
        result = {}
        for key in REQUIRED_FIELDS:
            pointer = C.POINTER(Layer)()
            guid = _guid(key)
            self._call('FwpmLayerGetByKey0', self.handle, C.byref(guid), C.byref(pointer))
            try:
                if (not pointer or _guid_text(pointer.contents.layerKey) != key
                        or pointer.contents.numFields > 256 or not pointer.contents.field):
                    raise PolicyError('native_layer_shape_unexpected')
                fields = {}
                for index in range(pointer.contents.numFields):
                    native_field = pointer.contents.field[index]
                    if not native_field.fieldKey:
                        raise PolicyError('native_field_missing')
                    fields[_guid_text(native_field.fieldKey.contents)] = native_field.dataType
                result[key] = fields
            finally:
                self._free(pointer)
        return result

    def sublayer_weights(self):
        """Read only weights from the enumerator snapshot, not provider data or names."""
        handle, failure = PTR(), None
        weights = set()
        try:
            self._call('FwpmSubLayerCreateEnumHandle0', self.handle, None, C.byref(handle))
            if not handle:
                raise PolicyError('sublayer_enumerator_missing')
            for _ in range(1025):
                entries = C.POINTER(C.POINTER(SubLayer))()
                count = U32()
                try:
                    self._call('FwpmSubLayerEnum0', self.handle, handle, 64,
                               C.byref(entries), C.byref(count))
                    if count.value > 64 or (count.value and not entries):
                        raise PolicyError('sublayer_enumeration_invalid')
                    for index in range(count.value):
                        if not entries[index]:
                            raise PolicyError('sublayer_enumeration_invalid')
                        weights.add(entries[index].contents.weight)
                finally:
                    if entries:
                        self._free(entries)
                if count.value < 64:
                    return frozenset(weights)
            raise PolicyError('sublayer_enumeration_limit')
        except BaseException as error:
            failure = error
            raise
        finally:
            if handle:
                try:
                    self._call('FwpmSubLayerDestroyEnumHandle0', self.handle, handle)
                except BaseException as error:
                    if failure is None:
                        raise PolicyError('sublayer_enumerator_close_failed') from error
                    failure.add_note('sublayer_enumerator_close_failed:' + str(error))

    def guard(self, plan):
        if (plan.identity.source != 'windows_wfp' or self.identity(plan.target,
                tuple(path for path, _ in plan.identity.excluded)) != plan.identity):
            raise PolicyError('application_identity_changed')
        snapshot = capture_process_snapshot(plan.target)
        if not snapshot.complete or snapshot.processes:
            raise PolicyError('dedicated_process_active_or_unknown')

    def get(self, kind, key):
        pointer = C.POINTER(STRUCTS[kind])()
        guid = _guid(key)
        name = 'Fwpm' + API_NAMES[kind] + 'GetByKey0'
        code = getattr(self.dll, name)(self.handle, C.byref(guid), C.byref(pointer))
        if code == NOT_FOUND[kind]:
            return None
        if code:
            raise PolicyError(name + ':0x' + format(code, '08x'))
        try:
            if not pointer:
                raise PolicyError('native_object_missing')
            return _unpack_object(kind, pointer.contents)
        finally:
            self._free(pointer)

    def _grant(self, plan, approval, action):
        _authorize(plan, approval, action)
        if self._permission is not None or plan.identity.source != 'windows_wfp':
            raise PolicyError('native_plan_required')
        self._permission = (plan, approval, action)

    def _revoke(self):
        self._permission = None

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

    def begin(self):
        self._writable()
        if self._transaction:
            raise PolicyError('transaction_already_active')
        self._call('FwpmTransactionBegin0', self.handle, 0)
        self._transaction = True

    def add(self, obj):
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
        plan = self._writable('rollback')
        expected = next((o for o in plan_objects(plan) if o['kind'] == kind and o['key'] == key), None)
        if not self._transaction or expected is None or not _matches_object(self.get(kind, key), expected):
            raise PolicyError('unplanned_or_changed_object_delete')
        guid = _guid(key)
        self._call('Fwpm' + API_NAMES[kind] + 'DeleteByKey0', self.handle, C.byref(guid))

    def commit(self):
        self._writable()
        if not self._transaction:
            raise PolicyError('transaction_missing')
        self._call('FwpmTransactionCommit0', self.handle)
        self._transaction = False

    def abort(self):
        self._writable()
        if not self._transaction:
            raise PolicyError('transaction_missing')
        self._call('FwpmTransactionAbort0', self.handle)
        self._transaction = False
