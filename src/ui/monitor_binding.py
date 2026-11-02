"""UI binding and core session adaptation; this module does not inspect a browser."""
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
import math
import ntpath
import time

from .model import Config


def _config_key(config):
    if type(config) is not Config:
        raise ValueError('配置未确认')
    encoded = json.dumps(asdict(config), ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, repr=False)
class BindingEvidence:
    """Cached provider evidence, not an attestation or a production provider."""
    config: Config = field(repr=False)
    pid: int
    process_started: int
    generation: str = field(repr=False)
    verified_at: float
    expires_at: float
    identity_confirmed: bool
    proxy_confirmed: bool

    @property
    def key(self):
        return (_config_key(self.config), self.pid, self.process_started, self.generation)

    def valid_for(self, config, now):
        try:
            return (type(self.pid) is int and self.pid > 0 and
                    type(self.process_started) is int and self.process_started > 0 and
                    isinstance(self.generation, str) and 0 < len(self.generation) <= 128 and
                    type(self.identity_confirmed) is bool and self.identity_confirmed and
                    type(self.proxy_confirmed) is bool and self.proxy_confirmed and
                    type(now) in (int, float) and math.isfinite(now) and
                    type(self.verified_at) in (int, float) and math.isfinite(self.verified_at) and
                    type(self.expires_at) in (int, float) and math.isfinite(self.expires_at) and
                    0 <= now - self.verified_at <= 60 and now < self.expires_at and
                    0 < self.expires_at - self.verified_at <= 60 and
                    _config_key(self.config) == _config_key(config))
        except (TypeError, ValueError, OverflowError):
            return False


def create_bound_monitor(config, evidence, *, browser_binding, interval_seconds, max_age_seconds,
                         identity_refresh_seconds, request_budget_seconds, request_evidence_ttl_seconds,
                         binding_provider=None, detector=None, clock=time.monotonic, relay_max_lease_seconds=None,
                         max_samples=None):
    """Require matching UI/core identities; never invent request or proxy evidence."""
    from src.core.monitoring import BrowserBinding, MonitorSession
    from .adapters import to_core_config
    if max_samples is not None and (type(max_samples) is not int or max_samples != 1):
        raise ValueError('界面仅支持显式单轮诊断或持续采样')
    timing = (interval_seconds, max_age_seconds, identity_refresh_seconds,
              request_budget_seconds, request_evidence_ttl_seconds)
    if relay_max_lease_seconds is not None:
        timing += (relay_max_lease_seconds,)
    try:
        valid_timing = all(type(value) in (int, float) and math.isfinite(value) and value > 0
                           for value in timing)
    except OverflowError:
        valid_timing = False
    if not valid_timing:
        raise ValueError('刷新、采样和请求预算必须是有限正数')
    if relay_max_lease_seconds is not None and relay_max_lease_seconds > 10:
        raise ValueError('转发租约上限不符合执行器契约')
    now = clock()
    if (not isinstance(evidence, BindingEvidence) or
            not evidence.valid_for(evidence.config, now) or
            not isinstance(browser_binding, BrowserBinding) or
            config != to_core_config(evidence.config)):
        raise ValueError('浏览器绑定与当前配置不一致')
    selected = evidence.config
    if (ntpath.normcase(ntpath.normpath(browser_binding.executable)) !=
            ntpath.normcase(ntpath.normpath(selected.chrome_path)) or
            ntpath.normcase(ntpath.normpath(browser_binding.user_data_dir)) !=
            ntpath.normcase(ntpath.normpath(selected.user_data_dir)) or
            browser_binding.profile_directory != selected.chrome_profile or
            evidence.key[1:] != (browser_binding.root_pid, browser_binding.root_created,
                                 browser_binding.session_id)):
        raise ValueError('浏览器绑定与所选身份不一致')
    remaining = evidence.expires_at - now
    deadline = min(remaining, max_age_seconds, request_evidence_ttl_seconds)
    if relay_max_lease_seconds is not None and max_samples is None:
        deadline = min(deadline, relay_max_lease_seconds)
    # 单轮只校验本次请求；持续模式仍须覆盖前后两次请求及中间等待。
    required_time = request_budget_seconds if max_samples == 1 else interval_seconds + 2 * request_budget_seconds
    if identity_refresh_seconds >= remaining or required_time >= deadline:
        raise ValueError('刷新或采样预算无法在当前证据到期前完成')
    return MonitorSession(config, browser_binding=browser_binding, binding_provider=binding_provider,
                          binding_key=evidence.key, detector=detector, clock=clock,
                          interval_seconds=interval_seconds, max_age_seconds=max_age_seconds, max_samples=max_samples)


class ManagedMonitorBinding:
    """Read the layered runtime's cache without issuing or extending evidence."""
    def __init__(self, runtime, *, clock=time.monotonic):
        self.runtime, self.clock = runtime, clock
        self.config = self.view = None
        self._epoch = None
        self._deadlines = {}

    def observe(self, view, config, request_id):
        from src.protection.managed_session import RuntimeView, SamplingBudget
        if (not isinstance(view, RuntimeView) or view.request_id != request_id
                or view.phase not in ('idle', 'preparing', 'running', 'alarm', 'stopping', 'blocked')
                or view.cleanup_status not in ('not_applicable', 'pending', 'confirmed', 'unknown')
                or view.evidence_mode != 'layered_v1' or not isinstance(view.sampling_budget, SamplingBudget)):
            raise ValueError('生产会话快照未确认')
        # Revalidate the approved limits, without applying the old single-layer formula.
        SamplingBudget(**vars(view.sampling_budget))
        epoch = (request_id, view.binding_key)
        if epoch != self._epoch:
            self._epoch, self._deadlines = epoch, {}
        for name in ('manager', 'exit', 'guard'):
            sequence, deadline = getattr(view, name + '_sequence'), getattr(view, name + '_expires_at')
            if type(sequence) is not int or sequence < 0:
                raise ValueError('生产证据序号未确认')
            if deadline is None:
                continue
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                raise ValueError('生产证据期限未确认')
            previous = self._deadlines.get(name)
            if previous and (sequence < previous[0] or (sequence == previous[0] and deadline > previous[1])):
                raise ValueError('旧证据不能延长或回退')
            self._deadlines[name] = (sequence, deadline)
        self.view, self.config = view, replace(config) if config is not None else None

    def current(self):
        from src.core.monitoring import BrowserBindingEvidence, MonitorSession
        from .adapters import to_core_config
        view, config, now = self.view, self.config, self.clock()
        try:
            if view is None or config is None or view.phase != 'running':
                return None
            sample, session = view.browser_evidence, view.session
            deadlines = (view.manager_expires_at, view.exit_expires_at, view.guard_expires_at, sample.expires_at)
            if (not isinstance(sample, BrowserBindingEvidence) or not isinstance(session, MonitorSession)
                    or any(type(x) not in (int, float) or not math.isfinite(x) or x <= now for x in deadlines)
                    or any(getattr(view, name + '_sequence') <= 0 for name in ('manager', 'exit', 'guard'))
                    or session.relay_config != to_core_config(config)
                    or sample.binding != session.relay_binding or sample.source != 'runtime'
                    or sample.target_origin != 'https://claude.ai' or sample.request_status != 'pass'
                    or sample.request_profile_status != 'pass' or sample.request_profile_source != 'selected_profile_context'
                    or sample.request_profile_directory != config.chrome_profile
                    or sample.proxy_port != session.relay_config.proxy_port or not sample.proxy_owner
                    or view.exit_expires_at != sample.expires_at
                    or not 0 < sample.expires_at - sample.sampled_at <= view.sampling_budget.request_evidence_ttl_seconds
                    or sample.observed_ip != config.expected_ip):
                return None
            binding = sample.binding
            evidence = BindingEvidence(replace(config), binding.root_pid, binding.root_created, binding.session_id,
                sample.sampled_at, min(deadlines), sample.identity_status == 'pass', sample.proxy_status == 'pass')
            if (evidence.valid_for(config, now) and evidence.key == view.binding_key == session.binding_key
                    and ntpath.normcase(ntpath.normpath(binding.executable)) == ntpath.normcase(ntpath.normpath(config.chrome_path))
                    and ntpath.normcase(ntpath.normpath(binding.user_data_dir)) == ntpath.normcase(ntpath.normpath(config.user_data_dir))
                    and binding.profile_directory == config.chrome_profile):
                return evidence
        except (AttributeError, TypeError, ValueError, OverflowError):
            pass
        return None

    def session_for(self, core_config, evidence, *, relay_max_lease_seconds, max_samples=None):
        from .adapters import to_core_config
        current = self.current()
        if (current is None or current.key != evidence.key or core_config != to_core_config(self.config)
                or max_samples is not None or self.view.session.relay_sample_limit is not None
                or relay_max_lease_seconds != self.view.sampling_budget.relay_max_lease_seconds):
            raise ValueError('生产会话绑定未确认')
        return self.view.session

    def relay_snapshot(self, binding_key):
        return self.view.relay_snapshot if self.view is not None and self.view.binding_key == binding_key else None
