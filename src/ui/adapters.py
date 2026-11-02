"""Explicit mappings only; these functions do not perform checks or launches."""

from .model import Result, Status
from dataclasses import dataclass, field, replace
from datetime import datetime


@dataclass(frozen=True)
class Probe:
    result: Result
    applications: tuple[str, ...] = field(default=(), repr=False)


def to_core_config(config):
    from src.core.backend import Config as CoreConfig
    config.validate_common()
    return CoreConfig(proxy_port=config.port, manager_port=config.manager_port,
                      expected_ip=config.expected_ip, ip_url=config.ip_url,
                      expected_zone=config.expected_zone if config.mapping_mode in ('required', 'not_required') else '',
                      required_reverse_mappings=config.required_mappings() if config.mapping_mode == 'required' else (),
                      mapping_mode=config.mapping_mode, manager_executable=config.manager_executable,
                      manager_sha256=config.manager_sha256)


def to_browser_selection(config):
    from src.browser.inspection import BrowserSelection
    config.validate_browser()
    return BrowserSelection(url=config.url, chrome_executable=config.chrome_path,
                            user_data_dir=config.user_data_dir, profile_directory=config.chrome_profile)


def _status(value):
    return {'pass': Status.PASS, 'passed': Status.PASS, 'fail': Status.FAIL,
            'failed': Status.FAIL, 'unknown': Status.UNKNOWN,
            'unconfirmed': Status.UNKNOWN}.get(value, Status.UNKNOWN)


def _aggregate(values):
    if any(value is Status.FAIL for value in values):
        return Status.FAIL
    return Status.PASS if all(value is Status.PASS for value in values) else Status.UNKNOWN


def from_inspections(detection, browser, checked_at=None, desktop_status=None, application_selected=False, mapping_mode='unknown'):
    from src.core.backend import Detection
    manager = _status(detection.manager.status)
    port = _status(detection.port.status)
    ip_match = _status(detection.exit_ip.status)
    connectivity = _status(detection.claude.status)
    target_trace = _status(getattr(getattr(detection, 'target_trace', None), 'status', 'unknown'))
    browser_input = _status(getattr(browser, 'input_status', 'unconfirmed'))
    browser_identity = _status(getattr(browser, 'identity_status', 'unconfirmed'))
    browser_proxy = _status(getattr(browser, 'proxy_status', 'unconfirmed'))
    browser_status = _aggregate((browser_input, browser_identity, browser_proxy))
    if browser_status is Status.PASS and getattr(browser, 'may_launch', False) is not True:
        browser_status = Status.UNKNOWN
    instance = _status(desktop_status.status) if desktop_status is not None else Status.UNKNOWN
    desktop = instance if instance is Status.FAIL or (instance is Status.PASS and application_selected) else Status.UNKNOWN
    mapping = _status(getattr(getattr(detection, 'mapping', None), 'status', 'unknown'))
    owner = Status.PASS if type(detection) is Detection and detection._owner_evidence is not None else Status.UNKNOWN
    checks = (manager, port, ip_match, target_trace, owner)
    if mapping_mode in ('required', 'not_required'):
        checks += (mapping,)
    else:
        checks += (Status.UNKNOWN,)
    observed_ip = getattr(detection, 'observed_ip', None)
    reasons = ('claude_home_http_403',) if (detection.claude.status == 'unknown' and detection.claude.message == 'Claude 首页返回 HTTP 403，服务未确认') else ()
    return Result(common=_aggregate(checks), mapping_mode=mapping_mode, mapping=mapping, owner=owner,
                  desktop=desktop, browser=browser_status, proxy_manager=manager,
                  port=port, ip_match=ip_match, connectivity=connectivity, target_trace=target_trace,
                  desktop_instance=instance,
                  desktop_egress=_status(detection.desktop_egress.status),
                  browser_input=browser_input, browser_identity=browser_identity,
                  browser_proxy=browser_proxy, observed_ip=observed_ip if isinstance(observed_ip, str) else '', checked_at=checked_at, reason_codes=reasons)


class LiveBackend:
    """Only explicit calls initiate local inspection or proxy requests."""

    def discover_desktop(self):
        from src.core.backend import discover_desktop
        return discover_desktop()

    def detect(self, config, app_id):
        from src.core.backend import detect, desktop_status, discover_desktop
        from src.browser.inspection import inspect_selection
        checked_at = datetime.now().astimezone()
        try:
            applications = discover_desktop()
        except Exception:
            applications = ()
        try:
            instance = desktop_status()
        except Exception:
            instance = None
        try:
            selection = to_browser_selection(config)
        except ValueError:
            browser = None
        else:
            try:
                browser = inspect_selection(selection)
            except Exception:
                browser = None
        detection = detect(to_core_config(config))
        result = from_inspections(detection, browser, checked_at, instance, app_id in applications, config.mapping_mode)
        reasons = list(result.reason_codes)
        if not config.manager_executable or not config.manager_sha256:
            reasons.append('manager_trust_missing')
            result = replace(result, owner=Status.UNKNOWN)
        elif result.owner is Status.UNKNOWN and result.port is Status.UNKNOWN:
            reasons.append('owner_unconfirmed')
        if config.mapping_mode == 'unknown':
            reasons.append('mapping_choice_required')
        elif not config.expected_zone or (config.mapping_mode == 'required' and not config.required_mappings()):
            reasons.append('mapping_input_required')
        result = replace(result, reason_codes=tuple(reasons))
        if (not config.manager_executable or not config.manager_sha256
                or config.mapping_mode not in ('required', 'not_required') or not config.expected_zone
                or (config.mapping_mode == 'required' and not config.required_mappings())
                or getattr(detection, 'ready', False) is not True):
            result = replace(result, common=Status.FAIL if result.common is Status.FAIL else Status.UNKNOWN,
                             mapping=result.mapping)
        return Probe(result, tuple(applications))

    def launch_desktop(self, config, app_id):
        from src.core.backend import launch_desktop
        if (not config.manager_executable or not config.manager_sha256
                or config.mapping_mode not in ('required', 'not_required') or not config.expected_zone
                or (config.mapping_mode == 'required' and not config.required_mappings())):
            raise RuntimeError('可信管理器或独立代理预期未确认。')
        return launch_desktop(to_core_config(config), app_id)

    def launch_browser(self, config):
        raise RuntimeError('当前浏览器身份和实际代理尚不能确认。')
