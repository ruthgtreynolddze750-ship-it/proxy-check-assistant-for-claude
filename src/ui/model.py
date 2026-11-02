from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from enum import Enum
import ipaddress
import json
import ntpath
import os
import re
from pathlib import Path
import tempfile
from urllib.parse import urlsplit


class Status(str, Enum):
    UNKNOWN = '未确认'
    PASS = '通过'
    FAIL = '失败'


@dataclass
class Config:
    port: int = 0
    manager_port: int = 0
    manager_executable: str = field(default='', repr=False)
    manager_sha256: str = field(default='', repr=False)
    expected_ip: str = field(default='', repr=False)
    ip_url: str = field(default='', repr=False)
    mapping_mode: str = 'unknown'
    expected_zone: str = field(default='', repr=False)
    mapping_targets: str = field(default='', repr=False)
    url: str = field(default='https://claude.ai/', repr=False)
    chrome_path: str = field(default='', repr=False)
    user_data_dir: str = field(default='', repr=False)
    chrome_profile: str = field(default='', repr=False)

    def validate_common(self):
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError('请输入 1 至 65535 的本机代理端口。')
        if isinstance(self.manager_port, bool) or not isinstance(self.manager_port, int) or not 1 <= self.manager_port <= 65535:
            raise ValueError('请输入 1 至 65535 的 Proxy Manager 管理端口。')
        if any(not isinstance(value, str) for value in (self.expected_ip, self.ip_url, self.expected_zone, self.mapping_targets, self.manager_executable, self.manager_sha256)) or self.mapping_mode not in ('unknown', 'required', 'not_required'):
            raise ValueError('配置字段格式不正确。')
        if self.manager_executable and not ntpath.isabs(self.manager_executable):
            raise ValueError('管理器程序路径必须是绝对路径。')
        if self.manager_sha256 and not re.fullmatch(r'[0-9a-fA-F]{64}', self.manager_sha256):
            raise ValueError('可信程序指纹必须是 64 位十六进制 SHA-256。')
        if self.expected_zone and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', self.expected_zone):
            raise ValueError('预期区域名称格式不正确。')
        self.required_mappings()
        try:
            ipaddress.ip_address(self.expected_ip.strip())
        except ValueError:
            raise ValueError('请输入有效的预期 IP。') from None
        try:
            if any(c.isspace() or ord(c) < 32 for c in self.ip_url) or '\\' in self.ip_url:
                raise ValueError
            endpoint = urlsplit(self.ip_url)
            if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username is not None or endpoint.password is not None or endpoint.query or endpoint.fragment or endpoint.port not in (None, 443) or endpoint.hostname.lower() == 'localhost':
                raise ValueError
            try:
                ipaddress.ip_address(endpoint.hostname)
            except ValueError:
                pass
            else:
                raise ValueError
        except ValueError:
            raise ValueError('请输入不含凭据、参数或片段的 HTTPS 出口检测服务域名地址。') from None
    def validate_desktop(self):
        self.validate_common()

    def required_mappings(self):
        if not self.mapping_targets.strip():
            return ()
        entries = self.mapping_targets.split(';')
        values = []
        for entry in entries:
            parts = entry.split()
            if len(parts) != 2:
                raise ValueError('映射格式应为 IPv4 域名，多项用分号分隔。')
            try:
                address = str(ipaddress.IPv4Address(parts[0]))
            except ValueError:
                raise ValueError('映射格式应为 IPv4 域名，多项用分号分隔。') from None
            host = parts[1].lower().rstrip('.')
            if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) or '..' in host:
                raise ValueError('映射格式应为 IPv4 域名，多项用分号分隔。')
            values.append(address + ' ' + host)
        if len({value.split()[0] for value in values}) != len(values):
            raise ValueError('映射地址不能重复。')
        return tuple(values)

    def validate_browser_fields(self):
        if any(not isinstance(value, str) for value in (self.url, self.chrome_path, self.user_data_dir, self.chrome_profile)):
            raise ValueError('网页配置字段格式不正确。')
        if self.url:
            try:
                if any(c.isspace() or ord(c) < 32 for c in self.url) or '\\' in self.url:
                    raise ValueError
                parsed = urlsplit(self.url)
                if parsed.scheme != 'https' or parsed.hostname != 'claude.ai' or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.port not in (None, 443):
                    raise ValueError
            except ValueError:
                raise ValueError('网页地址必须是无账号、参数或片段的 https://claude.ai 地址。') from None
    def validate_browser(self):
        self.validate_common()
        self.validate_browser_fields()
        if not all((self.url, self.chrome_path, self.user_data_dir, self.chrome_profile)):
            raise ValueError('请填写完整网页地址、Chrome 路径、用户数据目录和配置目录。')
        if not ntpath.isabs(self.chrome_path) or ntpath.basename(self.chrome_path).lower() != 'chrome.exe' or not ntpath.isabs(self.user_data_dir):
            raise ValueError('请填写 Chrome 可执行文件和用户数据目录的绝对路径。')
        if self.chrome_profile in ('.', '..') or any(c in self.chrome_profile for c in '/\\:'):
            raise ValueError('请填写用户数据目录下的配置目录名称。')

    def validate(self):
        self.validate_common()
        self.validate_browser_fields()


def save_config(path, config):
    config.validate()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            json.dump(asdict(config), stream, ensure_ascii=False, indent=2)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def load_config(path):
    with Path(path).open(encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError('配置文件格式不正确。')
    legacy = {'port', 'expected_ip', 'url', 'chrome_path', 'chrome_profile'}
    if set(data) == legacy:
        if type(data['port']) is not int or not all(isinstance(data[key], str) for key in legacy - {'port'}):
            raise ValueError('配置文件格式不正确。')
        return Config(**data)
    full_prior = set(Config.__dataclass_fields__) - {'manager_executable', 'manager_sha256'}
    previous = full_prior - {'mapping_mode', 'expected_zone', 'mapping_targets'}
    prior_mapping = full_prior - {'expected_zone', 'mapping_targets'}
    if set(data) == previous:
        data['mapping_mode'] = 'unknown'
    if set(data) in (previous | {'mapping_mode'}, prior_mapping):
        data['expected_zone'] = ''
        data['mapping_targets'] = ''
    if set(data) == full_prior:
        data['manager_executable'] = ''
        data['manager_sha256'] = ''
    if set(data) != set(Config.__dataclass_fields__):
        raise ValueError('配置文件格式不正确。')
    config = Config(**data)
    config.validate()
    return config


@dataclass
class Result:
    common: Status = Status.UNKNOWN
    mapping_mode: str = 'unknown'
    desktop: Status = Status.UNKNOWN
    browser: Status = Status.UNKNOWN
    proxy_manager: Status = Status.UNKNOWN
    port: Status = Status.UNKNOWN
    mapping: Status = Status.UNKNOWN
    owner: Status = Status.UNKNOWN
    ip_match: Status = Status.UNKNOWN
    connectivity: Status = Status.UNKNOWN
    target_trace: Status = Status.UNKNOWN
    desktop_instance: Status = Status.UNKNOWN
    desktop_egress: Status = Status.UNKNOWN
    browser_proxy: Status = Status.UNKNOWN
    browser_input: Status = Status.UNKNOWN
    browser_identity: Status = Status.UNKNOWN
    observed_ip: str = field(default='', repr=False)
    checked_at: datetime | None = None
    reason_codes: tuple[str, ...] = ()

    @property
    def can_start_desktop(self):
        return self.common_status is Status.PASS and self.desktop is Status.PASS and self.desktop_instance is Status.PASS

    @property
    def can_start_browser(self):
        return self.common_status is Status.PASS and self.browser_status is Status.PASS

    @property
    def common_status(self):
        if self.common is Status.FAIL or self.target_trace is Status.FAIL:
            return Status.FAIL
        if self.mapping_mode in ('required', 'not_required'):
            if self.mapping is Status.FAIL:
                return Status.FAIL
            if self.mapping is Status.PASS and self.owner is Status.PASS and self.common is Status.PASS and self.target_trace is Status.PASS:
                return Status.PASS
        return Status.UNKNOWN

    @property
    def browser_status(self):
        checks = (self.browser, self.browser_input, self.browser_identity, self.browser_proxy)
        if any(value is Status.FAIL for value in checks):
            return Status.FAIL
        return Status.PASS if all(value is Status.PASS for value in checks) else Status.UNKNOWN


def _ip(value, full):
    try:
        address = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return '未确认'
    if full:
        return str(address)
    if address.version == 4:
        return '.'.join(str(address).split('.')[:2]) + '.*.*'
    return ':'.join(address.exploded.split(':')[:2]) + ':*'


def render_report(result, config, include_full_ip=False):
    owner = result.owner if config.manager_executable and config.manager_sha256 else Status.UNKNOWN
    result = replace(result, mapping_mode=config.mapping_mode, owner=owner)
    timestamp = result.checked_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(result.checked_at, datetime) else '未检测'
    lines = [
        'Claude 专用启动中心 - 检测报告',
        '检测时间：' + timestamp,
        '检测范围：Bright Data ISP + Proxy Manager；网页端与桌面端分别判断',
        f'本机代理端口：{config.port if isinstance(config.port, int) and 1 <= config.port <= 65535 else "未配置"}',
        f'管理端口：{config.manager_port if isinstance(config.manager_port, int) and 1 <= config.manager_port <= 65535 else "未配置"}',
        '预期 IP：' + _ip(config.expected_ip, include_full_ip),
        '测试出口 IP：' + _ip(result.observed_ip, include_full_ip),
        '映射要求：' + {'unknown': '未确认', 'required': '需要检测', 'not_required': '用户选择不需要映射'}.get(config.mapping_mode, '未确认'),
    ]
    mapping_label = 'ISP 区域核验（不要求映射）' if config.mapping_mode == 'not_required' else '目标映射与 ISP 区域'
    for label, key in [('共同检测', 'common_status'), ('桌面启动前条件', 'desktop'), ('网页端', 'browser_status'), ('Proxy Manager', 'proxy_manager'), ('本机端口', 'port'), ('监听归属与可信程序', 'owner'), (mapping_label, 'mapping'), ('出口 IP 匹配', 'ip_match'), ('Claude 首页连通性', 'connectivity'), ('Claude 目标请求出口', 'target_trace'), ('桌面端实例检查', 'desktop_instance'), ('桌面端实际出口', 'desktop_egress'), ('浏览器配置检查', 'browser_input'), ('浏览器进程身份', 'browser_identity'), ('实际浏览器代理', 'browser_proxy')]:
        value = getattr(result, key)
        lines.append(f'{label}：{value.value if isinstance(value, Status) else Status.UNKNOWN.value}')
    reasons = {'backend_unavailable': '检测后端未接入', 'proxy_manager_unavailable': 'Proxy Manager 未确认或不可用', 'proxy_unavailable': '代理入口不可用', 'ip_mismatch': '测试出口 IP 与预期不一致', 'target_unreachable': 'Claude 连接不可用', 'claude_home_http_403': 'Claude 首页返回 HTTP 403，服务未确认。', 'timeout': '检测超时', 'desktop_running': '桌面端已有实例，请正常退出后重新检测', 'browser_unconfirmed': '实际浏览器代理状态未确认', 'mapping_choice_required': '请明确选择是否需要目标映射', 'mapping_input_required': '请填写独立预期区域及所需目标映射', 'manager_trust_missing': '可信程序基准未确认：需从可信来源核验管理器路径和指纹后填写；不要直接采用现场进程的指纹。', 'owner_unconfirmed': '监听归属或可信程序未确认，请核对可信基准、端口和程序状态。'}
    for code in result.reason_codes:
        if code in reasons:
            lines.append('原因：' + reasons[code])
    lines.extend(['说明：独立测试请求的出口不证明桌面端或浏览器的每条连接。', '启动前检测不证明防直连或断连保护。'])
    return '\n'.join(lines)
