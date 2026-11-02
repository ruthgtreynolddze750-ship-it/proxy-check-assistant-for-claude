"""Read-only selection checks; proxy and process identity are not inferred."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True, repr=False)
class BrowserSelection:
    url: str
    chrome_executable: str
    user_data_dir: str
    profile_directory: str

    def __repr__(self):
        return 'BrowserSelection(<redacted>)'


@dataclass(frozen=True)
class BrowserInspection:
    input_status: str
    identity_status: str
    proxy_status: str
    may_launch: bool
    reason: str


def _valid_url(value):
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
        return False
    try:
        parts = urlsplit(value)
        return (parts.scheme.lower() == 'https' and parts.hostname == 'claude.ai'
                and parts.username is None and parts.password is None
                and parts.port in (None, 443))
    except ValueError:
        return False


def _valid_profile(root, name):
    if not isinstance(root, str) or not isinstance(name, str):
        return False
    if not name or name in ('.', '..') or '/' in name or '\\' in name or ':' in name:
        return False
    try:
        base = Path(root)
        if not base.is_absolute() or not base.is_dir():
            return False
        profile = base / name
        return profile.is_dir() and profile.resolve().parent == base.resolve()
    except (OSError, ValueError, RuntimeError):
        return False


def inspect_selection(selection):
    """Inspect local input only. No browser process, network or profile writes."""
    if not _valid_url(selection.url):
        return BrowserInspection('failed', 'unconfirmed', 'unconfirmed', False,
                                 '网页地址必须是 https://claude.ai 的有效地址。')
    try:
        executable = Path(selection.chrome_executable)
        valid_executable = (executable.is_absolute() and executable.name.lower() == 'chrome.exe'
                            and executable.is_file())
    except (OSError, TypeError, ValueError):
        valid_executable = False
    if not valid_executable:
        return BrowserInspection('failed', 'unconfirmed', 'unconfirmed', False,
                                 '请选择存在的 Chrome 可执行文件；快捷方式尚不支持识别。')
    if not _valid_profile(selection.user_data_dir, selection.profile_directory):
        return BrowserInspection('failed', 'unconfirmed', 'unconfirmed', False,
                                 '请选择存在的用户数据目录和其中的配置目录。')
    return BrowserInspection('passed', 'unconfirmed', 'unconfirmed', False,
                             '配置存在不代表进程身份或实际代理已确认；请等待浏览器实测能力接入。')
