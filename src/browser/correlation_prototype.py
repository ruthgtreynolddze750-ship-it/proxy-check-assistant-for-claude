"""Synthetic correlation experiment. Never produces a real launch decision."""

from dataclasses import dataclass
from ipaddress import ip_address
import math


@dataclass(frozen=True, repr=False)
class Observation:
    profile_token: str
    session_token: str
    request_token: str
    browser_profile_token: str
    browser_session_token: str
    browser_request_token: str
    response_session_token: str
    response_request_token: str
    proxy_session_token: str
    proxy_request_token: str
    target_host: str
    reported_ip: str
    expected_ip: str
    observed_at: float
    now: float
    matching_proxy_connections: int

    def __repr__(self):
        return 'Observation(<redacted synthetic data>)'


@dataclass(frozen=True)
class CorrelationResult:
    diagnostic: str
    identity_status: str = 'unconfirmed'
    proxy_status: str = 'unconfirmed'
    may_launch: bool = False


def correlate_synthetic(observation):
    """Evaluate synthetic labels only. Caller-supplied values are not evidence."""
    try:
        o = observation
        tokens = (o.profile_token, o.session_token, o.request_token)
        if any(not isinstance(x, str) or not x for x in tokens):
            return CorrelationResult('rejected')
        if not (o.browser_profile_token == o.profile_token and
                o.browser_session_token == o.response_session_token == o.proxy_session_token == o.session_token and
                o.browser_request_token == o.response_request_token == o.proxy_request_token == o.request_token):
            return CorrelationResult('rejected')
        if o.target_host != 'claude.ai' or ip_address(o.reported_ip) != ip_address(o.expected_ip):
            return CorrelationResult('rejected')
        if (not math.isfinite(o.now) or not math.isfinite(o.observed_at) or
                not 0 <= o.now - o.observed_at <= 10 or
                type(o.matching_proxy_connections) is not int or o.matching_proxy_connections != 1):
            return CorrelationResult('rejected')
        return CorrelationResult('candidate')
    except (AttributeError, TypeError, ValueError):
        return CorrelationResult('rejected')
