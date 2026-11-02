"""Offline simulated page flow; this is not a Chrome or proxy detector."""
from dataclasses import dataclass
from ipaddress import ip_address
import json
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True)
class OfflineDemoResult:
    diagnostic: str
    network_calls: int | None
    identity_status: str = 'unconfirmed'
    proxy_status: str = 'unconfirmed'
    may_launch: bool = False


def run_demo(trace, expected, target='claude.ai'):
    node = shutil.which('node')
    if not node:
        return OfflineDemoResult('rejected', None)
    fixture = json.dumps({'trace': trace, 'expected': expected, 'host': target})
    try:
        process = subprocess.run([node, str(Path(__file__).with_name('offline_harness.cjs'))],
                                 input=fixture, text=True, encoding='utf-8',
                                 capture_output=True, check=True)
        observed = json.loads(process.stdout)
        page = observed['page']
        calls = observed['network_calls']
        if (not isinstance(page, dict) or calls != 0 or page['source'] != 'synthetic_page' or page['may_launch'] is not False
                or page['host'] != 'claude.ai' or len(page['values']) != 1
                or ip_address(page['values'][0]) != ip_address(page['expected'])):
            return OfflineDemoResult('rejected', calls)
        return OfflineDemoResult('candidate', calls)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return OfflineDemoResult('rejected', None)
