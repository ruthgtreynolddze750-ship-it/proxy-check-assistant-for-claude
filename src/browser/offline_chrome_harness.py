"""Offline fixture preparation. Real Chrome launch remains intentionally unavailable."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler
import http.client
import json
from pathlib import Path
import threading

if __package__:
    from .evidence_bridge import _Server
else:
    from evidence_bridge import _Server

HERE = Path(__file__).resolve().parent
EXTENSION = HERE / 'trace_extension'
FILES = ('manifest.json', 'worker.js', 'content.js', 'popup.html', 'popup.js')
SYNTHETIC_IP = '203.0.113.9'


class PreflightError(Exception):
    pass


class _SyntheticHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        valid = (self.path == '/cdn-cgi/trace' and
                 self.headers.get_all('Host', []) == [f'127.0.0.1:{self.server.server_port}'])
        body = b'ip=203.0.113.9\n' if valid else b''
        self.send_response(200 if valid else 403)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class SyntheticTarget:
    def __enter__(self):
        self.server = _Server(('127.0.0.1', 0), _SyntheticHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        try:
            self.thread.start()
        except Exception:
            self.server.server_close()
            raise
        return self

    def __exit__(self, *_):
        self.server.abort_requests()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def _replace_once(text, old, new):
    if text.count(old) != 1:
        raise PreflightError('原始扩展与预期不一致，不能生成合成副本。')
    return text.replace(old, new, 1)


def prepare_fixture(destination, target_port):
    if type(target_port) is not int or not 1 <= target_port <= 65535:
        raise PreflightError('本机端口无效。')
    dest = Path(destination)
    if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
        raise PreflightError('目标目录必须不存在且父目录已存在。')
    source = {name: (EXTENSION / name).read_bytes() for name in FILES}
    bridge_source = (HERE / 'evidence_bridge.py').read_bytes()
    origin = f'http://127.0.0.1:{target_port}'
    target = origin + '/cdn-cgi/trace'
    worker = source['worker.js'].decode('utf-8')
    worker = _replace_once(worker, "const TARGET = 'https://claude.ai/cdn-cgi/trace';", f"const TARGET = '{target}';")
    worker = _replace_once(worker, "u.origin === 'https://claude.ai'", f"u.origin === '{origin}'")
    worker = _replace_once(worker, "'https://claude.ai/cdn-cgi/trace*'", "'http://127.0.0.1/cdn-cgi/trace*'")
    content = _replace_once(source['content.js'].decode('utf-8'), "u.origin === 'https://claude.ai'", f"u.origin === '{origin}'")
    bridge = _replace_once(bridge_source.decode('utf-8'), "_TARGET = 'https://claude.ai/cdn-cgi/trace'", f"_TARGET = '{target}'")
    try:
        manifest = json.loads(source['manifest.json'].decode('utf-8-sig'))
    except (UnicodeError, ValueError) as exc:
        raise PreflightError('原始扩展清单无效。') from exc
    expected_keys = {'manifest_version', 'minimum_chrome_version', 'name', 'version', 'description',
                     'permissions', 'host_permissions', 'background', 'action', 'content_scripts'}
    expected_script = {'matches': ['https://claude.ai/cdn-cgi/trace*'], 'js': ['content.js'],
                       'run_at': 'document_idle', 'all_frames': False}
    if (not isinstance(manifest, dict) or set(manifest) != expected_keys or manifest['manifest_version'] != 3 or
            manifest['permissions'] != ['webRequest'] or
            manifest['host_permissions'] != ['https://claude.ai/*', 'http://127.0.0.1/*'] or
            manifest['background'] != {'service_worker': 'worker.js'} or
            manifest['action'] != {'default_popup': 'popup.html'} or
            manifest['content_scripts'] != [expected_script]):
        raise PreflightError('原始扩展清单范围已变化，拒绝生成合成副本。')
    manifest['host_permissions'] = ['http://127.0.0.1/*']
    manifest['content_scripts'][0]['matches'] = ['http://127.0.0.1/cdn-cgi/trace*']
    rendered = {'manifest.json': json.dumps(manifest, ensure_ascii=False, indent=2).encode('utf-8'),
                'worker.js': worker.encode('utf-8'), 'content.js': content.encode('utf-8'),
                'popup.html': source['popup.html'], 'popup.js': source['popup.js']}
    metadata = {'scope': 'synthetic_loopback_fixture_only',
                'source_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in source.items()},
                'bridge_source_sha256': hashlib.sha256(bridge_source).hexdigest(),
                'fixture_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in rendered.items()},
                'fixture_bridge_sha256': hashlib.sha256(bridge.encode('utf-8')).hexdigest()}
    dest.mkdir(exist_ok=False)
    (dest / 'extension').mkdir()
    for name, data in rendered.items():
        (dest / 'extension' / name).write_bytes(data)
    (dest / 'fixture_bridge.py').write_text(bridge, encoding='utf-8')
    (dest / 'fixture-manifest.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
    return metadata


def preflight(_untrusted_claim=None):
    # An input file or caller assertion cannot establish OS-enforced isolation.
    loopback = 'unconfirmed'
    try:
        with SyntheticTarget() as target:
            conn = http.client.HTTPConnection('127.0.0.1', target.port, timeout=2)
            try:
                conn.request('GET', '/cdn-cgi/trace')
                response = conn.getresponse()
                if response.status == 200 and response.read() == b'ip=203.0.113.9\n':
                    loopback = 'synthetic_passed'
            finally:
                conn.close()
    except OSError:
        pass
    return {'status': 'blocked', 'reason': 'trusted_isolation_verifier_unavailable',
            'isolation': 'unconfirmed', 'independent_profile': 'not_created',
            'existing_instance_binding': 'unconfirmed', 'loopback': loopback,
            'actual_chrome': 'not_run', 'extension_loading': 'unconfirmed',
            'cors': 'unconfirmed', 'identity_status': 'unconfirmed',
            'proxy_status': 'unconfirmed', 'may_launch': False}


def main():
    parser = argparse.ArgumentParser(description='离线合成前置检查；不会启动 Chrome')
    parser.add_argument('--preflight', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(preflight(), ensure_ascii=False))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
