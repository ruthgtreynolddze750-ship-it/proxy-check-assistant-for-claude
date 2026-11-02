"""Offline native-message framing probe. No registration or Chrome launch."""
import argparse
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.browser.native_binding import read_frame, write_frame
from src.browser.native_process import sample_current_chain


def chain_status():
    first = sample_current_chain()
    second = sample_current_chain()
    return 'observed' if first is not None and first == second else 'unknown'


def result(origin_match=False):
    return {'status': 'unknown', 'claimed_origin_matches': origin_match,
            'process_chain': chain_status(), 'identity_status': 'unknown',
            'request_status': 'unknown', 'proxy_status': 'unknown', 'may_launch': False}


def serve(source, sink, allowed_id, origin):
    expected = f'chrome-extension://{allowed_id}/'
    while True:
        try:
            message = read_frame(source)
        except ValueError:
            write_frame(sink, result())
            return 1
        if message is None:
            return 0
        valid = (isinstance(message, dict) and set(message) == {'version', 'type'} and
                 type(message['version']) is int and message['version'] == 1 and message['type'] == 'hello')
        write_frame(sink, result(valid and origin == expected))


def main():
    parser = argparse.ArgumentParser(description='原生消息离线原型，不注册、不启动浏览器')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--probe', action='store_true')
    group.add_argument('--stdio', action='store_true')
    parser.add_argument('--allowed-id')
    parser.add_argument('--origin')
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(result(), ensure_ascii=False))
        return 0
    import re
    if not isinstance(args.allowed_id, str) or re.fullmatch(r'[a-p]{32}', args.allowed_id) is None:
        return 2
    if sys.platform == 'win32':
        import msvcrt
        import os
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    return serve(sys.stdin.buffer, sys.stdout.buffer, args.allowed_id, args.origin)


if __name__ == '__main__':
    raise SystemExit(main())
