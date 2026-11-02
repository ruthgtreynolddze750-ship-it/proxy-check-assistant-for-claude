"""Probe missing and corrupt baseline data in new, disposable frozen-app copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

DATA = Path('_internal/src/core/release_v1_679_135_manifest.json')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app-dir', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source = Path(args.app_dir).resolve(strict=True)
    output = Path(args.output)
    if (not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir()
            or output.parent.resolve().is_relative_to(source)):
        raise SystemExit('Output must be a new absolute directory outside the app.')
    executable = source / 'ClaudeLaunchCenter.exe'
    data = source / DATA
    if not executable.is_file() or not data.is_file():
        raise SystemExit('Frozen application or baseline manifest missing.')
    original_hash = sha(data)
    output.mkdir()
    rows = []
    for mode, expected in [('missing', 'FileNotFoundError'), ('corrupt', 'RuntimeError')]:
        destination = output / mode
        def exclude(folder, names):
            return [DATA.name] if Path(folder) == source / DATA.parent and DATA.name in names else []
        shutil.copytree(source, destination, ignore=exclude)
        if mode == 'corrupt':
            (destination / DATA).write_bytes(b'{}')
        user = output / (mode + '-user')
        user.mkdir()
        env = dict(os.environ, LOCALAPPDATA=str(user), TEMP=str(user), TMP=str(user))
        run = subprocess.run([str(destination / executable.name), '--self-check'], cwd=user, env=env,
                             capture_output=True, text=True, encoding='utf-8', errors='replace',
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            report = json.loads(run.stdout)
        except ValueError as exc:
            raise SystemExit(f'{mode}: invalid self-check output: {run.stdout!r}; {run.stderr!r}') from exc
        passed = run.returncode != 0 and report.get('status') == 'failed' and report.get('failure') == expected
        rows.append({'case': mode, 'exit_code': run.returncode, 'report': report, 'stderr': run.stderr,
                     'expected_failure': expected, 'passed': passed})
    record = {'status': 'passed' if all(x['passed'] for x in rows) and sha(data) == original_hash else 'failed',
              'source_manifest_sha256': original_hash, 'source_preserved': sha(data) == original_hash,
              'cases': rows, 'scope': 'frozen copies only; no real selection, browser or external network'}
    (output / 'negative-probe.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': record['status'], 'cases': [x['case'] for x in rows]}, ensure_ascii=False))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
