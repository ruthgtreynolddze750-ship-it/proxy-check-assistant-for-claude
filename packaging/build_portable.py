"""Local-only portable experiment using an existing Python runtime; not an installer."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('claude_packaging_build', HERE / 'build.py')
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
REQUIRED_RUNTIME = (
    'python.exe', 'pythonw.exe', 'python312.dll', 'python3.dll', 'vcruntime140.dll',
    'vcruntime140_1.dll', 'LICENSE.txt', 'DLLs/_tkinter.pyd', 'DLLs/tcl86t.dll',
    'DLLs/tk86t.dll', 'Lib/os.py', 'Lib/tkinter/__init__.py',
    'tcl/tcl8.6/init.tcl', 'tcl/tcl8.6/tclIndex', 'tcl/tk8.6/tk.tcl', 'tcl/tk8.6/tclIndex', 'tcl/tk8.6/license.terms',
)


class PortableBuildError(Exception):
    pass


def _reparse(path):
    metadata = path.lstat()
    return path.is_symlink() or bool(getattr(metadata, 'st_file_attributes', 0) & 0x400)


def runtime_files(runtime):
    runtime = Path(runtime)
    try:
        if _reparse(runtime) or not runtime.is_dir():
            raise PortableBuildError('运行时目录无效或为链接。')
        selected = set()
        for name in REQUIRED_RUNTIME:
            p = runtime / name
            for parent in (p, *p.parents):
                if parent == runtime.parent:
                    break
                if _reparse(parent):
                    raise PortableBuildError('运行时含链接，拒绝复用。')
            if not p.is_file():
                raise PortableBuildError('Python/Tk 运行时文件不完整。')
            selected.add(name)
        for top, extensions in [('Lib', {'.py'}), ('DLLs', {'.dll', '.pyd'}),
                                ('tcl', {'.tcl', '.tm', '.enc', '.msg', '.txt', '.terms', '.dat'})]:
            for current, dirs, files in os.walk(runtime / top, followlinks=False):
                parent = Path(current)
                dirs[:] = [d for d in dirs if d.lower() not in {'site-packages', '__pycache__', 'test', 'tests', 'ensurepip', 'demos'}]
                for name in dirs:
                    if _reparse(parent / name):
                        raise PortableBuildError('运行时含链接，拒绝复用。')
                for name in files:
                    path = parent / name
                    if _reparse(path):
                        raise PortableBuildError('运行时含链接，拒绝复用。')
                    if path.suffix.lower() in extensions and not name.lower().startswith('_test'):
                        selected.add(path.relative_to(runtime).as_posix())
        return tuple(sorted(selected))
    except OSError as exc:
        raise PortableBuildError('运行时不完整或不可读取。') from exc


def build(runtime, output, version):
    try:
        _base.validate_version(version)
    except _base.BuildError as exc:
        raise PortableBuildError(str(exc)) from exc
    runtime, output = Path(runtime), Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise PortableBuildError('输出必须是父目录存在且本身不存在的绝对路径。')
    selected = runtime_files(runtime)
    output.mkdir()
    bundle = output / 'bundle'
    bundle.mkdir()
    app = bundle / 'app'
    try:
        _base.stage_sources(_base.PROJECT, app)
        helper = HERE / 'portable_launcher.py'
        if _reparse(helper) or not helper.is_file():
            raise PortableBuildError('缺少隔离启动入口。')
        with (app / 'packaging' / 'portable_launcher.py').open('xb') as sink:
            sink.write(helper.read_bytes())
        dest = bundle / 'runtime'
        dest.mkdir()
        for name in selected:
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with (runtime / name).open('rb') as source, target.open('xb') as sink:
                shutil.copyfileobj(source, sink)
        (dest / 'python312._pth').write_text('Lib\nDLLs\n', encoding='utf-8')
        (bundle / '启动助手.cmd').write_text('@echo off\r\nstart "" "%~dp0runtime\\pythonw.exe" -I -B "%~dp0app\\packaging\\portable_launcher.py"\r\n', encoding='utf-8')
        check_dir = output / 'isolated-selfcheck'
        check_dir.mkdir()
        env = dict(os.environ)
        for name in ('PYTHONHOME', 'PYTHONPATH', 'TCL_LIBRARY', 'TK_LIBRARY'):
            env.pop(name, None)
        env['LOCALAPPDATA'] = str(check_dir)
        process = subprocess.run([str(dest / 'python.exe'), '-I', '-B', str(app / 'packaging' / 'portable_launcher.py'), '--self-check'],
                                 cwd=bundle, env=env, capture_output=True, text=True, encoding='utf-8', check=False)
        (output / 'selfcheck-stdout.txt').write_text(process.stdout, encoding='utf-8')
        (output / 'selfcheck-stderr.txt').write_text(process.stderr, encoding='utf-8')
        if process.returncode != 0:
            raise PortableBuildError(f'隔离自检失败，退出码 {process.returncode}；原始输出已保存。')
        result = json.loads(process.stdout)
        if result.get('status') != 'passed' or (check_dir / 'ClaudeLaunchCenter').exists():
            raise PortableBuildError('隔离源码自检失败或意外创建用户配置。')
        manifest = {p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in bundle.rglob('*') if p.is_file()}
        (output / 'manifest.json').write_text(json.dumps({'version': version, 'scope': 'local_only_not_installer',
                                                        'files': manifest}, indent=2), encoding='utf-8')
        archive = output / ('ClaudeLaunchCenter-portable-' + version + '.zip')
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
            for name in sorted(manifest):
                z.write(bundle / name, name)
    except (_base.BuildError, OSError, subprocess.SubprocessError, ValueError) as exc:
        raise PortableBuildError('隔离构建失败；输出目录保留供检查。') from exc
    return archive


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='仅本机离线可移动实验包，不是安装程序')
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        path = build(args.runtime, args.output, args.version)
    except PortableBuildError as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({'status': 'built_local_not_installer', 'archive': str(path)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
