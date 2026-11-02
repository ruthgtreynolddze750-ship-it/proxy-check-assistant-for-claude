"""Offline, allowlisted Windows build; never installs missing tools."""
import argparse
import hashlib
import importlib.util
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
APP_FILES = (
    'packaging/build.py', 'packaging/launcher.py', 'packaging/app.iss',
    'packaging/licenses/Python-PSF.txt', 'packaging/licenses/Tcl.txt', 'packaging/licenses/Tk.txt',
    'packaging/licenses/PyInstaller.txt', 'packaging/licenses/Inno-Setup.txt',
    'packaging/licenses/OpenSSL.txt', 'packaging/licenses/zlib.txt', 'packaging/licenses/XZ.txt', 'packaging/licenses/libmpdec.txt',
    'src/ui/__init__.py', 'src/ui/app.py', 'src/ui/model.py', 'src/ui/adapters.py', 'src/ui/monitoring_presentation.py', 'src/ui/monitor_binding.py', 'src/ui/release_setup.py', 'src/ui/shortcut_setup.py', 'src/ui/onboarding.py', 'src/ui/desktop_presentation.py',
    'src/core/backend.py', 'src/core/monitoring.py', 'src/core/release_trust.py', 'src/core/release_v1_679_135_manifest.json',
    'src/browser/inspection.py', 'src/browser/shortcut_selection.py', 'src/browser/session_binding.py',
    'src/browser/cdp_pipe.py', 'src/browser/request_probe.py',
    'src/protection/__init__.py', 'src/protection/session_relay.py',
    'src/protection/relay_identity.py', 'src/protection/dedicated_wfp.py', 'src/protection/managed_session.py',
    'src/protection/desktop_wfp.py', 'src/protection/desktop_process.py', 'src/protection/desktop_relay.py',
    'src/protection/desktop_session.py',
)


class BuildError(Exception):
    pass


def validate_version(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value):
        raise BuildError('版本必须是数字格式，例如 1.2.3。')
    if any(int(part) > 65535 for part in value.split('.')):
        raise BuildError('版本号每段不能大于 65535。')
    return value


def _is_reparse(path):
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def stage_sources(project, stage):
    project, stage = Path(project).resolve(strict=True), Path(stage)
    if stage.exists() or stage.is_symlink():
        raise BuildError('暂存目录已存在，拒绝覆盖。')
    snapshot = {}
    try:
        for relative in APP_FILES:
            target = project / relative
            current = project
            for part in Path(relative).parts:
                current = current / part
                if _is_reparse(current):
                    raise BuildError('输入含链接或重解析点，拒绝打包。')
            if not target.is_file() or not target.resolve(strict=True).is_relative_to(project):
                raise BuildError('缺少必要源码或路径不在项目内。')
            snapshot[relative] = target.read_bytes()
        stage.mkdir(parents=False, exist_ok=False)
        for relative, content in snapshot.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output:
                output.write(content)
    except OSError as exc:
        raise BuildError('无法读取输入或创建暂存目录。') from exc
    return tuple(snapshot)


def find_inno():
    found = shutil.which('ISCC.exe') or shutil.which('ISCC')
    if found:
        return found
    for key in ('ProgramFiles(x86)', 'ProgramFiles'):
        parent = os.environ.get(key)
        if parent:
            candidate = Path(parent) / 'Inno Setup 6' / 'ISCC.exe'
            if candidate.is_file():
                return str(candidate)
    return None


def check_sources():
    try:
        root = PROJECT.resolve(strict=True)
        for relative in APP_FILES:
            current = root
            for part in Path(relative).parts:
                current = current / part
                if _is_reparse(current):
                    return False
            if not current.is_file() or not current.resolve(strict=True).is_relative_to(root):
                return False
        return True
    except OSError:
        return False


def check_dependencies():
    result = {'windows': sys.platform == 'win32', 'python_310_or_newer': sys.version_info >= (3, 10),
              'tkinter': False, 'pyinstaller': False, 'inno_setup': bool(find_inno()),
              'source_files': check_sources()}
    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        root.tk.call('package', 'require', 'Tk')
        root.destroy()
        result['tkinter'] = True
    except Exception:
        pass
    try:
        result['pyinstaller'] = importlib.util.find_spec('PyInstaller') is not None
    except (ImportError, ValueError):
        pass
    return result


def dependency_versions(checks):
    versions = {'python': sys.version.split()[0], 'tk': None, 'pyinstaller': None,
                'inno_setup': 'installed_version_unverified' if checks['inno_setup'] else None}
    if checks['tkinter']:
        try:
            import tkinter
            root = tkinter.Tcl()
            versions['tk'] = str(root.eval('info patchlevel'))
        except Exception:
            pass
    if checks['pyinstaller']:
        try:
            versions['pyinstaller'] = importlib.metadata.version('pyinstaller')
        except importlib.metadata.PackageNotFoundError:
            versions['pyinstaller'] = 'version_unavailable'
    return versions


def audit_distribution(root):
    """Reject obvious user state and links; this is not a binary secrets scan."""
    root = Path(root)
    forbidden = {'.json', '.sqlite', '.sqlite3', '.db', '.log', '.pem', '.key', '.env'}
    forbidden_dirs = {'user data', 'userdata', 'browserdata', 'chromeprofile'}
    for path in root.rglob('*'):
        if _is_reparse(path):
            raise BuildError('打包目录含链接或重解析点，拒绝生成安装包。')
        if path.is_dir() and path.name.lower() in forbidden_dirs:
            raise BuildError('打包目录疑似包含浏览器资料，拒绝生成安装包。')
        approved_json = path.relative_to(root).as_posix() == '_internal/src/core/release_v1_679_135_manifest.json'
        if path.is_file() and not approved_json and (path.name.lower() == '.env' or path.suffix.lower() in forbidden):
            raise BuildError('打包目录含不允许的数据或配置文件，拒绝生成安装包。')


def audit_stage(stage, hashes):
    """Require exactly the staged allowlisted files, directories and original bytes."""
    stage = Path(stage)
    expected_files = set(hashes)
    expected_dirs = set()
    for name in expected_files:
        for parent in Path(name).parents:
            if str(parent) != '.':
                expected_dirs.add(parent.as_posix())
    files, directories = set(), set()
    try:
        for path in stage.rglob('*'):
            if _is_reparse(path):
                raise BuildError('暂存目录含链接或重解析点。')
            relative = path.relative_to(stage).as_posix()
            if path.is_dir():
                directories.add(relative)
            elif path.is_file():
                files.add(relative)
            else:
                raise BuildError('暂存目录含非普通文件。')
        if files != expected_files or directories != expected_dirs:
            raise BuildError('暂存目录与严格白名单不一致。')
        if any(hashlib.sha256((stage / name).read_bytes()).hexdigest() != digest
               for name, digest in hashes.items()):
            raise BuildError('暂存源码内容发生变化。')
    except OSError as exc:
        raise BuildError('无法核对暂存目录。') from exc


def audit_application_defaults(stage):
    """Reject selected machine-specific literals in staged application text only."""
    stage = Path(stage)
    port = re.compile(r'(?<![A-Za-z0-9])(?:24001|22999)(?![A-Za-z0-9])')
    user_path = re.compile(r'(?i)[a-z]:[\\/]+users[\\/]+[^\\/\s"\x27]+')
    profile = re.compile(r'(?i)\bprofile[ _-]+\d+\b')
    credential = re.compile(r'(?i)(?:https?|socks5?)://[^/\s@]+@')
    address = re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])')
    try:
        for name in APP_FILES:
            if not name.startswith('src/') or Path(name).suffix not in ('.py', '.js', '.html', '.json'):
                continue
            if name == 'src/core/release_v1_679_135_manifest.json':
                continue
            text = (stage / name).read_text(encoding='utf-8')
            if port.search(text) or user_path.search(text) or profile.search(text) or credential.search(text):
                raise BuildError('应用源码包含本机特定示例、用户路径或代理凭据形式，拒绝打包。')
            for match in address.finditer(text):
                try:
                    value = ipaddress.IPv4Address(match.group())
                except ValueError:
                    continue
                if not value.is_loopback and not value.is_unspecified:
                    raise BuildError('应用源码包含固定非回环 IPv4，拒绝打包。')
    except (OSError, UnicodeError) as exc:
        raise BuildError('无法核对应用源码的本机默认值。') from exc


def isolated_build_environment(original, python_executable, site_dir, inno_executable):
    env = dict(original)
    for key in list(env):
        if key.upper() in ('PYTHONHOME', 'PYTHONPATH', 'PYTHONUSERBASE', 'PYTHONDONTWRITEBYTECODE', 'VIRTUAL_ENV', 'CONDA_PREFIX'):
            del env[key]
    system_root = Path(env.get('SystemRoot', r'C:\Windows'))
    python_dir = Path(python_executable).parent
    env['PATH'] = os.pathsep.join((str(python_dir), str(Path(inno_executable).parent),
                                  str(system_root / 'System32'), str(system_root)))
    env['PYTHONPATH'] = str(site_dir)
    env['PYTHONNOUSERSITE'] = '1'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PIP_NO_INDEX'] = '1'
    env['TCL_LIBRARY'] = str(python_dir / 'tcl' / 'tcl8.6')
    env['TK_LIBRARY'] = str(python_dir / 'tcl' / 'tk8.6')
    return env


def verify_frozen(executable, output, environment):
    check_root = Path(output) / 'frozen-selfcheck'
    check_root.mkdir(exist_ok=False)
    env = dict(environment)
    env['LOCALAPPDATA'] = str(check_root)
    env['TEMP'] = str(check_root)
    env['TMP'] = str(check_root)
    try:
        process = subprocess.run([str(executable), '--self-check'], cwd=check_root, env=env,
                                 capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        (check_root / 'stdout.txt').write_text(process.stdout, encoding='utf-8')
        (check_root / 'stderr.txt').write_text(process.stderr, encoding='utf-8')
        result = json.loads(process.stdout)
        if (process.returncode != 0 or not isinstance(result, dict) or result.get('status') != 'passed' or
                result.get('scope') != 'imports_tk_business_entry' or
                result.get('observation_entry') != 'absent_web_launch_blocked' or
                result.get('baseline_manifest') != 'hash_and_schema_validated' or
                result.get('release_setup') != 'window_only_no_selection' or
                result.get('shortcut_selection') != 'entry_available_fail_closed' or
                result.get('default_shortcut') != 'matching_url_and_mismatch_fail_closed' or
                result.get('guide') != 'auxiliary_copy_simulated_no_network' or
                result.get('first_setup') != 'window_only_no_user_config' or
                result.get('home_403') != 'simulated_owner_display_and_launch_blocked' or
                result.get('dedicated_browser_scope') != 'unconfirmed_no_monitor_no_block' or
                result.get('protection_modules') != 'imported_no_start' or
                result.get('production_entry') != 'actual_main_runtime_connected_idle' or
                (check_root / 'ClaudeLaunchCenter').exists()):
            raise BuildError('冻结程序候选入口自检失败；已保留原始输出。')
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        (check_root / 'error.txt').write_text(f'{type(exc).__name__}: {exc}', encoding='utf-8')
        raise BuildError('冻结程序候选入口自检异常；已保留错误信息。') from exc


def build_release(output, version):
    version = validate_version(version)
    checks = check_dependencies()
    if not all(checks.values()):
        raise BuildError('构建依赖未齐，先运行 --check 查看缺项。')
    spec = importlib.util.find_spec('PyInstaller')
    if spec is None or not spec.origin:
        raise BuildError('无法确定隔离 PyInstaller 目录。')
    site_dir = Path(spec.origin).resolve().parent.parent
    if not site_dir.is_relative_to((PROJECT / 'packaging' / 'tooling').resolve()):
        raise BuildError('PyInstaller 不在项目隔离工具目录。')
    compiler = find_inno()
    isolated_env = isolated_build_environment(os.environ, sys.executable, site_dir, compiler)
    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise BuildError('输出路径须为父目录已存在、尚不存在的绝对路径。')
    output.mkdir()
    stage = output / 'stage'
    stage_sources(PROJECT, stage)
    hashes = {path: hashlib.sha256((stage / path).read_bytes()).hexdigest() for path in APP_FILES}
    audit_stage(stage, hashes)
    audit_application_defaults(stage)
    (output / 'source-manifest.json').write_text(json.dumps({'version': version, 'dependencies': dependency_versions(checks), 'files': hashes}, indent=2), encoding='utf-8')
    work = output / 'work'
    work.mkdir()
    dist = output / 'dist'
    command = [sys.executable, '-B', '-m', 'PyInstaller', '--noconfirm', '--onedir', '--console',
               '--name', 'ClaudeLaunchCenter', '--distpath', str(dist), '--workpath', str(work / 'pyinstaller'),
               '--specpath', str(work), '--paths', str(stage), '--hidden-import', 'src.core.backend',
               '--hidden-import', 'src.core.release_trust',
                '--hidden-import', 'src.browser.cdp_pipe', '--hidden-import', 'src.browser.request_probe',
                '--hidden-import', 'src.protection.session_relay', '--hidden-import', 'src.protection.relay_identity',
                '--hidden-import', 'src.protection.dedicated_wfp', '--hidden-import', 'src.protection.managed_session',
                '--hidden-import', 'src.protection.desktop_session', '--hidden-import', 'src.protection.desktop_relay',
                '--hidden-import', 'src.protection.desktop_wfp', '--hidden-import', 'src.protection.desktop_process',
                '--hidden-import', 'src.ui.desktop_presentation',
               '--hidden-import', 'src.browser.inspection', '--hidden-import', 'src.ui.release_setup', '--hidden-import', 'src.ui.shortcut_setup', '--hidden-import', 'src.ui.onboarding',
               '--hidden-import', 'src.browser.shortcut_selection', '--exclude-module', 'src.ui.candidate',
               '--exclude-module', 'src.browser.evidence_bridge', '--add-data',
               str(stage / 'src/core/release_v1_679_135_manifest.json') + os.pathsep + 'src/core',
               str(stage / 'packaging' / 'launcher.py')]
    try:
        subprocess.run(command, cwd=stage, env=isolated_env, check=True)
        audit_stage(stage, hashes)
        app_dir = dist / 'ClaudeLaunchCenter'
        if not (app_dir / 'ClaudeLaunchCenter.exe').is_file():
            raise BuildError('打包程序没有生成应用入口。')
        staged_manifest = stage / 'src/core/release_v1_679_135_manifest.json'
        frozen_manifest = app_dir / '_internal/src/core/release_v1_679_135_manifest.json'
        if (not frozen_manifest.is_file() or
                hashlib.sha256(frozen_manifest.read_bytes()).digest() != hashlib.sha256(staged_manifest.read_bytes()).digest()):
            raise BuildError('冻结程序缺少可信版本清单或清单与暂存源码不一致。')
        license_dir = app_dir / 'licenses'
        license_dir.mkdir(exist_ok=False)
        for name in ('Python-PSF.txt', 'Tcl.txt', 'Tk.txt', 'PyInstaller.txt', 'Inno-Setup.txt', 'OpenSSL.txt', 'zlib.txt', 'XZ.txt', 'libmpdec.txt'):
            shutil.copyfile(stage / 'packaging' / 'licenses' / name, license_dir / name)
        audit_distribution(app_dir)
        verify_frozen(app_dir / 'ClaudeLaunchCenter.exe', output, isolated_env)
        installer_dir = output / 'installer'
        installer_dir.mkdir()
        subprocess.run([compiler, '/DAppVersion=' + version, '/DSourceDir=' + str(app_dir),
                        '/DOutputDir=' + str(installer_dir), str(stage / 'packaging' / 'app.iss')],
                       cwd=stage, env=isolated_env, check=True)
        expected = installer_dir / ('ClaudeLaunchCenterSetup-' + version + '.exe')
        if not expected.is_file():
            raise BuildError('安装程序未生成。')
        audit_stage(stage, hashes)
        if any(hashlib.sha256((PROJECT / name).read_bytes()).hexdigest() != digest
               for name, digest in hashes.items()):
            raise BuildError('构建期间项目源码发生变化。')
        (output / 'stage-verification.json').write_text(json.dumps(
            {'status': 'passed', 'checks': ['after_staging', 'after_freeze', 'after_installer'],
             'exact_files_directories_and_hashes': True}, indent=2), encoding='utf-8')
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BuildError('构建失败；保留输出目录供检查。') from exc
    return expected


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='离线检查或构建 Windows 安装包')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--build', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--version')
    args = parser.parse_args()
    if args.check:
        checks = check_dependencies()
        print(json.dumps({'status': 'ready' if all(checks.values()) else 'blocked', 'checks': checks, 'versions': dependency_versions(checks)}, ensure_ascii=False))
        return 0 if all(checks.values()) else 2
    if not args.output or not args.version:
        parser.error('--build 必须同时提供 --output 和 --version')
    try:
        path = build_release(args.output, args.version)
    except BuildError as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({'status': 'built_not_installed', 'installer': str(path)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
