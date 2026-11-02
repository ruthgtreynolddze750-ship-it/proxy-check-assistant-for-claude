"""Application entry and configuration-free installation self-check."""
import json
from pathlib import Path
import sys

if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _check_production_entry():
    """Observe the real main without injecting a runtime, provider, or session."""
    import os
    import tempfile
    import threading
    import tkinter
    from src.ui import app as module
    from src.protection.managed_session import ManagedSessionRuntime

    observed, attempts, callback_errors, roots = {}, [], [], []
    active = [False]

    def forbidden(reason):
        attempts.append(reason)
        raise RuntimeError('production entry attempted a forbidden operation')

    with tempfile.TemporaryDirectory(prefix='') as temporary:
        settings = Path(temporary) / 'ClaudeLaunchCenter' / 'settings.json'
        previous_local = os.environ.get('LOCALAPPDATA')
        previous_profile, previous_argv = sys.getprofile(), sys.argv
        previous_bytecode, previous_start = sys.dont_write_bytecode, threading.Thread.start

        def audit(event, args):
            if not active[0]:
                return
            if (event.startswith(('socket.', 'ctypes.')) or event in (
                    'subprocess.Popen', 'os.system', 'os.startfile', 'os.startfile/2',
                    'os.exec', 'os.spawn', 'os.posix_spawn', 'os.remove', 'os.rmdir',
                    'os.mkdir', 'os.rename')):
                forbidden(event)
            if event == 'open':
                mode, flags = args[1], args[2]
                if ((isinstance(mode, str) and any(c in mode for c in 'wax+')) or
                        (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))):
                    forbidden('file_write')
                if isinstance(args[0], (str, bytes, os.PathLike)):
                    path = Path(os.fsdecode(args[0]))
                    if (path.name.lower() in ('cookies', 'cookies-journal') or
                            path.name.lower() == 'settings.json' and path.resolve() != settings.resolve()):
                        forbidden('private_config_or_cookie_read')

        def observe(app):
            try:
                runtime, adapter = app._monitor_runtime, app._managed_adapter
                view = runtime.current() if type(runtime) is ManagedSessionRuntime else None
                observed.update(
                    actual_runtime=type(runtime) is ManagedSessionRuntime,
                    same_runtime_adapter=(adapter is not None and adapter.runtime is runtime
                        and app._monitor_binding_provider is adapter
                        and getattr(app._monitor_factory, '__self__', None) is adapter
                        and getattr(app._monitor_relay_snapshot, '__self__', None) is adapter),
                    idle=(view is not None and view.phase == 'idle' and view.session is None
                        and view.browser_evidence is None and view.relay_snapshot is None),
                    no_work=(runtime is not None and runtime._thread is None
                        and runtime._backend is None and runtime._factory is None
                        and app._monitor_session is None),
                    isolated_config=(app.config_path == settings and not app.saved
                        and app._monitor_selection is None
                        and runtime is not None and runtime.journal_path == settings.with_name('session-recovery.json')),
                    blank_fields=not any(app.fields[name].get() for name in (
                        'expected_ip', 'manager_executable', 'chrome_path', 'user_data_dir', 'chrome_profile')),
                    start_blocked=all(str(button['state']) == 'disabled' for button in (
                        app.start_monitor_button, app.stop_monitor_button, app.resume_monitor_button,
                        app.browser_button)),
                )
            except Exception as error:
                callback_errors.append(type(error).__name__)
            finally:
                # quit isolates this mainloop even if another Tk interpreter exists.
                app.root.quit()
                try:
                    app.request_close()
                    observed['normal_close'] = app._managed_closed is True
                except Exception as error:
                    callback_errors.append(type(error).__name__)

        def profile(frame, event, arg):
            if event != 'return':
                return
            if frame.f_code is tkinter.Tk.__init__.__code__:
                root = frame.f_locals['self']
                roots.append(root)
                root.withdraw()
                root.report_callback_exception = lambda kind, value, tb: callback_errors.append(kind.__name__)
            elif frame.f_code is module.App.__init__.__code__:
                sys.setprofile(previous_profile)
                app = frame.f_locals['self']
                app.root.after(100, lambda: observe(app))

        sys.addaudithook(audit)
        try:
            os.environ['LOCALAPPDATA'] = temporary
            sys.argv = [sys.argv[0]]
            sys.dont_write_bytecode = True
            threading.Thread.start = lambda *args, **kwargs: forbidden('thread_start')
            active[0] = True
            sys.setprofile(profile)
            exit_code = main()
        finally:
            sys.setprofile(previous_profile)
            for root in roots:
                try:
                    root.quit()
                    if root.winfo_exists():
                        root.destroy()
                except tkinter.TclError:
                    pass
            active[0] = False
            threading.Thread.start = previous_start
            sys.dont_write_bytecode, sys.argv = previous_bytecode, previous_argv
            if previous_local is None:
                os.environ.pop('LOCALAPPDATA', None)
            else:
                os.environ['LOCALAPPDATA'] = previous_local
        if (exit_code != 0 or attempts or callback_errors or len(roots) != 1 or
                len(observed) != 8 or not all(observed.values()) or any(Path(temporary).iterdir())):
            raise RuntimeError('actual production entry validation failed')
    return 'actual_main_runtime_connected_idle'


def self_check():
    root = None
    try:
        import hashlib
        import os
        import subprocess
        import tempfile
        import uuid
        import tkinter
        from src.ui.app import App
        from src.ui.shortcut_setup import ShortcutDialog
        from src.ui.onboarding import FirstSetupDialog, GuideDialog, PortDialog, THIRD_PARTY_CHECK_URL
        from src.ui.adapters import from_inspections
        from src.ui.model import Config, Status, render_report
        from src.core.backend import Check, Detection
        import src.ui.model
        import src.ui.adapters
        import src.core.backend
        import src.core.monitoring
        import src.core.release_trust as release_trust
        import src.browser.inspection
        import src.browser.session_binding
        import src.browser.cdp_pipe
        import src.browser.request_probe
        import src.protection.session_relay
        import src.protection.relay_identity
        import src.protection.dedicated_wfp
        import src.protection.managed_session
        from src.browser.shortcut_selection import ShortcutSelection, inspect_shortcut
        manifest = Path(release_trust.__file__).with_name(release_trust.MANIFEST_NAME).read_bytes()
        if hashlib.sha256(manifest).hexdigest() != release_trust.MANIFEST_SHA256:
            raise RuntimeError('baseline manifest hash mismatch')
        release_data = json.loads(manifest)
        if (not isinstance(release_data, dict) or release_data.get('schema') != 1 or
                not isinstance(release_data.get('files'), dict) or len(release_data['files']) != 19682 or
                release_data['files'].get('proxy manager.exe') != release_trust.EXECUTABLE_SHA256):
            raise RuntimeError('baseline manifest schema mismatch')
        root = tkinter.Tk()
        root.withdraw()
        version = str(root.tk.call('package', 'require', 'Tk'))
        config = Path(tempfile.gettempdir()) / ('claude-selfcheck-' + uuid.uuid4().hex) / 'settings.json'
        monitor_attempts = []
        def refuse_monitor(_config):
            monitor_attempts.append(True)
            raise RuntimeError('monitor must not start in self-check')
        app = App(root, config_path=config, monitor_factory=refuse_monitor)
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        if any(child.winfo_class() == 'TButton' and child.cget('text') == '网页候选观测'
               for child in descendants(root)) or str(app.browser_button['state']) != 'disabled':
            raise RuntimeError('observation entry or browser launch unexpectedly enabled')
        if (str(app.start_monitor_button['state']) != 'disabled' or app._monitor_browser_bound()
                or app._monitor_session is not None):
            raise RuntimeError('unconfirmed browser monitor unexpectedly enabled')
        app.start_monitor()
        if (monitor_attempts or app._monitor_session is not None or config.exists()
                or '未启用' not in app.monitor_summary.get()):
            raise RuntimeError('unconfirmed browser monitor did not fail closed')
        passed = Check('pass', '')
        unknown = Check('unknown', '')
        detection = Detection(passed, passed, passed, Check('unknown', 'Claude 首页返回 HTTP 403，服务未确认'),
                              unknown, mapping=passed, _owner_evidence=object())
        simulated = from_inspections(detection, None, desktop_status=passed,
                                     application_selected=True, mapping_mode='required')
        report = render_report(simulated, Config(mapping_mode='required', manager_executable=r'C:\example\proxy.exe',
                                                 manager_sha256='a' * 64))
        if (simulated.owner is not Status.PASS or simulated.common_status is not Status.UNKNOWN or
                simulated.can_start_desktop or simulated.can_start_browser or
                '监听归属与可信程序：通过' not in report or 'HTTP 403' not in report or '封号' in report):
            raise RuntimeError('simulated home 403 state invalid')
        app.open_first_setup()
        first = app._first_setup_dialog
        if (not isinstance(first, FirstSetupDialog) or app.saved or config.exists() or
                any(app.fields[name].get() for name in ('expected_ip', 'manager_executable', 'chrome_path', 'user_data_dir', 'chrome_profile')) or
                str(first.expected_ip_entry['show']) != '●' or str(app.browser_button['state']) != 'disabled'):
            raise RuntimeError('first setup entry unavailable')
        first.window.withdraw()
        first.port_button.invoke()
        port_dialog = app._port_dialog
        if not isinstance(port_dialog, PortDialog) or str(port_dialog.apply_button['state']) != 'disabled' or port_dialog.busy:
            raise RuntimeError('first setup port entry unavailable')
        port_dialog.window.withdraw()
        port_dialog.window.destroy()
        first.window.destroy()
        app.open_guide()
        guide = app._guide_dialog
        if not isinstance(guide, GuideDialog):
            raise RuntimeError('guide entry unavailable')
        guide.window.withdraw()
        instructions = guide.text.get('1.0', 'end')
        if (THIRD_PARTY_CHECK_URL != 'https://ip.net.coffee/claude/' or
                THIRD_PARTY_CHECK_URL not in instructions or
                not all(word in instructions for word in ('第三方', '辅助', '未确认'))):
            raise RuntimeError('guide text invalid')
        clipboard = []
        guide.window.clipboard_clear = lambda: clipboard.clear()
        guide.window.clipboard_append = lambda value: clipboard.append(value)
        guide.copy_button.invoke()
        if (clipboard != [THIRD_PARTY_CHECK_URL] or '已复制' not in guide.copy_status.get() or
                app.result.can_start_browser or str(app.browser_button['state']) != 'disabled'):
            raise RuntimeError('guide action invalid')
        guide.window.destroy()
        app.open_shortcut()
        shortcut = app._shortcut_dialog
        if (not isinstance(shortcut, ShortcutDialog) or str(shortcut.apply_button['state']) != 'disabled'
                or str(app.browser_button['state']) != 'disabled'):
            raise RuntimeError('shortcut entry unavailable')
        shortcut.window.withdraw()
        with tempfile.TemporaryDirectory(prefix='') as temporary:
            folder = Path(temporary)
            dummy_chrome = folder / 'chrome.exe'
            dummy_chrome.touch()
            link = folder / 'test.lnk'
            arguments = f'--user-data-dir="{folder}" --profile-directory=Default'
            script = ("[Console]::InputEncoding=[Text.UTF8Encoding]::new();"
                      "$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
                      "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($d.link);"
                      "$s.TargetPath=$d.target;$s.Arguments=$d.arguments;$s.Save()")
            shell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
            payload = json.dumps({'link': str(link), 'target': str(dummy_chrome), 'arguments': arguments}).encode('utf-8')
            subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', script], input=payload,
                           capture_output=True, timeout=10, check=True,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            observed = inspect_shortcut(str(link))
            if (observed.status != 'complete' or observed.chrome_executable != str(dummy_chrome)
                    or observed.user_data_dir != str(folder) or observed.profile_directory != 'Default'):
                raise RuntimeError('shortcut parsing failed')
            shortcut._generation = app._generation
            shortcut._queue.put((app._generation, observed))
            shortcut._poll()
            if str(shortcut.apply_button['state']) != 'normal':
                raise RuntimeError('shortcut candidate unavailable')
            shortcut.apply()
            if (app.fields['chrome_path'].get() != str(dummy_chrome) or
                    app.fields['user_data_dir'].get() != str(folder) or
                    app.fields['chrome_profile'].get() != 'Default' or app.result.can_start_browser):
                raise RuntimeError('shortcut apply state invalid')
            shortcut._generation = app._generation
            shortcut._queue.put((app._generation, ShortcutSelection('manual_review', str(dummy_chrome), str(folder), 'Default')))
            shortcut._poll()
            if str(shortcut.apply_button['state']) != 'disabled' or app.result.can_start_browser:
                raise RuntimeError('shortcut review did not fail closed')
            local = folder
            default_dir = local / 'Google' / 'Chrome' / 'User Data'
            (default_dir / 'P').mkdir(parents=True)
            default_link = folder / 'default.lnk'
            default_arguments = '--profile-directory="P" https://claude.ai/'
            payload = json.dumps({'link': str(default_link), 'target': str(dummy_chrome),
                                  'arguments': default_arguments}).encode('utf-8')
            subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', script], input=payload,
                           capture_output=True, timeout=10, check=True,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            original_local = os.environ.get('LOCALAPPDATA')
            try:
                os.environ['LOCALAPPDATA'] = str(local)
                default = inspect_shortcut(str(default_link), allowed_url='https://claude.ai/')
                mismatch = inspect_shortcut(str(default_link), allowed_url='https://claude.ai/new')
            finally:
                if original_local is None:
                    os.environ.pop('LOCALAPPDATA', None)
                else:
                    os.environ['LOCALAPPDATA'] = original_local
            if (default.status != 'complete' or default.data_dir_source != 'default_candidate' or
                    default.user_data_dir != str(default_dir) or default.profile_directory != 'P' or
                    mismatch.status != 'manual_review'):
                raise RuntimeError('default shortcut parse failed')
            shortcut._generation = app._generation
            shortcut._queue.put((app._generation, default))
            shortcut._poll()
            if str(shortcut.apply_button['state']) != 'normal' or '默认' not in shortcut.status.get():
                raise RuntimeError('default shortcut candidate unavailable')
            shortcut.apply()
            if (app.fields['user_data_dir'].get() != str(default_dir) or
                    app.fields['chrome_profile'].get() != 'P' or app.result.can_start_browser):
                raise RuntimeError('default shortcut apply state invalid')
            shortcut._generation = app._generation
            shortcut._queue.put((app._generation, mismatch))
            shortcut._poll()
            if str(shortcut.apply_button['state']) != 'disabled' or app.result.can_start_browser:
                raise RuntimeError('mismatched shortcut did not fail closed')
        shortcut.window.destroy()
        app.open_release_setup()
        setup = app._release_dialog
        if (setup is None or str(setup.accept_button['state']) != 'disabled' or
                setup.installer.get() or setup.directory.get()):
            raise RuntimeError('release setup entry unavailable')
        setup.window.withdraw()
        setup.window.destroy()
        root.destroy()
        root = None
        production_entry = _check_production_entry()
        print(json.dumps({'status': 'passed', 'scope': 'imports_tk_business_entry',
                          'observation_entry': 'absent_web_launch_blocked', 'baseline_manifest': 'hash_and_schema_validated',
                          'release_setup': 'window_only_no_selection',
                          'shortcut_selection': 'entry_available_fail_closed',
                          'default_shortcut': 'matching_url_and_mismatch_fail_closed',
                          'guide': 'auxiliary_copy_simulated_no_network',
                          'first_setup': 'window_only_no_user_config',
                          'home_403': 'simulated_owner_display_and_launch_blocked',
                          'dedicated_browser_scope': 'unconfirmed_no_monitor_no_block',
                          'protection_modules': 'imported_no_start',
                          'production_entry': production_entry,
                          'tk': version}))
        return 0
    except Exception as exc:
        if root is not None:
            root.destroy()
        report = {'status': 'failed', 'scope': 'imports_tk_business_entry', 'failure': type(exc).__name__}
        if isinstance(exc, ModuleNotFoundError):
            report['module'] = exc.name
        print(json.dumps(report))
        return 1


def main():
    if sys.argv[1:] == ['--self-check']:
        return self_check()
    if sys.argv[1:]:
        return 2
    from src.ui.app import main as launch_app
    launch_app()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
