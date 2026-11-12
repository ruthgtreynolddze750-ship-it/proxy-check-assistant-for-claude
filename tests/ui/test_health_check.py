import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path

root_path = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root_path))
sys.path.insert(0, str(root_path / 'src'))
from src.core.release_trust import EXECUTABLE_SHA256
from ui.app import App
from ui.health_check import (HealthInput, HealthItem, repair_manager, repair_plan, report, restart_manager,
                             run_health_check, summary)
from ui.onboarding import PortCandidates

EXE = 'C:\\Users\\someone\\AppData\\Local\\Programs\\@luminati-ioluminati-proxy\\Proxy Manager.exe'
FINGERPRINT = 'a' * 64
NOW = 1793600000.0


def data(**overrides):
    values = dict(port=24001, manager_port=22999, expected_ip='203.0.113.25', ip_url='https://ip.example/check',
                  expected_zone='claude_pc2', manager_executable=EXE, manager_sha256=FINGERPRINT)
    values.update(overrides)
    return HealthInput(**values)


class Stubs:
    def __init__(self):
        self.requests = []
        self.exit_ip = '203.0.113.25'
        self.trace_ip = '203.0.113.25'
        self.stamp = NOW + 10

    cf_ip = '203.0.113.25'
    cn_ip = '203.0.113.25'
    loc = 'US'

    def proxy_request(self, port, url, allow_redirects=False):
        self.requests.append((port, url))
        if 'one.one.one.one' in url:
            if self.cf_ip is None:
                raise OSError('down')
            return f'h=one.one.one.one\nip={self.cf_ip}\nloc={self.loc}\n'.encode()
        if 'trace' in url:
            return f'fl=1\nh=claude.ai\nip={self.trace_ip}\nts={self.stamp}\nloc={self.loc}\n'.encode()
        if 'ip138' in url or 'ip.cn' in url:
            if self.cn_ip is None:
                raise OSError('down')
            return f'<html>您的IP是：[{self.cn_ip}] 来自：美国</html>'.encode()
        return self.exit_ip.encode()

    def manager_json(self, port, path):
        if path == '/api/proxies_running':
            return [{'port': 24000, 'zone': 'claude_pc2'}, {'port': 24001, 'zone': 'claude_pc2'}]
        return {'zones': [{'name': 'claude_pc2', 'plan': {'type': 'static_res'}}]}

    def options(self, **overrides):
        values = dict(running=lambda: (EXE,), discover=lambda: PortCandidates('observed', (22225, 22999, 24000, 24001)),
                      defaults=lambda path: (22999, 24000), digest=lambda path: EXECUTABLE_SHA256,
                      processes=lambda: ('verge-mihomo.exe', 'Proxy Manager.exe'),
                      system_proxy=lambda: (True, '127.0.0.1:7897', False), manager_json=self.manager_json,
                      proxy_request=self.proxy_request, desktop=lambda: (('Claude_x!Claude',), 'pass'),
                      probe=lambda ports: (), locale=lambda: ('Pacific Standard Time', 'en-US', 'en-US'),
                      now=lambda: NOW, environ={})
        values.update(overrides)
        return values


def by_name(items):
    return {item.name: item for item in items}


class HealthCheckTests(unittest.TestCase):
    def setUp(self):
        self.stubs = Stubs()

    def run_check(self, value=None, **overrides):
        return by_name(run_health_check(value or data(), **self.stubs.options(**overrides)))

    def test_healthy_machine_passes_every_item_and_report_hides_private_values(self):
        items = run_health_check(data(), **self.stubs.options())
        self.assertEqual([item.name for item in items if item.status != 'ok'], [])
        self.assertEqual(len(self.stubs.requests), 4)
        self.assertTrue(any('one.one.one.one' in url for _, url in self.stubs.requests))
        text = report(items)
        for secret in ('203.0.113.25', EXE, 'someone', FINGERPRINT, EXECUTABLE_SHA256):
            self.assertNotIn(secret, text)
        self.assertIn('203.0.*.*', text)
        self.assertIn('没发现会挡住启动的问题', summary(items))

    def test_manager_not_running_explains_and_sends_no_request(self):
        items = self.run_check(running=lambda: (), discover=lambda: PortCandidates(), processes=lambda: ())
        self.assertEqual(items['代理管理器在运行吗'].status, 'fail')
        self.assertIn('没有托盘图标', items['代理管理器在运行吗'].fix)
        self.assertEqual(items['Clash（翻墙软件）'].status, 'warn')
        self.assertEqual(items['经代理上网'].status, 'skip')
        self.assertEqual(self.stubs.requests, [])

    def test_manager_open_but_ports_dead_points_to_restart(self):
        items = self.run_check(discover=lambda: PortCandidates())
        self.assertEqual(items['代理管理器在运行吗'].status, 'ok')
        self.assertEqual(items['代理管理器的端口'].status, 'fail')
        self.assertIn('重启电脑', items['代理管理器的端口'].fix)
        self.assertEqual(self.stubs.requests, [])

    def test_hidden_listen_table_is_confirmed_by_connecting(self):
        items = self.run_check(discover=lambda: PortCandidates(),
                               probe=lambda ports: tuple(port for port in ports if port in (22999, 24000, 24001)))
        self.assertEqual(items['系统端口列表'].status, 'warn')
        self.assertEqual(items['代理管理器的端口'].status, 'ok')
        self.assertEqual(items['代理端口'].status, 'ok')
        self.assertEqual(items['Claude 看到的 IP'].status, 'ok')
        self.assertEqual(len(self.stubs.requests), 4)

    def test_partly_hidden_listen_table_probes_only_the_missing_ports(self):
        probed = []
        def probe(ports):
            probed.append(tuple(ports))
            return tuple(ports)
        items = self.run_check(discover=lambda: PortCandidates('observed', (24000, 24001)), probe=probe)
        self.assertEqual(probed, [(22999,)])
        self.assertEqual(items['代理管理器的端口'].status, 'ok')
        self.assertEqual(items['系统端口列表'].status, 'warn')

    def test_three_exits(self):
        self.stubs.cn_ip = '198.51.100.9'
        item = self.run_check()['三个出口是否一致']
        self.assertEqual(item.status, 'fail')
        self.assertIn('198.51.*.*', item.detail)
        self.assertNotIn('198.51.100.9', item.detail)
        self.stubs.cn_ip = None
        self.assertEqual(self.run_check()['三个出口是否一致'].status, 'warn')
        self.stubs.cn_ip = '203.0.113.25'
        self.stubs.cf_ip = '198.51.100.9'
        self.assertEqual(self.run_check()['三个出口是否一致'].status, 'fail')

    def test_time_zone_and_language_against_the_exit_country(self):
        item = self.run_check(locale=lambda: ('China Standard Time', 'zh-CN', 'zh-CN'))['时区和语言']
        self.assertEqual(item.status, 'warn')
        self.assertIn('不是美国的时区', item.detail)
        self.assertIn('请你自己改', item.fix)
        item = self.run_check(locale=lambda: ('Central Standard Time', 'zh-CN', 'en-US'))['时区和语言']
        self.assertEqual(item.status, 'ok')
        item = self.run_check(locale=lambda: ('Central Standard Time', 'zh-CN', 'zh-CN'))['时区和语言']
        self.assertEqual(item.status, 'warn')
        self.assertNotIn('时区是', item.detail)
        self.stubs.loc = 'ZZ'
        self.assertEqual(self.run_check()['时区和语言'].status, 'skip')

    def test_manager_api_silent(self):
        def broken(port, path):
            raise OSError('down')
        items = self.run_check(manager_json=broken)
        self.assertEqual(items['助手连得上代理管理器吗'].status, 'fail')

    def test_system_proxy_on_the_manager_port_is_flagged(self):
        items = self.run_check(system_proxy=lambda: (True, 'http=127.0.0.1:24001;https=127.0.0.1:24001', False))
        self.assertEqual(items['Windows 系统代理'].status, 'fail')
        self.assertIn('请你自己改', items['Windows 系统代理'].fix)
        self.assertEqual(self.run_check(system_proxy=lambda: (False, '', False))['Windows 系统代理'].status, 'ok')

    def test_wrong_exit_and_trace_ip_are_masked_failures(self):
        self.stubs.exit_ip = self.stubs.trace_ip = '198.51.100.7'
        items = self.run_check()
        for name in ('经代理上网', 'Claude 看到的 IP'):
            self.assertEqual(items[name].status, 'fail')
            self.assertIn('198.51.*.*', items[name].detail)
            self.assertNotIn('198.51.100.7', items[name].detail)
            self.assertIn('先别登录', items[name].fix)

    def test_missing_expected_ip_is_a_warning_not_a_pass(self):
        items = self.run_check(data(expected_ip=''))
        self.assertEqual(items['Claude 看到的 IP'].status, 'warn')

    def test_proxy_unreachable_points_to_clash_and_balance(self):
        def broken(port, url, allow_redirects=False):
            raise OSError('reset')
        items = self.run_check(proxy_request=broken)
        self.assertEqual(items['经代理上网'].status, 'fail')
        self.assertIn('Clash', items['经代理上网'].fix)
        self.assertEqual(items['Claude 看到的 IP'].status, 'fail')

    def test_clock_drift(self):
        self.stubs.stamp = NOW + 3600
        items = self.run_check()
        self.assertEqual(items['电脑时间'].status, 'fail')
        self.assertIn('60 分钟', items['电脑时间'].detail)

    def test_baseline_version_and_zone_problems(self):
        items = self.run_check(data(manager_executable='', manager_sha256=''))
        self.assertIn('一键查找并填入', items['保存的管理器基准'].fix)
        items = self.run_check(data(manager_executable='D:\\Other\\Proxy Manager.exe'))
        self.assertEqual(items['保存的管理器基准'].status, 'fail')
        items = self.run_check(digest=lambda path: 'b' * 64)
        self.assertEqual(items['代理管理器版本'].status, 'fail')
        items = self.run_check(data(expected_zone='typo'))
        self.assertEqual(items['代理端口'].status, 'fail')
        self.assertIn('claude_pc2', items['代理端口'].fix)

    def test_empty_form_ports_are_found_from_the_zone(self):
        items = self.run_check(data(port=None, manager_port=None))
        self.assertEqual(items['代理端口'].status, 'ok')
        self.assertEqual({port for port, url in self.stubs.requests}, {24001})

    def test_desktop(self):
        items = self.run_check(desktop=lambda: ((), 'pass'))
        self.assertEqual(items['Claude 桌面端'].status, 'fail')
        items = self.run_check(desktop=lambda: (('x',), 'fail'))
        self.assertEqual(items['Claude 桌面端'].status, 'warn')
        self.assertNotIn('授权', items)

    def test_summary_names_the_first_problem(self):
        items = (HealthItem('甲', 'ok', ''), HealthItem('乙', 'fail', '坏了', '这样修'), HealthItem('丙', 'fail', '', ''))
        self.assertEqual(summary(items), '体检完成：发现 2 个问题。先处理“乙”：这样修')


class RepairTests(unittest.TestCase):
    def test_plan(self):
        dead = (HealthItem('代理管理器的端口', 'fail', 'x'),)
        self.assertEqual(repair_plan(dead), ['restart'])
        self.assertEqual(repair_plan(dead + (HealthItem('代理管理器版本', 'fail', 'x'),)), [])
        self.assertEqual(repair_plan((HealthItem('代理端口', 'fail', '代理端口 24001 没在工作。'),)), ['restart'])
        self.assertEqual(repair_plan((HealthItem('代理端口', 'fail', '名称不一样'),)), [])
        self.assertEqual(repair_plan((HealthItem('保存的管理器基准', 'fail', 'x'),)), ['reverify'])
        self.assertEqual(repair_plan((HealthItem('时区和语言', 'warn', 'x'),)), [])

    def restart(self, **overrides):
        self.killed, self.started = [], []
        state = {'running': [(5, EXE), (6, EXE)]}
        def kill(pids):
            self.killed.append(tuple(pids))
            state['running'] = []
        options = dict(desktop=lambda: (('x',), 'pass'), processes=lambda: tuple(state['running']), kill=kill,
                       start=self.started.append, ports_ready=lambda: True, sleep=lambda s: None)
        options.update(overrides)
        return restart_manager(EXE, **options)

    def test_restart_kills_only_this_install_and_starts_it_once(self):
        ok, message = self.restart()
        self.assertTrue(ok)
        self.assertEqual(self.killed, [(5, 6)])
        self.assertEqual(self.started, [EXE])

    def test_restart_refuses_while_claude_may_be_open(self):
        for state in ('fail', 'unknown'):
            ok, message = self.restart(desktop=lambda state=state: (('x',), state))
            self.assertFalse(ok)
            self.assertIn('正常退出', message)
            self.assertEqual((self.killed, self.started), ([], []))

    def test_restart_leaves_other_installs_alone(self):
        ok, message = self.restart(processes=lambda: ((5, EXE), (9, 'D:\\Other\\Proxy Manager.exe')))
        self.assertFalse(ok)
        self.assertEqual((self.killed, self.started), ([], []))

    def test_restart_starts_when_not_running_and_reports_slow_ports(self):
        ok, message = self.restart(processes=lambda: ())
        self.assertTrue(ok)
        self.assertEqual((self.killed, self.started), ([], [EXE]))
        ticks = iter(range(0, 1000, 10))
        ok, message = self.restart(processes=lambda: (), ports_ready=lambda: False, clock=lambda: next(ticks))
        self.assertFalse(ok)
        self.assertIn('90 秒', message)

    def test_restart_does_not_start_if_the_old_one_will_not_end(self):
        ticks = iter(range(0, 1000, 5))
        ok, message = self.restart(kill=lambda pids: None, clock=lambda: next(ticks))
        self.assertFalse(ok)
        self.assertEqual(self.started, [])

    def test_repair_manager_waits_for_both_ports(self):
        seen = {}
        def restart(executable, ports_ready):
            seen['exe'] = executable
            seen['ready'] = ports_ready()
            return True, ''
        repair_manager(data(), restart=restart, running=lambda: (EXE,),
                       discover=lambda: PortCandidates('observed', (24001,)), defaults=lambda path: (22999, 24000),
                       probe=lambda ports: tuple(ports), manager_json=lambda port, path: [{'port': 24001}])
        self.assertEqual(seen, {'exe': EXE, 'ready': True})


class HealthWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.app = App(self.root, config_path=Path(self.temp.name) / 'config.json')

    def tearDown(self):
        self.root.update()
        self.root.destroy()
        self.temp.cleanup()

    def wait(self, predicate):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            self.root.update()
            if predicate():
                return
            time.sleep(.01)
        raise AssertionError('等待超时')

    def test_button_runs_check_with_form_values_and_changes_nothing(self):
        seen = []
        self.app.health_check = lambda value: seen.append(value) or (HealthItem('代理端口', 'fail', '端口没在工作。', '重启电脑'),)
        self.app.fields['port'].set('24001')
        self.app.fields['expected_zone'].set('z')
        saved = self.app.saved
        self.app.health_button.invoke()
        dialog = self.app._health_dialog
        self.wait(lambda: not dialog.busy)
        self.assertEqual((seen[0].port, seen[0].manager_port, seen[0].expected_zone), (24001, None, 'z'))
        self.assertIn('端口没在工作', dialog.text.get('1.0', 'end'))
        self.assertIn('重启电脑', dialog.status.get())
        dialog.copy_button.invoke()
        self.assertIn('环境体检报告', self.root.clipboard_get())
        self.assertEqual(self.app.saved, saved)
        self.assertFalse(Path(self.temp.name, 'config.json').exists())

    def test_repair_button_confirms_runs_and_rechecks(self):
        from unittest.mock import patch
        results = [(HealthItem('代理管理器的端口', 'fail', '没在工作', '重启'), HealthItem('时区和语言', 'warn', 'x', 'y')),
                   (HealthItem('代理管理器的端口', 'ok', '好了'),)]
        self.app.health_check = lambda value: results.pop(0)
        calls, opened = [], []
        self.app.health_repair = lambda value: calls.append(value) or (True, '代理管理器已重新启动，端口正在工作。')
        self.app.health_button.invoke()
        dialog = self.app._health_dialog
        dialog._open_settings = opened.append
        self.wait(lambda: not dialog.busy and dialog.items)
        self.assertEqual(str(dialog.repair_button['state']), 'normal')
        dialog.zone_button.invoke()
        dialog.language_button.invoke()
        self.assertEqual(opened, ['ms-settings:dateandtime', 'ms-settings:regionlanguage'])
        with patch('tkinter.messagebox.askokcancel', return_value=False):
            dialog.repair_button.invoke()
        self.assertEqual(calls, [])
        with patch('tkinter.messagebox.askokcancel', return_value=True) as ask:
            dialog.repair_button.invoke()
        self.assertIn('不会强制关闭 Claude', ask.call_args.args[1])
        self.wait(lambda: not dialog.busy and dialog.items and dialog.items[0].status == 'ok')
        self.assertEqual(len(calls), 1)
        self.assertEqual(str(dialog.repair_button['state']), 'disabled')

    def test_wizard_has_health_button_and_prefills_the_check_url(self):
        self.assertEqual(self.app.fields['ip_url'].get(), '')
        self.app.open_first_setup()
        wizard = self.app._first_setup_dialog
        self.assertEqual(self.app.fields['ip_url'].get(), 'https://api.ipify.org')
        self.app.health_check = lambda value: ()
        wizard.health_button.invoke()
        self.assertIsNotNone(self.app._health_dialog)


if __name__ == '__main__':
    unittest.main()
