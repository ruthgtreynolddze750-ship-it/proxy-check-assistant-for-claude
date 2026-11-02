"""User-selected offline release comparison; no implicit baseline acceptance."""
import ntpath
import queue
import re
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk


class ReleaseDialog:
    def __init__(self, app, inspector=None, clock=time.monotonic):
        self.app = app
        self.clock = clock
        self.inspector = inspector
        self.window = tk.Toplevel(app.root)
        self.window.title('核验管理器安装来源')
        self.window.geometry('760x500')
        self.window.columnconfigure(1, weight=1)
        self.installer = tk.StringVar()
        self.directory = tk.StringVar()
        self.summary = tk.StringVar(value='请选择本地安装包和管理器文件夹，然后开始核验。')
        self.package_status = tk.StringVar(value='发布包与历史记录：未确认')
        self.installed_status = tk.StringVar(value='安装目录文件对照：未确认')
        self.owner_status = tk.StringVar(value='监听进程与端口：未确认')
        self.signature_status = tk.StringVar(value='Windows 签名：未确认')
        self.busy = False
        self._generation = 0
        self._candidate = None
        self._snapshot = None
        self._candidate_at = None
        self._queue = queue.Queue()
        self._closed = False
        self._lifecycle_lock = threading.Lock()
        text = ('选择您保留的安装包和已安装的管理器文件夹；端口使用主窗口当前填写值。\n'
                '核验不会运行安装包、联网、修改代理或自动保存配置。当前仅支持历史记录的 1.679.135 版本。')
        ttk.Label(self.window, text=text, wraplength=720, justify='left').grid(row=0, column=0, columnspan=3, sticky='w', padx=16, pady=12)
        for row, label, variable, command in ((1, '本地安装包', self.installer, self.choose_installer), (2, '管理器文件夹', self.directory, self.choose_directory)):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=16, pady=5)
            ttk.Entry(self.window, textvariable=variable, state='readonly').grid(row=row, column=1, sticky='ew', pady=5)
            ttk.Button(self.window, text='选择', command=command).grid(row=row, column=2, padx=12)
        self.inspect_button = ttk.Button(self.window, text='开始核验', command=self.inspect)
        self.inspect_button.grid(row=3, column=2, padx=12, pady=6)
        for row, variable in enumerate((self.package_status, self.installed_status, self.owner_status, self.signature_status), 4):
            ttk.Label(self.window, textvariable=variable, wraplength=700).grid(row=row, column=0, columnspan=3, sticky='w', padx=16, pady=3)
        ttk.Label(self.window, textvariable=self.summary, wraplength=700).grid(row=8, column=0, columnspan=3, sticky='w', padx=16, pady=8)
        self.accept_button = ttk.Button(self.window, text='采用候选（还需保存配置）', command=self.accept, state='disabled')
        self.accept_button.grid(row=9, column=1, sticky='e', pady=8)
        ttk.Button(self.window, text='关闭', command=self.window.destroy).grid(row=9, column=2, padx=12)
        self._poll_id = self.window.after(50, self._poll)
        self.window.bind('<Destroy>', self._destroy, add='+')

    def _clear_candidate(self):
        self._generation += 1
        self._candidate = None
        self._snapshot = None
        self._candidate_at = None
        self.accept_button.configure(state='disabled')
        self.package_status.set('发布包与历史记录：未确认')
        self.installed_status.set('安装目录文件对照：未确认')
        self.owner_status.set('监听进程与端口：未确认')
        self.signature_status.set('Windows 签名：未确认')

    def choose_installer(self):
        selected = filedialog.askopenfilename(parent=self.window, title='选择已保存的发布安装包', filetypes=[('安装程序', '*.exe'), ('所有文件', '*.*')])
        if selected:
            if self.app._candidate_previous is not None:
                self.app._invalidate()
            self._clear_candidate()
            self.installer.set(selected)

    def choose_directory(self):
        selected = filedialog.askdirectory(parent=self.window, title='选择 Proxy Manager 安装文件夹')
        if selected:
            if self.app._candidate_previous is not None:
                self.app._invalidate()
            self._clear_candidate()
            self.directory.set(selected)

    def _current_snapshot(self):
        if self.app._operation == 'launch' or not self.installer.get() or not self.directory.get():
            return None
        try:
            manager_port = int(self.app.fields['manager_port'].get())
            proxy_port = int(self.app.fields['port'].get())
            if not 1 <= manager_port <= 65535 or not 1 <= proxy_port <= 65535 or manager_port == proxy_port:
                return None
        except ValueError:
            return None
        return (self.installer.get(), ntpath.normpath(ntpath.join(self.directory.get(), 'Proxy Manager.exe')), manager_port, proxy_port, self.app._generation, self._generation)

    def _run(self, phase, snapshot):
        self.busy = True
        self.inspect_button.configure(state='disabled')
        self.accept_button.configure(state='disabled')
        self.summary.set('正在核验本地文件，请稍候。')
        def work():
            try:
                inspector = self.inspector
                if inspector is None:
                    from src.core.release_trust import inspect_release_baseline
                    inspector = inspect_release_baseline
                value = inspector(*snapshot[:4], selected=True)
            except Exception:
                value = None
            with self._lifecycle_lock:
                if not self._closed:
                    self._queue.put((phase, snapshot, value))
        threading.Thread(target=work, daemon=True).start()

    def inspect(self):
        if self.busy:
            return
        self._clear_candidate()
        snapshot = self._current_snapshot()
        if snapshot is None:
            self.summary.set('请先选择安装包和文件夹，并在主窗口填写两个不同的有效端口。')
            return
        self._run('inspect', snapshot)

    def _show_evidence(self, result):
        self.package_status.set('发布包与历史记录：' + ('一致' if getattr(result, 'package_match', None) == 'pass' and getattr(result, 'release_source', None) == 'historical_release_record' else '未确认'))
        self.installed_status.set('安装目录文件对照：' + ('一致' if getattr(result, 'installed_match', None) == 'pass' else '未确认'))
        self.owner_status.set('监听进程与端口：' + ('一致' if getattr(result, 'owner_match', None) == 'pass' else '未确认'))
        signature = '历史检查未受信任（非本次实时签名检查）' if getattr(result, 'windows_signature', None) == 'historical_untrusted' else '未确认'
        self.signature_status.set('Windows 签名：' + signature)

    def _valid_result(self, result, snapshot):
        from src.core.release_trust import ReleaseInspection, Baseline, VERSION
        baseline = getattr(result, 'baseline', None)
        if not isinstance(result, ReleaseInspection) or not isinstance(baseline, Baseline):
            return False
        return (result.status == 'pass' and result.package_match == 'pass' and result.installed_match == 'pass'
                and result.owner_match == 'pass' and result.release_source == 'historical_release_record'
                and result.windows_signature == 'historical_untrusted' and baseline.version == VERSION
                and isinstance(baseline.manager_executable, str)
                and ntpath.normcase(ntpath.normpath(baseline.manager_executable)) == ntpath.normcase(ntpath.normpath(snapshot[1]))
                and isinstance(baseline.manager_sha256, str) and re.fullmatch(r'[0-9a-fA-F]{64}', baseline.manager_sha256) is not None)

    def _poll(self):
        try:
            while True:
                phase, snapshot, result = self._queue.get_nowait()
                self.busy = False
                self.inspect_button.configure(state='normal')
                if snapshot != self._current_snapshot():
                    self._clear_candidate()
                    self.summary.set('选择或配置已变化，旧结果已丢弃，请重新核验。')
                    continue
                self._show_evidence(result)
                if not self._valid_result(result, snapshot):
                    self._candidate = None
                    self._snapshot = None
                    self.summary.set('无法确认完整候选；版本不匹配或所需证据不足。')
                    continue
                if phase == 'inspect':
                    self._candidate = result.baseline
                    self._snapshot = snapshot
                    self._candidate_at = self.clock()
                    self.accept_button.configure(state='normal')
                    self.summary.set('已取得候选；签名未获信任。采用前将再次核验，随后还需单独保存配置。')
                elif self._candidate is not None and result.baseline == self._candidate:
                    inspector = self.inspector
                    baseline = self._candidate
                    def recheck():
                        check = inspector
                        if check is None:
                            from src.core.release_trust import inspect_release_baseline
                            check = inspect_release_baseline
                        later = check(*snapshot[:4], selected=True)
                        return self._valid_result(later, snapshot) and later.baseline == baseline
                    applied = self.app.apply_release_candidate(result.baseline, recheck)
                    self._candidate = None
                    self._snapshot = None
                    self.summary.set('已填入候选，尚未保存；请在主窗口检查并主动保存配置。' if applied else '当前无法采用候选，请重新核验。')
                else:
                    self._candidate = None
                    self._snapshot = None
                    self.summary.set('候选发生变化，未采用；请重新核验。')
        except queue.Empty:
            pass
        if self._candidate is not None and (self._snapshot != self._current_snapshot() or not 0 <= self.clock() - self._candidate_at < 60):
            self._clear_candidate()
            self.summary.set('配置已变化或候选已过期，请重新核验。')
        self._poll_id = self.window.after(50, self._poll)

    def accept(self):
        if self.busy or self._candidate is None or self._snapshot != self._current_snapshot() or not 0 <= self.clock() - self._candidate_at < 60:
            self._clear_candidate()
            self.summary.set('配置已变化或候选已过期，请重新核验。')
            return
        self._run('accept', self._snapshot)

    def _destroy(self, event):
        if event.widget is self.window:
            with self._lifecycle_lock:
                self._closed = True
                while not self._queue.empty():
                    self._queue.get_nowait()
            self._candidate = None
            self._snapshot = None
            self.window.after_cancel(self._poll_id)
