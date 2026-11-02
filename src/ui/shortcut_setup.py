"""Present metadata from a shortcut the user explicitly selects."""
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from src.browser.shortcut_selection import ShortcutSelection, inspect_shortcut


class ShortcutDialog:
    def __init__(self, app, inspector=inspect_shortcut):
        self.app = app
        self.inspector = inspector
        self.window = tk.Toplevel(app.root)
        self.window.title('选择已有 Chrome 快捷方式')
        self.window.geometry('780x360')
        self.window.columnconfigure(1, weight=1)
        self.status = tk.StringVar(value='选择本机快捷方式后只读解析；不会启动或修改快捷方式。')
        self.executable = tk.StringVar()
        self.data_dir = tk.StringVar()
        self.profile = tk.StringVar()
        self.busy = False
        self._generation = None
        self._candidate = None
        self._queue = queue.Queue()
        self._closed = False
        self._lock = threading.Lock()
        ttk.Label(self.window, text='只提取可识别的 Chrome 程序和配置目录。额外或危险参数需要人工核对，不能直接采用。', wraplength=740).grid(row=0, column=0, columnspan=2, sticky='w', padx=16, pady=10)
        self.choose_button = ttk.Button(self.window, text='选择快捷方式', command=self.choose)
        self.choose_button.grid(row=1, column=1, sticky='e', padx=16)
        for row, label, var in ((2, 'Chrome 程序', self.executable), (3, '用户数据目录', self.data_dir), (4, '配置目录', self.profile)):
            ttk.Label(self.window, text=label).grid(row=row, column=0, sticky='w', padx=16, pady=5)
            ttk.Entry(self.window, textvariable=var, state='readonly').grid(row=row, column=1, sticky='ew', padx=(0, 16), pady=5)
        ttk.Label(self.window, textvariable=self.status, wraplength=740).grid(row=5, column=0, columnspan=2, sticky='w', padx=16, pady=10)
        self.apply_button = ttk.Button(self.window, text='填入表单（不保存）', command=self.apply, state='disabled')
        self.apply_button.grid(row=6, column=1, sticky='e', padx=16)
        self._poll_id = self.window.after(50, self._poll)
        self.window.bind('<Destroy>', self._destroy, add='+')

    def _clear(self):
        self._candidate = None
        self._generation = None
        self.executable.set('')
        self.data_dir.set('')
        self.profile.set('')
        self.apply_button.configure(state='disabled')

    def choose(self):
        if self.busy or self.app._operation == 'launch':
            return
        path = filedialog.askopenfilename(parent=self.window, title='选择已有 Chrome 快捷方式', filetypes=[('Windows 快捷方式', '*.lnk')])
        if not path:
            return
        self._clear()
        self._generation = self.app._generation
        generation = self._generation
        allowed_url = self.app.fields['url'].get().strip()
        self.busy = True
        self.choose_button.configure(state='disabled')
        self.status.set('正在只读解析快捷方式。')
        def work():
            try:
                result = self.inspector(path, allowed_url=allowed_url)
            except Exception:
                result = None
            with self._lock:
                if not self._closed:
                    self._queue.put((generation, result))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                generation, result = self._queue.get_nowait()
                self.busy = False
                self.choose_button.configure(state='normal')
                if generation != self.app._generation:
                    self._clear()
                    self.status.set('配置已变化，旧结果已丢弃，请重新选择。')
                elif not isinstance(result, ShortcutSelection) or result.status not in ('complete', 'incomplete', 'manual_review'):
                    self._clear()
                    self.status.set('无法识别快捷方式或 Chrome 程序，请核对所选文件。')
                else:
                    self.executable.set(result.chrome_executable)
                    self.data_dir.set(result.user_data_dir or '')
                    self.profile.set(result.profile_directory or '')
                    if result.status == 'manual_review':
                        self.status.set('存在不匹配的网址、额外或重复参数，或路径格式不安全；请人工核对，不能直接填入。浏览器身份及实际代理未确认。')
                    elif result.status == 'incomplete':
                        self.status.set('缺少用户数据目录或配置目录，不能直接填入；请人工核对。浏览器身份及实际代理未确认。')
                    elif result.data_dir_source not in ('shortcut', 'default_candidate') or not result.user_data_dir or not result.profile_directory or any(ord(c) < 32 or ord(c) == 127 for v in (result.chrome_executable, result.user_data_dir, result.profile_directory) for c in v):
                        self.status.set('路径或配置目录无法安全采用，请人工核对。浏览器身份及实际代理未确认。')
                    else:
                        self._candidate = result
                        self.apply_button.configure(state='normal')
                        source = '用户数据目录来自 Chrome 默认位置推定，请确认实际使用的是该目录。' if result.data_dir_source == 'default_candidate' else '用户数据目录来自快捷方式参数。'
                        self.status.set(source + '请核对候选并主动填入；尚未保存。浏览器身份和实际代理未确认，网页启动仍禁用。')
        except queue.Empty:
            pass
        if self._generation is not None and self._generation != self.app._generation:
            self._clear()
            self.status.set('配置已变化，旧结果已丢弃，请重新选择。')
        self._poll_id = self.window.after(50, self._poll)

    def apply(self):
        if self.busy or self._candidate is None or self._generation != self.app._generation or self.app._operation == 'launch':
            self._clear()
            self.status.set('没有可用候选，或配置已变化；请重新选择。')
            return
        candidate = self._candidate
        self._clear()
        self.app.fields['chrome_path'].set(candidate.chrome_executable)
        self.app.fields['user_data_dir'].set(candidate.user_data_dir)
        self.app.fields['chrome_profile'].set(candidate.profile_directory)
        self.status.set('已填入表单，尚未保存；浏览器身份及实际代理未确认，网页启动仍禁用。')

    def _destroy(self, event):
        if event.widget is self.window:
            with self._lock:
                self._closed = True
                while not self._queue.empty():
                    self._queue.get_nowait()
            self._candidate = None
            self.window.after_cancel(self._poll_id)
