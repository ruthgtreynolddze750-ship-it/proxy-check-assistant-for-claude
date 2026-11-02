"""Temporary candidate observation; it does not establish browser trust."""
import threading
import tkinter as tk
from tkinter import ttk

from src.browser.evidence_bridge import EvidenceBridge


class CandidateController:
    def __init__(self, ttl_seconds=60):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._bridge = None
        self._timer = None
        self._used = False
        self._finished = threading.Event()
        self._finished.set()
        self.state = 'idle'

    def start(self, invitation):
        with self._lock:
            if self._used:
                raise ValueError('本次会话已结束。')
            bridge = EvidenceBridge.from_invitation(invitation, ttl_seconds=self._ttl)
            offer = bridge.start()
            self._used = True
            self._bridge = bridge
            self._finished.clear()
            self.state = 'waiting'
            self._timer = threading.Timer(self._ttl, self._finish, args=('expired',))
            self._timer.daemon = True
            try:
                self._timer.start()
            except Exception:
                self._bridge = None
                self.state = 'error'
                bridge.close()
                self._finished.set()
                raise
            return offer

    def _finish(self, state):
        with self._lock:
            bridge = self._bridge
            if bridge is not None:
                self._bridge = None
                self.state = state
                if self._timer is not None:
                    self._timer.cancel()
                self._timer = None
        if bridge is not None:
            try:
                bridge.close()
            finally:
                self._finished.set()
        else:
            self._finished.wait()

    def poll(self):
        with self._lock:
            bridge = self._bridge
            candidate = bridge is not None and bridge.result().diagnostic == 'candidate'
        if candidate:
            self._finish('candidate')
        return self.state

    def close(self):
        self._finish('cancelled')


class CandidateDialog:
    def __init__(self, root, ttl_seconds=60):
        self.root = root
        self.controller = CandidateController(ttl_seconds)
        self.window = tk.Toplevel(root)
        self.window.title('网页候选观测')
        self.window.geometry('720x360')
        self.window.columnconfigure(1, weight=1)
        self.invitation = tk.StringVar()
        self.pairing = tk.StringVar()
        self.status = tk.StringVar(value='尚未开始；浏览器身份及实际代理均未确认。')
        self._poll_id = None
        text = ('此功能需要专用 Chrome 中的候选扩展原型；尚未确认扩展安装或真实 Chrome 行为。\n'
                '先在扩展中发起候选检测，再把扩展中的候选邀请信息粘贴到这里。')
        ttk.Label(self.window, text=text, wraplength=680, justify='left').grid(row=0, column=0, columnspan=2, padx=16, pady=12, sticky='w')
        ttk.Label(self.window, text='候选邀请信息').grid(row=1, column=0, sticky='w', padx=16, pady=4)
        ttk.Entry(self.window, textvariable=self.invitation).grid(row=1, column=1, sticky='ew', padx=(0, 16), pady=4)
        self.start_button = ttk.Button(self.window, text='生成一次性授权', command=self.start)
        self.start_button.grid(row=2, column=1, sticky='e', padx=16, pady=6)
        ttk.Label(self.window, text='一次性配对信息').grid(row=3, column=0, sticky='w', padx=16, pady=4)
        ttk.Entry(self.window, textvariable=self.pairing, state='readonly').grid(row=3, column=1, sticky='ew', padx=(0, 16), pady=4)
        ttk.Label(self.window, text='将配对信息填回扩展并发送；仅本次有效，请勿转发。', wraplength=680).grid(row=4, column=0, columnspan=2, sticky='w', padx=16, pady=5)
        ttk.Label(self.window, textvariable=self.status, wraplength=680).grid(row=5, column=0, columnspan=2, sticky='w', padx=16, pady=5)
        ttk.Button(self.window, text='取消并关闭', command=self.window.destroy).grid(row=6, column=1, sticky='e', padx=16, pady=8)
        self.window.bind('<Destroy>', self._destroy, add='+')

    def start(self):
        try:
            offer = self.controller.start(self.invitation.get().strip())
        except Exception:
            self.status.set('无法开始：请核对候选邀请信息，或关闭已有候选通道。')
            return
        self.invitation.set('')
        self.pairing.set(offer.pairing_code())
        self.start_button.configure(state='disabled')
        self.status.set('等待扩展发送；授权最多有效 60 秒。')
        self._poll_id = self.window.after(50, self._poll)

    def _poll(self):
        state = self.controller.poll()
        if state == 'waiting':
            self._poll_id = self.window.after(50, self._poll)
            return
        self._poll_id = None
        self.pairing.set('')
        if state == 'candidate':
            self.status.set('已收到候选观测；浏览器身份及实际代理仍未确认，不能用于启动。')
        elif state == 'expired':
            self.status.set('本次授权已超时；如需重试请关闭窗口重新开始。')
        else:
            self.status.set('候选观测已结束，浏览器身份和实际代理仍未确认。')

    def _destroy(self, event):
        if event.widget is not self.window:
            return
        if self._poll_id is not None:
            self.window.after_cancel(self._poll_id)
            self._poll_id = None
        self.invitation.set('')
        self.pairing.set('')
        self.controller.close()
