"""Light ttk theme for the assistant (UI option A). Appearance only; no behaviour depends on it."""
from tkinter import font as tkfont, ttk

FAMILY = 'Microsoft YaHei UI'
BG, CARD, BORDER, BUTTON_BORDER = '#F3F5F8', '#FFFFFF', '#DDE2EA', '#C9D1DC'
TEXT, MUTED, DISABLED = '#1F2937', '#6B7280', '#A0A7B4'
ACCENT, ACCENT_HOVER, ACCENT_OFF = '#2563EB', '#1D4ED8', '#A9C1F5'
GOOD, WARN, BAD = '#15803D', '#B45309', '#B91C1C'

_BAD_WORDS = ('失败', '不一致', '异常', '熔断', '断开', '失效', '锁定', '过期', '无效')
_WARN_WORDS = ('未确认', '未启用', '未启动', '未检测', '未配置', '未授权', '即将到期')


def apply_theme(root):
    for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont', 'TkFixedFont'):
        tkfont.nametofont(name, root=root).configure(family=FAMILY, size=9)
    root.configure(background=BG)
    root.option_add('*Toplevel.background', BG)
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=BG, foreground=TEXT, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    focuscolor=ACCENT, troughcolor=BG, font=(FAMILY, 9))
    style.configure('TLabel', background=BG, foreground=TEXT)
    style.configure('Muted.TLabel', foreground=MUTED, font=(FAMILY, 8))
    style.configure('Title.TLabel', font=(FAMILY, 16, 'bold'))
    for tone, color in (('Good', GOOD), ('Warn', WARN), ('Bad', BAD)):
        style.configure(f'{tone}.TLabel', foreground=color, font=(FAMILY, 9, 'bold'))
    style.configure('TLabelframe', background=BG, bordercolor=BORDER, relief='solid', borderwidth=1)
    style.configure('TLabelframe.Label', background=BG, foreground=TEXT, font=(FAMILY, 9, 'bold'))
    style.configure('TButton', background=CARD, foreground=TEXT, padding=(10, 2), relief='solid', borderwidth=1,
                    bordercolor=BUTTON_BORDER)
    style.map('TButton', background=[('disabled', BG), ('active', '#EEF2F7')], foreground=[('disabled', DISABLED)],
              bordercolor=[('disabled', BORDER), ('focus', ACCENT)])
    style.configure('Accent.TButton', background=ACCENT, foreground='#FFFFFF', bordercolor=ACCENT, font=(FAMILY, 9, 'bold'))
    style.map('Accent.TButton', background=[('disabled', ACCENT_OFF), ('active', ACCENT_HOVER)],
              foreground=[('disabled', '#FFFFFF')], bordercolor=[('disabled', ACCENT_OFF), ('focus', ACCENT_HOVER)])
    style.configure('TEntry', fieldbackground=CARD, padding=(5, 1), bordercolor=BORDER)
    style.map('TEntry', bordercolor=[('focus', ACCENT)], fieldbackground=[('readonly', '#F8FAFC')])
    style.configure('TCombobox', fieldbackground=CARD, background=CARD, padding=(5, 1), arrowsize=12, arrowcolor=MUTED,
                    bordercolor=BORDER)
    style.map('TCombobox', fieldbackground=[('readonly', CARD)], background=[('active', '#EEF2F7')],
              bordercolor=[('focus', ACCENT)])
    style.configure('TNotebook', background=BG, bordercolor=BORDER, tabmargins=(0, 4, 0, 0))
    style.configure('TNotebook.Tab', padding=(14, 3), background=BG, foreground=MUTED, bordercolor=BORDER)
    style.map('TNotebook.Tab', background=[('selected', CARD)], foreground=[('selected', ACCENT)])
    style.configure('TCheckbutton', background=BG)
    style.configure('Vertical.TScrollbar', background=BG, arrowsize=12)


def style_report(text):
    text.configure(background=CARD, foreground=TEXT, relief='flat', borderwidth=0, padx=8, pady=4, font=(FAMILY, 9))


def tone_for(text):
    if any(word in text for word in _BAD_WORDS):
        return 'Bad.TLabel'
    if any(word in text for word in _WARN_WORDS):
        return 'Warn.TLabel'
    return 'Good.TLabel'


def follow_tone(label, variable):
    def update(*_):
        label.configure(style=tone_for(variable.get()))
    variable.trace_add('write', update)
    update()
