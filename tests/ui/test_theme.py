"""Light theme (UI option A): primary actions stand out and the two status lines follow their state. Looks only."""
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from tkinter import ttk

from src.ui import app as app_module
from src.ui.theme import tone_for


class ToneTests(unittest.TestCase):
    def test_failure_words_win_over_unconfirmed(self):
        self.assertEqual(tone_for('出口 IP 与预期不一致 · 网页端：未确认'), 'Bad.TLabel')
        self.assertEqual(tone_for('持续监测：异常，已断开'), 'Bad.TLabel')

    def test_unconfirmed_is_warning_and_passed_is_good(self):
        self.assertEqual(tone_for('启动前共同检测：未确认 · 网页端：未确认'), 'Warn.TLabel')
        self.assertEqual(tone_for('启动前共同检测：通过 · 桌面端：可启动'), 'Good.TLabel')


class ThemedAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = app_module.App(self.root, backend=app_module.UnconnectedBackend(),
                                  config_path=Path(self.temp.name) / 'settings.json')

    def tearDown(self):
        self.root.destroy()
        self.temp.cleanup()

    def test_primary_actions_use_the_accent_style(self):
        for button in (self.app.detect_button, self.app.desktop_button, self.app.browser_button,
                       self.app.start_monitor_button, self.app.save_button):
            self.assertEqual(str(button.cget('style')), 'Accent.TButton')
        self.assertEqual(ttk.Style(self.root).theme_use(), 'clam')

    def test_status_lines_follow_their_text(self):
        self.app.summary.set('出口 IP 与预期不一致')
        self.assertEqual(str(self.app.summary_label.cget('style')), 'Bad.TLabel')
        self.app.monitor_summary.set('持续监测：未启动 · 阻断保护：未启用')
        self.assertEqual(str(self.app.monitor_summary_label.cget('style')), 'Warn.TLabel')


if __name__ == '__main__':
    unittest.main()
