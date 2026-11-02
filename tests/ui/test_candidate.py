import hashlib
import hmac
import http.client
import json
import socket
import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ui.candidate import CandidateController, CandidateDialog
from ui.app import App
from ui.model import Status, render_report

EXTENSION = 'a' * 32
TARGET = 'https://claude.ai/cdn-cgi/trace'


def wait_until(predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('候选通道未及时完成')


def closed(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.1):
            return False
    except OSError:
        return True


def submit(port, token, session):
    nonce = str(uuid4())
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    headers = {'Origin': 'chrome-extension://' + EXTENSION}
    conn.request('GET', '/v1/challenge?nonce=' + nonce, headers=headers)
    response = conn.getresponse()
    assert response.status == 200
    response.read()
    conn.close()
    message = f'bridge-v1|client|{nonce}|{session}|{TARGET}|candidate|seen|observed'
    proof = hmac.new(token.encode('ascii'), message.encode(), hashlib.sha256).hexdigest()
    payload = {'version': 1, 'nonce': nonce, 'session_id': session, 'target': TARGET,
               'diagnostic': 'candidate', 'page_echo': 'seen', 'target_request': 'observed', 'proof': proof}
    headers['Content-Type'] = 'text/plain'
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    conn.request('POST', '/v1/evidence', body=json.dumps(payload), headers=headers)
    response = conn.getresponse()
    assert response.status == 200
    response.read()
    conn.close()


class CandidateTests(unittest.TestCase):
    def test_cancel_releases_listener_and_single_session_guard(self):
        controller = CandidateController(ttl_seconds=1)
        offer = controller.start(EXTENSION + '.' + str(uuid4()))
        controller.close()
        wait_until(lambda: closed(offer.port))
        another = CandidateController(ttl_seconds=1)
        try:
            another.start(EXTENSION + '.' + str(uuid4()))
        finally:
            another.close()

    def test_timeout_releases_listener_without_gui_loop(self):
        controller = CandidateController(ttl_seconds=.2)
        offer = controller.start(EXTENSION + '.' + str(uuid4()))
        wait_until(lambda: controller.state == 'expired')
        wait_until(lambda: closed(offer.port))
        controller.close()

    def test_cancel_during_incomplete_request_releases_listener(self):
        controller = CandidateController(ttl_seconds=5)
        offer = controller.start(EXTENSION + '.' + str(uuid4()))
        conn = socket.create_connection(('127.0.0.1', offer.port), timeout=1)
        try:
            conn.sendall(b'GET /v1/challenge?nonce=')
            time.sleep(.1)
            controller.close()
            wait_until(lambda: closed(offer.port))
        finally:
            conn.close()
            controller.close()

    def test_candidate_is_only_observation_and_listener_closes(self):
        controller = CandidateController(ttl_seconds=2)
        session = str(uuid4())
        offer = controller.start(EXTENSION + '.' + session)
        submit(offer.port, offer.token, session)
        self.assertEqual(controller.poll(), 'candidate')
        wait_until(lambda: closed(offer.port))
        self.assertNotIn(offer.token, repr(controller))
        self.assertEqual(controller.state, 'candidate')
        controller.close()

    def test_dialog_candidate_never_unlocks_and_does_not_enter_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = tk.Tk()
            try:
                app = App(root, config_path=Path(folder) / 'settings.json')
                dialog = CandidateDialog(root, ttl_seconds=2)
                session = str(uuid4())
                dialog.invitation.set(EXTENSION + '.' + session)
                dialog.start()
                port_text, token = dialog.pairing.get().split(':', 1)
                port = int(port_text)
                submit(port, token, session)
                def finished():
                    root.update()
                    return dialog.controller.state == 'candidate' and not dialog.pairing.get()
                wait_until(finished)
                self.assertEqual(str(app.browser_button['state']), 'disabled')
                self.assertIs(app.result.browser_proxy, Status.UNKNOWN)
                self.assertIs(app.result.browser_identity, Status.UNKNOWN)
                self.assertNotIn(token, render_report(app.result, app.config))
                wait_until(lambda: closed(port))
                dialog.window.destroy()
            finally:
                root.update()
                root.destroy()

    def test_closing_window_releases_listener(self):
        root = tk.Tk()
        dialog = CandidateDialog(root, ttl_seconds=2)
        dialog.invitation.set(EXTENSION + '.' + str(uuid4()))
        dialog.start()
        port = int(dialog.pairing.get().split(':', 1)[0])
        root.update()
        root.destroy()
        wait_until(lambda: closed(port))

    def test_timeout_clears_displayed_authorization(self):
        root = tk.Tk()
        try:
            dialog = CandidateDialog(root, ttl_seconds=.2)
            dialog.invitation.set(EXTENSION + '.' + str(uuid4()))
            dialog.start()
            port = int(dialog.pairing.get().split(':', 1)[0])
            def expired():
                root.update()
                return dialog.controller.state == 'expired' and not dialog.pairing.get()
            wait_until(expired)
            self.assertEqual(dialog.pairing.get(), '')
            wait_until(lambda: closed(port))
        finally:
            root.update()
            root.destroy()

    def test_app_entry_is_user_triggered_and_cancelled_without_start(self):
        with tempfile.TemporaryDirectory() as folder:
            root = tk.Tk()
            try:
                app = App(root, config_path=Path(folder) / 'settings.json')
                self.assertIsNone(app._candidate_dialog)
                app.open_candidate()
                self.assertEqual(app._candidate_dialog.controller.state, 'idle')
                self.assertEqual(app._candidate_dialog.pairing.get(), '')
                app._candidate_dialog.window.destroy()
            finally:
                root.update()
                root.destroy()

    def test_invalid_invitation_fails_without_exposing_input(self):
        root = tk.Tk()
        try:
            dialog = CandidateDialog(root)
            dialog.invitation.set('SECRET-invalid')
            dialog.start()
            self.assertEqual(dialog.controller.state, 'idle')
            self.assertEqual(dialog.pairing.get(), '')
            self.assertNotIn('SECRET', dialog.status.get())
        finally:
            root.update()
            root.destroy()


if __name__ == '__main__':
    unittest.main()
