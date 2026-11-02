import os
from pathlib import Path
import socket
import subprocess
import unittest
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src' / 'protection' / 'LocalProbe.cs'
CSC = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Microsoft.NET' / 'Framework64' / 'v4.0.30319' / 'csc.exe'


@unittest.skipUnless(os.name == 'nt' and CSC.is_file(), 'Windows .NET Framework compiler unavailable')
class LocalProbeExeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise AssertionError('project probe source is missing')
        cls.build_dir = ROOT / 'src' / 'protection' / ('build-' + uuid4().hex)
        cls.build_dir.mkdir(exist_ok=False)
        cls.programs = {}
        for role in ('TARGET', 'CONTROL'):
            output = cls.build_dir / (role.lower() + '.exe')
            p = subprocess.run([str(CSC), '/nologo', '/target:exe', '/optimize+',
                                '/define:' + role, '/out:' + str(output), str(SOURCE)],
                               capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
            if p.returncode != 0:
                raise AssertionError(p.stdout + p.stderr)
            cls.programs[role] = output

    def test_both_binaries_reach_only_owned_loopback_listener(self):
        for role, exe in self.programs.items():
            with self.subTest(role=role), socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.bind(('127.0.0.1', 0))
                server.listen(1)
                server.settimeout(5)
                token = uuid4().hex
                p = subprocess.Popen([str(exe), str(server.getsockname()[1]), token],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(5)
                        data = b''
                        while len(data) < len(token):
                            chunk = conn.recv(len(token) - len(data))
                            if not chunk:
                                break
                            data += chunk
                        self.assertEqual(data.decode('ascii'), token)
                        conn.sendall(data)
                    stdout, stderr = p.communicate(timeout=5)
                finally:
                    if p.poll() is None:
                        p.communicate(timeout=6)
                self.assertEqual(p.returncode, 0, stderr.decode(errors='replace'))
                self.assertEqual(stdout.decode('ascii').strip(), role.lower() + ':ok')

    def test_invalid_invocation_fails_without_connecting(self):
        p = subprocess.run([str(self.programs['TARGET']), 'not-a-port', 'bad'],
                           capture_output=True, timeout=5)
        self.assertNotEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
