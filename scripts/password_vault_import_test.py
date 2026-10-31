import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vault_import', pathlib.Path(__file__).with_name('password-vault-import.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def test_transport_and_validation(self):
        self.assertTrue(module.safe_url('http://127.0.0.1:1234'))
        self.assertFalse(module.safe_url('http://localhost:1234'))
        self.assertTrue(module.safe_url('https://vault.example.invalid'))
        self.assertFalse(module.safe_url('http://192.0.2.1'))
        self.assertFalse(module.safe_url('https://user:password@vault.example.invalid'))
        self.assertFalse(module.safe_url('https://vault.example.invalid/path'))
        self.assertFalse(module.valid([{'password': 'synthetic'}]))

    def test_loopback_import_and_no_redirect(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(302 if self.server.redirect else 201)
                if self.server.redirect:
                    self.send_header('Location', 'http://127.0.0.1:1/')
                self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.redirect = False
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as temp:
            token = pathlib.Path(temp) / 'token'
            token.write_text('synthetic-token', encoding='utf8')
            row = {'request_id': '0123456789abcdef0123456789abcdef', 'kind': 'service',
                   'title': 'fixture', 'site': '', 'username': 'fixture',
                   'password': 'synthetic-secret', 'shared': True}
            args = ['import', '--url', 'http://127.0.0.1:%d' % server.server_port,
                    '--token-file', str(token), '--organization', 'fixture-org']
            out = io.StringIO()
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdin', io.StringIO(json.dumps([row]))), redirect_stdout(out):
                module.main()
            self.assertEqual(received, [row])
            self.assertNotIn(row['password'], out.getvalue())
            with patch.object(sys, 'argv', ['import', '--dry-run', '--organization', 'fixture-org']), patch.object(sys, 'stdin', io.StringIO(json.dumps([row]))), redirect_stdout(out):
                module.main()
            self.assertEqual(len(received), 1)
            self.assertNotIn(row['password'], out.getvalue())
            server.redirect = True
            error = io.StringIO()
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdin', io.StringIO(json.dumps([row]))), redirect_stderr(error):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertNotIn(row['password'], error.getvalue())


if __name__ == '__main__':
    unittest.main()
