"""Local browser regressions. No connection to a real conformance suite or OP."""
import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('conformance_runner', ROOT / 'run-tests.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BrowserBehaviorTests(unittest.TestCase):
    def test_exact_policies_and_invalid_configuration(self):
        policies = runner._load_browser_behaviors(str(ROOT / 'browser-behaviors.json'))
        self.assertEqual(len(policies), 5)
        self.assertEqual(runner._browser_action('visit_then_login', 0), 'visit')
        self.assertEqual(runner._browser_action('visit_then_login', 1), 'login')
        self.assertEqual(policies.get('unlisted-module', 'login'), 'login')
        self.assertEqual(runner._remap_result('any', 'REVIEW'), 'REVIEW')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'behavior.json'
            for invalid in [[], {'module': {'action': 'pass', 'reason': 'invalid'}}, {'wild*card': {'action': 'cancel', 'reason': 'invalid'}}]:
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    runner._load_browser_behaviors(str(path))

    def test_visit_204_preserves_tls_and_reports_exact_url(self):
        class Session:
            def post(self, url, **kwargs):
                self.url, self.kwargs = url, kwargs
                # Deliberately no json(): the real endpoint returns 204.
                return types.SimpleNamespace(raise_for_status=lambda: None)
        session = Session()
        with patch.dict(os.environ, {'SUITE_CA_FILE': '/local/test-ca.pem'}, clear=True):
            runner._mark_browser_visited(session, 'https://suite.test', 'module-id', 'https://op.test/authorize?x=1&y=2')
        self.assertEqual(session.kwargs['verify'], '/local/test-ca.pem')
        self.assertEqual(session.kwargs['params']['url'], 'https://op.test/authorize?x=1&y=2')
        self.assertTrue(session.url.endswith('/module-id/visit'))

    def exercise(self, policy, expected_visits, expected_submits):
        state = {'visits': 0, 'submits': 0, 'cancel': 0, 'opened': 0}
        test = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                if self.path == '/authorize':
                    state['opened'] += 1
                    body = '<form method="post" action="/done"><input name="email"><input name="password" type="password"><button type="submit">Login</button></form><a href="/authorize/cancel?session=test">Cancel</a>'
                else:
                    if self.path.startswith('/authorize/cancel'):
                        state['cancel'] += 1
                    body = 'Callback'
                self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())
            def do_POST(self):
                state['submits'] += 1
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(303); self.send_header('Location','/callback'); self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        auth_url = f'http://127.0.0.1:{server.server_port}/authorize'
        class Session:
            def response(self, data):
                return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: data)
            def post(self, url, **kwargs):
                if '/visit' in url:
                    test.assertEqual(kwargs['params']['url'], auth_url)
                    test.assertGreater(state['opened'], state['visits'])
                    if state['visits'] == 0:
                        test.assertEqual(state['submits'], 0)
                    state['visits'] += 1
                    return types.SimpleNamespace(raise_for_status=lambda: None)
                return self.response({'id': 'local-mock'})
            def get(self, url, **kwargs):
                if '/browser/' in url:
                    return self.response({'urls': [auth_url] if state['visits'] < expected_visits else []})
                complete = (state['submits'] > 0 or state['cancel'] > 0)
                if policy == 'no_interaction': complete = True
                # Mock outcome intentionally FAILED: automation must preserve it.
                return self.response({'status': 'FINISHED' if complete else 'WAITING', 'result': 'FAILED' if complete else ''})
        args = argparse.Namespace(browser_behaviors={'local-test': policy}, suite_url='https://mock.invalid', headful=False, browser_launch_args=['--no-sandbox'], timeout=25, email='local@example.test', password='local-only')
        try:
            result = asyncio.run(runner.run_module(plan_id='local', module_name='local-test', module_variant={}, sess=Session(), args=args))
            self.assertEqual(result, 'FAILED')
            self.assertEqual(state['visits'], expected_visits)
            self.assertEqual(state['submits'], expected_submits)
            self.assertEqual(state['opened'], expected_visits)
            self.assertEqual(state['cancel'], 1 if policy == 'cancel' else 0)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_first_visit_does_not_login_second_identical_url_does(self):
        self.exercise('visit_then_login', 2, 1)

    def test_cancel_never_submits_credentials(self):
        self.exercise('cancel', 1, 0)

    def test_no_interaction_never_opens_browser_request(self):
        self.exercise('no_interaction', 0, 0)


if __name__ == '__main__':
    unittest.main()
