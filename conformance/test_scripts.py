"""Offline safety checks; these never run a conformance module."""
import ast
import asyncio
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent

class ScriptSafetyTests(unittest.TestCase):
    def test_skipped_has_a_separate_summary_column(self):
        import contextlib
        import io
        import datetime
        import re
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        names = {'_print_summary', '_update_conformance_md'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        ns = {'datetime': datetime, 'os': os, 're': re,
              **{name: '' for name in ['BOLD','NC','GREEN','RED','YELLOW','GREY']}}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'runner', 'exec'), ns)
        summaries = [('example', [('ok','PASSED'),('unsupported','SKIPPED'),('manual','INTERRUPTED')])]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ns['_print_summary'](summaries, {'PASSED':1,'FAILED':0,'REVIEW':0,'SKIPPED':1,'OTHER':1})
        self.assertEqual(output.getvalue().count('1 SKIPPED'),2)
        self.assertEqual(output.getvalue().count('1 ?'),2)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); (directory / 'conformance').mkdir()
            md = directory / 'CONFORMANCE.md'
            md.write_text('| Plan | Tests | Passed | Review | Failed | Pass rate |\n|---|---|---|---|---|---|\n| old | 1 | 1 | 0 | 0 | 100% |\n\n| Separate | Table |\n|---|---|\n| Keep | Me |\n')
            ns['__file__'] = str(directory / 'conformance' / 'run-tests.py')
            with contextlib.redirect_stdout(io.StringIO()): ns['_update_conformance_md'](summaries)
            content = md.read_text()
            self.assertIn('| Skipped | Other / incomplete |',content)
            self.assertIn('| example | 3 | 1 | 0 | 0 | 1 | 1 | 33% |',content)
            self.assertIn('| Keep | Me |',content)

    def test_plan_selection_is_independent_of_api_order(self):
        import datetime
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        names = {'_plan_id', '_plan_alias', '_latest_plans'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        from plan_selection import latest_plans
        ns = {'datetime': datetime, 'latest_plans': latest_plans}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'runner', 'exec'), ns)
        old = {'_id': 'old', 'config': {'alias': 'same'}, 'started': '2026-11-02T10:29:24.029824898Z'}
        new = {'_id': 'new', 'config': {'alias': 'same'}, 'started': '2026-11-02T19:38:43.194625166Z'}
        other = {'_id': 'other', 'config': {'alias': 'other'}}
        for plans in ([old, new, other], [other, new, old]):
            selected = ns['_latest_plans'](plans)
            self.assertEqual({p['_id'] for p in selected}, {'new', 'other'})
        with self.assertRaisesRegex(ValueError, 'exact plan ID'):
            ns['_latest_plans']([old, {'_id': 'ambiguous', 'config': {'alias': 'same'}}])

    def test_dry_run_never_calls_curl(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for name in ['create-plans.sh', 'check-config.py']:
                shutil.copyfile(ROOT / name, target / name)
            for path in ROOT.glob('*plan.json'):
                shutil.copyfile(path, target / path.name)
            for i, name in enumerate(['fapi-private-key.jwk', 'fapi2-private-key.jwk']):
                (target / name).write_text(json.dumps({'kty': 'RSA', 'n': str(i), 'e': 'AQAB', 'd': 'TEST_PRIVATE_SENTINEL'}))
            curl = target / 'curl'
            marker = target / 'CALLED'
            curl.write_text('#!/bin/sh\ntouch "$TEST_MARKER"\nexit 97\n')
            curl.chmod(0o700)
            env = dict(os.environ, PATH=str(target) + os.pathsep + os.environ['PATH'], TEST_MARKER=str(marker))
            env.pop('FAPI_KEY_FILE', None)
            env.pop('FAPI2_KEY_FILE', None)
            result = subprocess.run(['bash', str(target / 'create-plans.sh'), '--dry-run'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertNotIn('TEST_PRIVATE_SENTINEL', result.stdout + result.stderr)
            self.assertIn('Dry run complete', result.stdout)
            final = subprocess.run(['bash', str(target / 'create-plans.sh'), '--final-only', '--dry-run'], env=env, capture_output=True, text=True)
            self.assertEqual(final.returncode, 0, final.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(final.stdout.count('DRY RUN:'), 3)
            for alias in ['clavex-fapi-final-dpop', 'clavex-fapi-final-mtls', 'clavex-fapi-jarm-final']:
                self.assertIn(alias, final.stdout)
            self.assertNotIn('DRY RUN: oidcc-', final.stdout)
            self.assertNotIn('TEST_PRIVATE_SENTINEL', final.stdout + final.stderr)
            single = subprocess.run(['bash', str(target / 'create-plans.sh'), '--only-alias=clavex-haip', '--dry-run'], env=env, capture_output=True, text=True)
            self.assertEqual(single.returncode, 0, single.stderr)
            self.assertEqual(single.stdout.count('DRY RUN:'), 1)
            self.assertIn('alias: clavex-haip', single.stdout)
            self.assertFalse(marker.exists())

    def test_suite_tls_verification_is_explicit(self):
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        get = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_suite_get')
        ns = {'os': os, 'requests': types.SimpleNamespace(Session=object)}
        exec(compile(ast.Module(body=[get], type_ignores=[]), 'runner', 'exec'), ns)
        class Session:
            def get(self, url, **kwargs):
                self.options = kwargs
                return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: {})
        for env, expected in [({}, True), ({'SUITE_INSECURE': '1'}, False), ({'SUITE_CA_FILE': '/test/ca.pem'}, '/test/ca.pem')]:
            with patch.dict(os.environ, env, clear=True):
                session = Session()
                ns['_suite_get'](session, 'https://suite.example', '/api/plan')
                self.assertEqual(session.options['verify'], expected)

    def test_browser_pin_requires_verified_suite_certificate(self):
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_suite_browser_args')
        from urllib.parse import urlsplit
        from unittest.mock import MagicMock
        import ssl
        import socket
        ns = {'os': os, 'ssl': ssl, 'socket': socket, 'subprocess': subprocess,
              'urlsplit': urlsplit, 'base64': base64, 'hashlib': hashlib}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'runner', 'exec'), ns)
        with patch.dict(os.environ, {'SUITE_CA_FILE': '/test/ca.pem'}, clear=True):
            with patch.object(ssl, 'create_default_context', side_effect=ssl.SSLError('untrusted')):
                with patch.object(socket, 'create_connection') as connect:
                    with self.assertRaises(ssl.SSLError):
                        ns['_suite_browser_args']('https://suite.example:8443')
                    connect.assert_not_called()
            ctx = MagicMock()
            ctx.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b'verified DER'
            with patch.object(ssl, 'create_default_context', return_value=ctx) as create:
                with patch.object(socket, 'create_connection') as connect:
                    with patch.object(subprocess, 'run', side_effect=[types.SimpleNamespace(stdout=b'public PEM'), types.SimpleNamespace(stdout=b'public SPKI')]):
                        args = ns['_suite_browser_args']('https://suite.example:8443')
                    create.assert_called_once_with(cafile='/test/ca.pem')
                    self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
                    connect.assert_called_once_with(('suite.example', 8443), timeout=10)
                    self.assertEqual(args, ['--ignore-certificate-errors-spki-list=' + base64.b64encode(hashlib.sha256(b'public SPKI').digest()).decode()])
                    self.assertNotIn('--ignore-certificate-errors', args)

    def test_login_browser_error_is_never_success(self):
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        names = {'_drive_login', '_browser_error_url'}
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
        ns = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'runner', 'exec'), ns)
        class Page:
            url = 'https://op.example/authorize'
            @property
            def first(self): return self
            def locator(self, selector): return self
            async def wait_for_selector(self, *a, **kw): pass
            async def fill(self, *a): pass
            async def is_visible(self, **kw): return True
            async def click(self): self.url = 'chrome-error://chromewebdata/'
            async def wait_for_url(self, *a, **kw): pass
        with self.assertRaisesRegex(RuntimeError, 'Browser navigation failed'):
            asyncio.run(ns['_drive_login'](Page(), 'test@example.test', 'test-password'))

    def test_manual_key_rotation_module_never_starts_automatically(self):
        from unittest.mock import Mock
        tree = ast.parse((ROOT / 'run-tests.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'run_module')
        for arg in node.args.args + node.args.kwonlyargs:
            arg.annotation = None
        node.returns = None
        post = Mock(side_effect=AssertionError('No suite mutation allowed'))
        ns = {'YELLOW': '', 'NC': '', '_suite_post': post}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'runner', 'exec'), ns)
        result = asyncio.run(ns['run_module'](plan_id='test-plan', module_name='oidcc-server-rotate-keys', module_variant={}, sess=None, args=None))
        self.assertEqual(result, 'MANUAL_REQUIRED')
        post.assert_not_called()

if __name__ == '__main__':
    unittest.main()
