"""Offline fixture/configuration tests, without suite traffic."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from federation_config import inject


class FederationConfigTests(unittest.TestCase):
    def material(self):
        def key(kind, kid):
            return {'keys': [{'kty': kind, 'kid': kid, 'use': 'sig', 'd': 'PRIVATE_SENTINEL',
                              'alg': 'ES256' if kind == 'EC' else 'PS256',
                              'crv': 'P-256', 'x': kid, 'y': kid, 'n': kid, 'e': 'AQAB'}]}
        return {'rp_ec_jwks': key('EC', 'rp'), 'rp_client_jwks': key('RSA', 'client'),
                'trust_anchor_jwks': key('EC', 'ta')}

    def test_template_is_public_and_injection_matches_actual_suite_origin(self):
        raw = Path(__file__).with_name('openid-federation-plan.json').read_text()
        plan = json.loads(raw)
        self.assertNotIn('"d":', raw)
        result = inject(plan, self.material(), 'https://suite.example:8443')
        base = 'https://suite.example:8443/test/a/clavex-openid-federation-op'
        self.assertEqual(result['federation']['trust_anchor'], base + '/trust-anchor')
        self.assertEqual(result['client']['redirect_uri'], base + '/callback')
        self.assertIn('rp_ec_jwks', result['federation'])
        self.assertIn('trust_anchor_jwks', result['federation_trust_anchor'])

    def test_invalid_missing_or_shared_keys_and_non_origin_urls_are_rejected(self):
        plan = json.loads(Path(__file__).with_name('openid-federation-plan.json').read_text())
        material = self.material()
        for url in ['http://suite.example', 'https://suite.example/path', 'https://user:pass@suite.example', 'https://suite.example?query=1']:
            with self.assertRaises(ValueError):
                inject(copy.deepcopy(plan), material, url)
        for name in material:
            invalid = copy.deepcopy(material)
            del invalid[name]
            with self.assertRaises(ValueError):
                inject(copy.deepcopy(plan), invalid, 'https://suite.example')
        invalid = copy.deepcopy(material)
        invalid['trust_anchor_jwks'] = invalid['rp_ec_jwks']
        with self.assertRaisesRegex(ValueError, 'distinct'):
            inject(copy.deepcopy(plan), invalid, 'https://suite.example')

    def test_upload_injects_only_selected_plan_without_printing_private_keys(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ['create-plans.sh', 'check-config.py', 'federation_config.py']:
                shutil.copyfile(root / name, directory / name)
            for plan in root.glob('*plan.json'):
                shutil.copyfile(plan, directory / plan.name)
            for i, name in enumerate(['fapi-private-key.jwk', 'fapi2-private-key.jwk']):
                (directory / name).write_text(json.dumps({'kty': 'RSA', 'n': str(i), 'e': 'AQAB'}))
            keyfile = directory / 'keys.json'
            keyfile.write_text(json.dumps(self.material()))
            keyfile.chmod(0o600)
            body = directory / 'body.json'
            fake = directory / 'curl'
            fake.write_text('#!/bin/sh\ncat > "$TEST_BODY"\nprintf \'{"id":"offline-plan"}\\n\'\n')
            fake.chmod(0o700)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH'],
                       TEST_BODY=str(body), FEDERATION_KEY_FILE=str(keyfile), SUITE_URL='https://suite.example:8443',
                       FAPI_KEY_FILE=str(directory / 'fapi-private-key.jwk'), FAPI2_KEY_FILE=str(directory / 'fapi2-private-key.jwk'))
            result = subprocess.run(['bash', str(directory / 'create-plans.sh'), '--only-alias=clavex-openid-federation-op'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('PRIVATE_SENTINEL', result.stdout + result.stderr)
            sent = json.loads(body.read_text())
            self.assertEqual(sent['alias'], 'clavex-openid-federation-op')
            self.assertIn('rp_ec_jwks', sent['federation'])
            self.assertNotIn('variant', sent)


if __name__ == '__main__':
    unittest.main()
