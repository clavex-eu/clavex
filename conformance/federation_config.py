"""Local fixture injection only; never contacts a service or changes trust."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


def inject(plan, material, suite_url):
    url = urlsplit(suite_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('Federation requires an HTTPS suite origin')
    alias = plan['alias']
    if alias != 'clavex-openid-federation-op':
        raise ValueError('Unexpected Federation laboratory alias')
    if not plan.get('federation', {}).get('entity_identifier'):
        raise ValueError('Missing federation.entity_identifier')
    identifiers = set()
    for name, kind in [('rp_ec_jwks', 'EC'), ('rp_client_jwks', 'RSA'), ('trust_anchor_jwks', 'EC')]:
        keys = material.get(name, {}).get('keys', [])
        if len(keys) != 1 or keys[0].get('kty') != kind or not keys[0].get('d') or keys[0].get('use') != 'sig':
            raise ValueError(f'Missing or invalid private laboratory key set: {name}')
        if kind == 'EC' and keys[0].get('crv') != 'P-256':
            raise ValueError('Federation EC fixture keys must use P-256')
        expected_alg = 'ES256' if kind == 'EC' else 'PS256'
        required = ('x', 'y') if kind == 'EC' else ('n', 'e')
        if keys[0].get('alg') != expected_alg or not all(keys[0].get(k) for k in required):
            raise ValueError('Invalid laboratory public key or signing algorithm')
        public = tuple(keys[0].get(k) for k in ('kty', 'crv', 'x', 'y', 'n', 'e'))
        if public in identifiers:
            raise ValueError('Laboratory identities must use distinct keys')
        identifiers.add(public)
    base = suite_url.rstrip('/') + '/test/a/' + alias
    plan['federation'].update({name: material[name] for name in ('rp_ec_jwks', 'rp_client_jwks')})
    plan['federation']['trust_anchor'] = base + '/trust-anchor'
    plan['federation_trust_anchor'] = {'trust_anchor_jwks': material['trust_anchor_jwks']}
    plan.setdefault('client', {})['redirect_uri'] = base + '/callback'
    return plan


def main():
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--suite-url', required=True)
    args = parser.parse_args()
    if args.keys.stat().st_mode & 0o077:
        raise ValueError('Private laboratory key file must not be group/world accessible')
    plan = inject(json.load(sys.stdin), json.loads(args.keys.read_text()), args.suite_url)
    json.dump(plan, sys.stdout)


if __name__ == '__main__':
    main()
