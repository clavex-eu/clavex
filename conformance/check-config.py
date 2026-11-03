#!/usr/bin/env python3
"""Read-only plan/key/certificate checks. Does not contact or run the OIDF suite."""
import argparse
import base64
import datetime
import json
import os
import re
import subprocess
from pathlib import Path


def public_jwk(key):
    names = ('kty', 'n', 'e') if key['kty'] == 'RSA' else ('kty', 'crv', 'x', 'y')
    return {name: key[name] for name in names}


def openssl(*args, data):
    return subprocess.run(['openssl', *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def certificate(pem):
    data = pem.encode()
    dates = openssl('x509', '-noout', '-dates', data=data).decode().splitlines()
    now = datetime.datetime.now(datetime.timezone.utc)
    start, end = [datetime.datetime.strptime(line.split('=', 1)[1], '%b %d %H:%M:%S %Y %Z')
                  .replace(tzinfo=datetime.timezone.utc) for line in dates]
    if not start <= now < end:
        raise ValueError('certificate outside validity period')
    return openssl('x509', '-pubkey', '-noout', data=data)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plans-dir', type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument('--registered-clients', type=Path, help='Optional read-only registry JSON snapshot')
    ap.add_argument('--suite-catalog', type=Path, help='Read-only /api/plan/available JSON snapshot')
    args = ap.parse_args()
    directory = args.plans_dir
    registered = {}
    if args.registered_clients:
        registered = {c['client_id']: c for c in json.loads(args.registered_clients.read_text())}
    fapi = [json.loads(Path(os.environ.get(env, str(directory / name))).read_text())
            for env, name in [('FAPI_KEY_FILE', 'fapi-private-key.jwk'),
                              ('FAPI2_KEY_FILE', 'fapi2-private-key.jwk')]]
    if public_jwk(fapi[0]) == public_jwk(fapi[1]):
        raise ValueError('FAPI clients must use distinct signing keys')
    plans, certs, client_checks = 0, 0, 0
    attesters = None
    for path in sorted(directory.glob('*plan.json')):
        plan = json.loads(path.read_text())
        if path.name in {'authzen-plan.json', 'introspection-test-plan.json'}:
            continue  # Local protocol test specifications, not suite plans.
        if path.name == 'haip-plan.json':
            credential = plan.get('credential', {})
            status_anchor = credential.get('status_list_trust_anchor_pem')
            credential_anchor = credential.get('trust_anchor_pem')
            if not status_anchor or not credential_anchor:
                raise ValueError('HAIP requires explicit credential and status-list trust anchors')
            if plan.get("variant", {}).get("credential_format") == "sd_jwt_vc" and certificate(status_anchor) != certificate(credential_anchor):
                raise ValueError('The configured shared credential/status signer requires matching trust anchors')
        if path.name == 'openid-federation-plan.json':
            if not plan.get('federation', {}).get('entity_identifier') or not isinstance(plan.get('federation_trust_anchor'), dict):
                raise ValueError('Federation requires its top-level entity and laboratory TA configuration')
            if 'server' in plan:
                raise ValueError('Federation identifiers belong under federation, not server')
        if not plan.get('alias'):
            raise ValueError(f'{path.name}: missing alias')
        plans += 1
        for field in ('client', 'client2'):
            client = plan.get(field, {})
            keys = client.get('jwks', {}).get('keys', [])
            cid = client.get('client_id')
            if not keys and cid and cid.startswith('conformance-client-') and ('fapi' in cid or 'ciba' in cid):
                keys = [fapi[0 if field == 'client' else 1]]
            if registered and cid and keys:
                actual = registered.get(cid)
                if not actual or not actual['active']:
                    raise ValueError(f'{path.name}: inactive/missing {cid}')
                expected = actual['jwks']
                expected = json.loads(expected) if isinstance(expected, str) else expected
                if not expected or [public_jwk(k) for k in keys] != [public_jwk(k) for k in expected['keys']]:
                    raise ValueError(f'{path.name}: registered key mismatch for {field}')
                client_checks += 1
        vci = plan.get('vci', {})
        keys = vci.get('key_attestation_jwks', {}).get('keys', [])
        if keys:
            signers = [public_jwk(k) for k in keys]
            if attesters is not None and signers != attesters:
                raise ValueError(f'{path.name}: inconsistent conformance key-attestation signer')
            attesters = signers
        def walk(value):
            nonlocal certs
            if isinstance(value, dict):
                if isinstance(value.get('cert'), str) and value.get('key'):
                    pub = certificate(value['cert'])
                    private_pub = openssl('pkey', '-pubout', data=value['key'].encode())
                    if pub != private_pub:
                        raise ValueError(f'{path.name}: TLS key/certificate mismatch')
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str) and '-----BEGIN CERTIFICATE-----' in value:
                for block in value.split('-----END CERTIFICATE-----')[:-1]:
                    certificate(block + '-----END CERTIFICATE-----\n')
                    certs += 1
        walk(plan)
        for key in keys:
            for cert in key.get('x5c', []):
                pem = '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(base64.b64decode(cert)).decode() + '\n-----END CERTIFICATE-----\n'
                certificate(pem)
                certs += 1
    if args.suite_catalog:
        catalog = {p['planName']: p for p in json.loads(args.suite_catalog.read_text())}
        script = (directory / 'create-plans.sh').read_text()
        uploads = re.findall(r'create_plan\s+(?:\\\s*)?\s*"([^"]+)"\s+(?:\\\s*)?\s*"\$\{DIR\}/([^"]+)"', script)
        if not uploads:
            raise ValueError('No plan uploads found in script')
        for name, filename in uploads:
            if name not in catalog:
                raise ValueError(f'{filename}: plan absent from suite catalog: {name}')
            variants = catalog[name]['variants']
            for key, value in json.loads((directory / filename).read_text()).get('variant', {}).items():
                if key not in variants or value not in variants[key]['variantValues']:
                    raise ValueError(f'{filename}: unsupported suite variant {key}={value}')
        print(f'PASS: {len(uploads)} upload definitions match {len(catalog)} catalog plan names and individual variant values.')
        print('This catalog check does not validate runtime prerequisites or all variant combinations.')
    print(f'PASS: {plans} JSON plans; {certs} valid certificates; distinct FAPI keys; consistent key-attestation signer.')
    if registered:
        print(f'PASS: {client_checks} plan client-key registrations match the database snapshot.')
    print('No suite plans were uploaded and no conformance tests were started.')
    print('HAIP shared-signer trust-anchor consistency checked; live chain validation remains required. This check does not certify compliance.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # Do not echo input JSON, private keys, or OpenSSL stderr.
        detail = str(error) if isinstance(error, (ValueError, FileNotFoundError)) else type(error).__name__
        raise SystemExit(f'Configuration check failed: {detail}') from None
