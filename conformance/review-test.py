#!/usr/bin/env python3
"""Record a per-instance local decision or attach a screenshot to its suite placeholder."""
import argparse
import json
import os
from pathlib import Path
import sys
import requests
from manual_review import DEFAULT_REGISTRY, api, load_records, record_review, upload_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('instance', nargs='?')
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--approve', action='store_true')
    actions.add_argument('--reject', action='store_true')
    actions.add_argument('--inspect', action='store_true')
    actions.add_argument('--list', action='store_true')
    actions.add_argument('--upload', type=Path, metavar='PNG')
    parser.add_argument('--placeholder')
    parser.add_argument('--reviewer', default=os.environ.get('CONFORMANCE_REVIEWER'))
    parser.add_argument('--note')
    parser.add_argument('--registry', type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument('--suite-url', default=os.environ.get('SUITE_URL', 'https://localhost.emobix.co.uk:8443'))
    args = parser.parse_args()
    session = requests.Session()
    if os.environ.get('SUITE_TOKEN'):
        session.headers['Authorization'] = 'Bearer ' + os.environ['SUITE_TOKEN']
    try:
        if args.list:
            print(json.dumps(load_records(args.registry), indent=2))
            return
        if not args.instance:
            parser.error('instance ID is required')
        from manual_review import instance_path
        instance_path(args.instance)
        if args.inspect:
            info = api(session, args.suite_url, '/api/info/' + args.instance)
            from manual_review import evidence_snapshot
            images = api(session, args.suite_url, '/api/log/' + args.instance + '/images')
            print(json.dumps(evidence_snapshot(info, images), indent=2))
            print(args.suite_url.rstrip('/') + '/upload.html?log=' + args.instance)
        elif args.upload:
            if not args.placeholder:
                parser.error('--upload requires --placeholder from --inspect')
            upload_image(session, args.suite_url, args.instance, args.placeholder, args.upload.read_bytes())
            print('Screenshot uploaded. No local approval recorded; suite determines its own result.')
        else:
            if not args.reviewer or not args.note:
                parser.error('--reviewer (or CONFORMANCE_REVIEWER) and --note are required')
            record = record_review(session, args.suite_url, args.instance,
                'approved' if args.approve else 'rejected', args.reviewer, args.note, args.registry)
            print(f"Recorded {record['decision']} for {args.instance} in {args.registry}; suite verdict unchanged.")
    except (ValueError, OSError, requests.RequestException) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
