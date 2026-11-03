#!/usr/bin/env python3
"""Read-only source/JAR provenance checks. Does not run suite modules or use APIs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile

OFFICIAL_URL = 'https://gitlab.com/openid/conformance-suite.git'
PINNED_COMMIT = '23353b36957d6466010de767c812d2c91ed37638'


def inspect_suite(source, jar, expected_commit=PINNED_COMMIT):
    source, jar = Path(source), Path(jar)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    origin = git('remote', 'get-url', 'origin')
    if origin.rstrip('/') not in (OFFICIAL_URL, OFFICIAL_URL[:-4], 'git@gitlab.com:openid/conformance-suite.git'):
        raise ValueError('Suite origin is not the documented official repository')
    commit = git('rev-parse', 'HEAD')
    if commit != expected_commit:
        raise ValueError('Suite checkout does not match the expected commit')
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('Suite worktree has changes; review them instead of claiming an unmodified suite')
    with ZipFile(jar) as archive:
        names = [name for name in archive.namelist() if name.endswith('/git.properties')]
        if names != ['BOOT-INF/classes/git.properties']:
            raise ValueError('Missing or ambiguous suite build provenance')
        properties = dict(line.split('=', 1) for line in archive.read(names[0]).decode().splitlines()
                          if line and not line.startswith('#') and '=' in line)
    if properties.get('git.commit.id') != expected_commit:
        raise ValueError('JAR build commit does not match the suite checkout')
    if properties.get('git.dirty') != 'false':
        raise ValueError('JAR was not recorded as a clean build')
    digest = hashlib.sha256()
    with jar.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'official_repository': OFFICIAL_URL, 'suite_commit': commit,
            'source_worktree_clean': True, 'jar_recorded_commit': properties['git.commit.id'],
            'jar_recorded_dirty': False, 'jar_sha256': digest.hexdigest(),
            'scope': 'Source checkout and JAR-recorded metadata checked; not a bytecode attestation or a conformance verdict.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('.conformance-suite'))
    parser.add_argument('--jar', type=Path, help='Defaults to SOURCE/target/fapi-test-suite.jar')
    parser.add_argument('--expected-commit', default=PINNED_COMMIT)
    args = parser.parse_args()
    result = inspect_suite(args.source, args.jar or args.source / 'target/fapi-test-suite.jar', args.expected_commit)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
