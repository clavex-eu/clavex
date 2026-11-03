"""Offline provenance checker regression tests; no conformance tests are run."""
import subprocess
import tempfile
from pathlib import Path
import unittest
from zipfile import ZipFile

from verify_suite import inspect_suite, OFFICIAL_URL


class SuiteProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.source), *args], stderr=subprocess.DEVNULL, text=True).strip()
        self.git = git
        git('init'); git('config', 'user.name', 'Offline fixture'); git('config', 'user.email', 'fixture@example.invalid')
        git('remote', 'add', 'origin', OFFICIAL_URL)
        (self.source / 'validator.java').write_text('unchanged fixture\n')
        git('add', 'validator.java'); git('commit', '-m', 'fixture')
        self.commit = git('rev-parse', 'HEAD')
        self.jar = self.root / 'suite.jar'
        self.write_jar()

    def write_jar(self, commit=None, dirty='false'):
        with ZipFile(self.jar, 'w') as out:
            out.writestr('BOOT-INF/classes/git.properties', f'git.commit.id={commit or self.commit}\ngit.dirty={dirty}\n')

    def test_clean_matching_fixture_and_hash(self):
        result = inspect_suite(self.source, self.jar, self.commit)
        self.assertTrue(result['source_worktree_clean'])
        self.assertEqual(len(result['jar_sha256']), 64)

    def test_rejects_modified_or_untracked_source(self):
        path = self.source / 'validator.java'
        path.write_text('changed validator\n')
        with self.assertRaisesRegex(ValueError, 'worktree'):
            inspect_suite(self.source, self.jar, self.commit)
        self.git('checkout', '--', 'validator.java')
        (self.source / 'extra.java').write_text('untracked validator\n')
        with self.assertRaisesRegex(ValueError, 'worktree'):
            inspect_suite(self.source, self.jar, self.commit)

    def test_rejects_different_build_commit_dirty_build_and_wrong_origin(self):
        self.write_jar(commit='0' * 40)
        with self.assertRaisesRegex(ValueError, 'build commit'):
            inspect_suite(self.source, self.jar, self.commit)
        self.write_jar(dirty='true')
        with self.assertRaisesRegex(ValueError, 'clean build'):
            inspect_suite(self.source, self.jar, self.commit)
        self.write_jar()
        self.git('remote', 'set-url', 'origin', 'https://example.invalid/fork.git')
        with self.assertRaisesRegex(ValueError, 'official'):
            inspect_suite(self.source, self.jar, self.commit)
