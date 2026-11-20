"""Exercise the actual inline publisher offline, without a token or GitHub writes."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
SOURCE = 'a' * 40
BODY = b'packaged extension bytes'
DIGEST = hashlib.sha256(BODY).hexdigest()
FILENAME = 'burp-exporter-0.0.1.jar'
TAG = 'v0.0.1-build.1234.1'


def inline_python(step):
    """Extract a named YAML step's Python heredoc; fail closed if its shape changes."""
    block = WORKFLOW.split(f'      - name: {step}\n', 1)[1].split('\n      - name:', 1)[0]
    script = block.split("          python3 <<'PY'\n", 1)[1].split('          PY', 1)[0]
    return '\n'.join(line[10:] if line.startswith('          ') else line
                     for line in script.splitlines())


PUBLISHER = compile(inline_python('Stage, verify and publish a new build release'),
                    'build.yml:publisher', 'exec')


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.env = {
            'GITHUB_REPOSITORY': 'example/exporter', 'GITHUB_SHA': SOURCE,
            'GITHUB_REF': 'refs/heads/master', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_RUN_ID': '1234', 'GITHUB_RUN_ATTEMPT': '1',
            'SOURCE_SHA': SOURCE, 'VERSION': '0.0.1', 'FILENAME': FILENAME,
            'EXPECTED_SHA256': DIGEST,
        }
        self.draft = {
            'id': 42, 'draft': True, 'tag_name': TAG, 'target_commitish': SOURCE,
            'assets': [{'name': FILENAME, 'state': 'uploaded', 'size': len(BODY),
                        'digest': f'sha256:{DIGEST}'}],
        }
        self.previous = {'tag': 'v0.0.1', 'asset': b'previous verified download'}
        self.old = copy.deepcopy(self.previous)
        self.calls = []
        self.heads = [SOURCE, SOURCE]
        self.fail_at = None
        self.failure = None
        self.published = False

    def fake_run(self, command, **kwargs):
        self.assertTrue(kwargs['check'])
        self.assertGreater(kwargs['timeout'], 0)
        if command[1:3] == ['release', 'upload']:
            operation = 'upload'
            self.assertEqual(command, ['gh', 'release', 'upload', self.draft['tag_name'],
                                       str(Path('verified') / FILENAME), '--repo', 'example/exporter'])
            result = None
        else:
            self.assertEqual(command[:3], ['gh', 'api', '--method'])
            method, endpoint = command[3:5]
            payload = json.loads(kwargs['input']) if kwargs.get('input') else None
            operation = f'{method} {endpoint.removeprefix("repos/example/exporter/")}'
            if operation == 'GET git/ref/heads/master':
                result = {'object': {'sha': self.heads.pop(0)}}
            elif operation == 'POST releases':
                self.assertEqual(payload['tag_name'], self.draft['tag_name'])
                self.assertEqual(payload['target_commitish'], SOURCE)
                self.assertIs(payload['draft'], True)
                self.assertIs(payload['prerelease'], False)
                self.assertEqual(payload['make_latest'], 'false')
                result = self.draft
            elif operation == 'GET releases/42':
                result = self.draft
            elif operation == 'PATCH releases/42':
                self.assertEqual(payload, {'draft': False, 'make_latest': 'true'})
                result = dict(self.draft, draft=False, html_url='https://example/release')
            else:
                self.fail(f'Unexpected GitHub operation: {operation}')
        self.calls.append(operation)
        self.assertEqual(self.previous, self.old, 'Previous download must never be modified')
        if operation == self.fail_at:
            raise self.failure or subprocess.CalledProcessError(1, command)
        if operation == 'PATCH releases/42':
            self.published = True
        return subprocess.CompletedProcess(command, 0, json.dumps(result), '')

    def execute(self):
        # Mock only I/O: execute the exact production publisher, not a copied algorithm.
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(subprocess, 'run', side_effect=self.fake_run), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'open', return_value=io.BytesIO(BODY)), \
                patch.object(Path, 'stat') as stat, redirect_stdout(io.StringIO()):
            stat.return_value.st_size = len(BODY)
            exec(PUBLISHER, {'__name__': '__main__'})

    def test_draft_upload_verify_then_publish_without_removing_old_download(self):
        self.execute()
        self.assertEqual(self.calls, ['GET git/ref/heads/master', 'POST releases', 'upload',
                                     'GET releases/42', 'GET git/ref/heads/master', 'PATCH releases/42'])
        self.assertTrue(self.published)
        self.assertEqual(self.previous, self.old)

    def test_failures_never_remove_previous_download(self):
        for operation in ['GET git/ref/heads/master', 'POST releases', 'upload',
                          'GET releases/42', 'PATCH releases/42']:
            for failure in [subprocess.CalledProcessError(1, ['gh']),
                            subprocess.TimeoutExpired(['gh'], 120)]:
                with self.subTest(operation=operation, failure=type(failure).__name__):
                    self.setUp()
                    self.fail_at, self.failure = operation, failure
                    with self.assertRaises(type(failure)):
                        self.execute()
                    self.assertFalse(self.published)
                    self.assertEqual(self.previous, self.old)

    def test_remote_asset_must_match_before_promotion(self):
        for field, wrong in [('digest', None), ('digest', 'sha256:bad'), ('name', 'other.jar'),
                             ('state', 'starter'), ('size', len(BODY) + 1)]:
            with self.subTest(field=field, value=wrong):
                self.setUp()
                self.draft['assets'][0][field] = wrong
                with self.assertRaisesRegex(SystemExit, 'verification failed'):
                    self.execute()
                self.assertNotIn('PATCH releases/42', self.calls)

    def test_extra_or_missing_assets_are_not_published(self):
        for assets in [[], self.draft['assets'] * 2]:
            with self.subTest(assets=assets):
                self.setUp()
                self.draft['assets'] = assets
                with self.assertRaisesRegex(SystemExit, 'verification failed'):
                    self.execute()
                self.assertFalse(self.published)

    def test_stale_build_does_not_create_a_draft(self):
        self.heads = ['b' * 40]
        with self.assertRaises(SystemExit) as exit_status:
            self.execute()
        self.assertEqual(exit_status.exception.code, 0)
        self.assertEqual(self.calls, ['GET git/ref/heads/master'])

    def test_superseded_during_upload_leaves_unpublished_draft(self):
        self.heads = [SOURCE, 'b' * 40]
        with self.assertRaises(SystemExit) as exit_status:
            self.execute()
        self.assertEqual(exit_status.exception.code, 0)
        self.assertNotIn('PATCH releases/42', self.calls)

    def test_invalid_identity_fails_before_any_github_call(self):
        for field, wrong in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REF', 'refs/heads/topic'),
                             ('SOURCE_SHA', 'b' * 40), ('FILENAME', '../escape.jar'),
                             ('VERSION', 'v1\nbad'), ('GITHUB_RUN_ID', 'bad'),
                             ('GITHUB_RUN_ATTEMPT', 'bad')]:
            with self.subTest(field=field):
                self.setUp()
                self.env[field] = wrong
                with self.assertRaisesRegex(SystemExit, 'Unsafe publication identity'):
                    self.execute()
                self.assertEqual(self.calls, [])

    def test_local_digest_mismatch_fails_before_any_github_call(self):
        self.env['EXPECTED_SHA256'] = '0' * 64
        with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_rerun_attempt_uses_a_new_tag_without_changing_product_version(self):
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        self.draft['tag_name'] = 'v0.0.1-build.1234.2'
        self.execute()
        self.assertTrue(self.published)
        self.assertEqual(self.env['FILENAME'], FILENAME)

    def test_all_embedded_python_compiles(self):
        for index, script in enumerate(re.findall(
                r"          python3 <<'PY'\n(.*?)          PY", WORKFLOW, re.DOTALL)):
            compile('\n'.join(line[10:] if line.startswith('          ') else line
                              for line in script.splitlines()), f'build.yml:python{index}', 'exec')

    def test_permissions_and_concurrency_are_isolated(self):
        before_jobs, jobs = WORKFLOW.split('\njobs:\n', 1)
        build, release = jobs.split('\n  release:\n', 1)
        self.assertIn('  pull_request:\n    branches: [master]', before_jobs)
        self.assertNotIn('pull_request_target', WORKFLOW)
        self.assertNotIn('concurrency:', before_jobs)
        self.assertIn('permissions:\n  contents: read', before_jobs)
        self.assertNotIn('contents: write', build)
        self.assertIn('cancel-in-progress: true', build)
        self.assertIn("cache-read-only: ${{ github.event_name == 'pull_request' ||", build)
        self.assertIn("if: github.event_name != 'pull_request' && github.ref == 'refs/heads/master'", release)
        self.assertIn('cancel-in-progress: false', release)
        self.assertIn('contents: write', release)
        self.assertNotIn('uses: actions/checkout', release)
        self.assertNotIn('gradlew', release)
        self.assertIn("'sha256').hexdigest()", release)
        self.assertIn('artifact-ids: ${{ needs.build.outputs.artifact-id }}', release)
        self.assertIn('digest-mismatch: error', release)
        self.assertNotIn('DELETE', release)
        self.assertNotIn('--clobber', release)
        self.assertNotIn('replacesArtifacts', release)
        self.assertLess(build.index('Verify Java quality gates'), build.index('Verify Javadoc'))
        self.assertIn('git diff --check HEAD^ HEAD', build)
        self.assertLess(build.index('clean javadoc'), build.index('clean build -PexcludeIntegration'))
        for reference in re.findall(r'uses: ([^\s]+)', WORKFLOW):
            self.assertRegex(reference, r'@[0-9a-f]{40}$')


if __name__ == '__main__':
    unittest.main()
