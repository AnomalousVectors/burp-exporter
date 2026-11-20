"""Exercise the inline publisher against an offline, stateful single-release model."""

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
OLD_SOURCE = 'b' * 40
BODY = b'new packaged extension bytes'
OLD_BODY = b'previous packaged extension bytes'
DIGEST = hashlib.sha256(BODY).hexdigest()
FILENAME = 'burp-exporter-0.0.1.jar'
TAG = 'v0.0.1'
STEM = 'burp-exporter-0.0.1'


def inline_python(step):
    """Extract the real step body, failing if the workflow's heredoc shape changes."""
    block = WORKFLOW.split(f'      - name: {step}\n', 1)[1].split('\n      - name:', 1)[0]
    script = block.split("          python3 <<'PY'\n", 1)[1].split('          PY', 1)[0]
    return '\n'.join(line[10:] if line.startswith('          ') else line
                     for line in script.splitlines())


PUBLISHER = compile(inline_python('Stage, verify and replace the single release asset'),
                    'build.yml:publisher', 'exec')


def asset(asset_id, name, body):
    return {'id': asset_id, 'name': name, 'state': 'uploaded', 'size': len(body),
            'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.env = {
            'GITHUB_REPOSITORY': 'example/exporter', 'GITHUB_SHA': SOURCE,
            'GITHUB_REF': 'refs/heads/master', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_RUN_ID': '1234', 'GITHUB_RUN_ATTEMPT': '1',
            'SOURCE_SHA': SOURCE, 'VERSION': '0.0.1', 'FILENAME': FILENAME,
            'EXPECTED_SHA256': DIGEST,
        }
        self.release = {
            'id': 42, 'draft': False, 'prerelease': False, 'tag_name': TAG, 'name': TAG,
            'body': 'Always use the latest.', 'target_commitish': OLD_SOURCE,
            'upload_url': 'https://uploads.github.com/repos/example/exporter/releases/42/assets{?name,label}',
            'html_url': 'https://example/release/v0.0.1',
        }
        self.items = {7: asset(7, FILENAME, OLD_BODY)}
        self.old = copy.deepcopy(self.items[7])
        self.next_id = 8
        self.tag_source = OLD_SOURCE
        self.heads = [SOURCE, SOURCE]
        self.calls = []
        self.failures = {}
        self.after_failures = {}
        self.upload_mutations = {}
        self.corrupt_canonical = False
        self.add_unknown_on_publish = False

    def stage_name(self):
        return f'{STEM}.staging-1234.{self.env["GITHUB_RUN_ATTEMPT"]}.jar'

    def normal(self):
        return next((item for item in self.items.values() if item['name'] == FILENAME), None)

    def fake_run(self, command, **kwargs):
        self.assertEqual(command[:3], ['gh', 'api', '--method'])
        self.assertTrue(kwargs['check'])
        self.assertGreater(kwargs['timeout'], 0)
        method, endpoint = command[3:5]
        payload = json.loads(kwargs['input']) if kwargs.get('input') else None
        path = endpoint.removeprefix('repos/example/exporter/')
        if endpoint.startswith('https://uploads.github.com/'):
            operation = 'POST upload'
        else:
            operation = method + ' ' + path
            if payload and 'name' in payload and '/assets/' in path:
                operation += ' -> ' + payload['name']
        self.calls.append(operation)
        if self.failures.get(operation, 0):
            self.failures[operation] -= 1
            raise subprocess.CalledProcessError(1, command)

        if operation == 'GET git/ref/heads/master':
            result = {'object': {'sha': self.heads.pop(0)}}
        elif operation == 'GET releases/tags/' + TAG:
            result = copy.deepcopy(self.release)
        elif operation == 'GET releases/42/assets?per_page=100':
            result = list(self.items.values())
        elif operation == 'POST upload':
            self.assertEqual(endpoint, self.release['upload_url'].split('{', 1)[0]
                             + '?name=' + self.stage_name())
            self.assertEqual(command[command.index('--input') + 1], str(Path('verified') / FILENAME))
            self.assertIn('Content-Type: application/java-archive', command)
            # Old download must not change before the upload is complete and verified.
            if 7 in self.items and self.items[7]['name'] == FILENAME:
                self.assertEqual(self.items[7], self.old)
            self.assertFalse(any(' -> ' in call for call in self.calls))
            result = asset(self.next_id, self.stage_name(), BODY)
            result.update(self.upload_mutations)
            self.items[self.next_id] = result
            self.next_id += 1
        elif path.startswith('releases/assets/'):
            asset_id = int(path.rsplit('/', 1)[1])
            self.assertIn(asset_id, self.items)
            if method == 'GET':
                result = copy.deepcopy(self.items[asset_id])
                if self.corrupt_canonical and asset_id != 7 and result['name'] == FILENAME:
                    result['digest'] = 'sha256:bad'
            elif method == 'PATCH':
                self.assertEqual(set(payload), {'name'})
                self.assertFalse(any(item['id'] != asset_id and item['name'] == payload['name']
                                     for item in self.items.values()))
                self.items[asset_id]['name'] = payload['name']
                result = self.items[asset_id]
            elif method == 'DELETE':
                self.assertNotEqual(self.items[asset_id]['name'], FILENAME)
                self.assertRegex(self.items[asset_id]['name'],
                                 re.escape(STEM) + r'\.(staging|previous)-[0-9]+\.[0-9]+\.jar$')
                del self.items[asset_id]
                result = None
            else:
                self.fail('Unexpected asset operation: ' + operation)
        elif operation == 'PATCH git/refs/tags/' + TAG:
            self.assertEqual(payload, {'sha': SOURCE, 'force': False})
            self.tag_source = SOURCE
            result = {'object': {'sha': SOURCE}}
        elif operation == 'GET git/ref/tags/' + TAG:
            result = {'object': {'sha': self.tag_source}}
        elif operation == 'PATCH releases/42':
            self.assertEqual(payload, {'name': TAG, 'body': 'Always use the latest.',
                                      'target_commitish': SOURCE, 'make_latest': 'true'})
            self.release.update(payload)
            result = self.release
            if self.add_unknown_on_publish:
                self.items[90] = asset(90, 'user-owned.txt', b'keep me')
        else:
            self.fail('Unexpected operation; releases and extra tags must never be created/deleted: ' + operation)
        if self.after_failures.get(operation, 0):
            self.after_failures[operation] -= 1
            raise subprocess.TimeoutExpired(command, 120)
        return subprocess.CompletedProcess(command, 0, json.dumps(result) if result is not None else '', '')

    def execute(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(subprocess, 'run', side_effect=self.fake_run), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'open', return_value=io.BytesIO(BODY)), \
                patch.object(Path, 'stat') as stat, redirect_stdout(io.StringIO()):
            stat.return_value.st_size = len(BODY)
            exec(PUBLISHER, {'__name__': '__main__'})

    def assert_final_layout(self):
        self.assertEqual(len(self.items), 1)
        self.assertEqual(self.normal()['digest'], 'sha256:' + DIGEST)
        self.assertEqual(self.release['id'], 42)
        self.assertEqual(self.release['tag_name'], TAG)
        self.assertEqual(self.release['name'], TAG)
        self.assertEqual(self.release['body'], 'Always use the latest.')
        self.assertEqual(self.tag_source, SOURCE)

    def test_success_reuses_one_release_and_tag_and_removes_temporary_assets(self):
        self.execute()
        self.assert_final_layout()
        self.assertLess(self.calls.index('GET releases/assets/8'),
                        self.calls.index('PATCH releases/assets/7 -> ' + STEM + '.previous-1234.1.jar'))
        self.assertLess(self.calls.index('PATCH releases/42'), self.calls.index('DELETE releases/assets/7'))

    def test_upload_failure_preserves_old_canonical_download(self):
        self.failures['POST upload'] = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.normal(), self.old)
        self.assertFalse(any(' -> ' in call for call in self.calls))

    def test_staged_verification_failure_does_not_touch_old_download(self):
        for field, value in [('digest', None), ('digest', 'sha256:bad'), ('size', 1), ('state', 'starter')]:
            with self.subTest(field=field, value=value):
                self.setUp()
                self.upload_mutations[field] = value
                with self.assertRaisesRegex(SystemExit, 'Staged upload verification failed'):
                    self.execute()
                self.assertEqual(self.normal(), self.old)
                self.assertEqual(len(self.items), 1)

    def test_stale_before_upload_performs_no_mutation(self):
        self.heads = [OLD_SOURCE]
        with self.assertRaises(SystemExit) as status:
            self.execute()
        self.assertEqual(status.exception.code, 0)
        self.assertEqual(self.calls, ['GET git/ref/heads/master'])

    def test_stale_after_upload_cleans_only_own_staging_asset(self):
        self.heads = [SOURCE, OLD_SOURCE]
        with self.assertRaises(SystemExit) as status:
            self.execute()
        self.assertEqual(status.exception.code, 0)
        self.assertEqual(self.normal(), self.old)
        self.assertEqual(len(self.items), 1)

    def test_unknown_assets_are_not_deleted_or_overwritten(self):
        self.items[20] = asset(20, 'user-owned.txt', b'keep me')
        with self.assertRaisesRegex(SystemExit, 'Unexpected release asset'):
            self.execute()
        self.assertNotIn('POST upload', self.calls)
        self.assertEqual(self.items[20]['name'], 'user-owned.txt')

    def test_same_attempt_collisions_do_not_clobber_existing_assets(self):
        self.items[8] = asset(8, self.stage_name(), BODY)
        with self.assertRaisesRegex(SystemExit, 'already has temporary assets'):
            self.execute()
        self.assertNotIn('POST upload', self.calls)
        self.assertEqual(self.normal(), self.old)

    def test_missing_canonical_after_interruption_is_recovered(self):
        self.items = {6: asset(6, STEM + '.previous-99.1.jar', OLD_BODY)}
        self.execute()
        self.assert_final_layout()

    def test_transient_rename_errors_retry_only_the_uploaded_assets_metadata(self):
        self.failures['PATCH releases/assets/8 -> ' + FILENAME] = 2
        self.execute()
        self.assert_final_layout()
        self.assertEqual(self.calls.count('POST upload'), 1)

    def test_exhausted_rename_retries_restore_old_name_and_retain_verified_staging(self):
        self.failures['PATCH releases/assets/8 -> ' + FILENAME] = 3
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.normal(), self.old)
        self.assertEqual(self.items[8]['digest'], 'sha256:' + DIGEST)
        self.assertEqual(self.tag_source, OLD_SOURCE)

    def test_lost_old_rename_response_restores_old_name_from_fresh_inventory(self):
        self.after_failures['PATCH releases/assets/7 -> ' + STEM + '.previous-1234.1.jar'] = 1
        with self.assertRaises(subprocess.TimeoutExpired):
            self.execute()
        self.assertEqual(self.normal(), self.old)
        self.assertEqual(self.tag_source, OLD_SOURCE)

    def test_lost_new_rename_response_is_safe_to_retry(self):
        self.after_failures['PATCH releases/assets/8 -> ' + FILENAME] = 1
        self.execute()
        self.assert_final_layout()

    def test_canonical_verification_failure_rolls_back_names(self):
        self.corrupt_canonical = True
        with self.assertRaisesRegex(RuntimeError, 'Canonical asset verification failed'):
            self.execute()
        self.assertEqual(self.normal(), self.old)
        self.assertEqual(self.tag_source, OLD_SOURCE)

    def test_tag_update_failure_preserves_both_verified_copies_and_next_attempt_recovers(self):
        self.failures['PATCH git/refs/tags/' + TAG] = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.normal()['digest'], 'sha256:' + DIGEST)
        self.assertIn(7, self.items)
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        self.heads = [SOURCE, SOURCE]
        self.calls = []
        self.execute()
        self.assert_final_layout()

    def test_release_metadata_failure_keeps_the_previous_bytes_until_completion(self):
        self.failures['PATCH releases/42'] = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.normal()['digest'], 'sha256:' + DIGEST)
        self.assertIn(7, self.items)

    def test_cleanup_failure_never_deletes_the_new_canonical_download(self):
        self.failures['DELETE releases/assets/7'] = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.normal()['digest'], 'sha256:' + DIGEST)
        self.assertEqual(self.tag_source, SOURCE)

    def test_concurrent_unknown_asset_is_retained_and_reported(self):
        self.add_unknown_on_publish = True
        with self.assertRaisesRegex(SystemExit, 'Final single-asset layout'):
            self.execute()
        self.assertIn(90, self.items)
        self.assertEqual(self.normal()['digest'], 'sha256:' + DIGEST)

    def test_invalid_identity_is_rejected_before_any_github_call(self):
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REF', 'refs/heads/topic'),
                           ('SOURCE_SHA', OLD_SOURCE), ('FILENAME', '../escape.jar'),
                           ('VERSION', 'bad\nvalue'), ('GITHUB_RUN_ID', 'bad'),
                           ('GITHUB_RUN_ATTEMPT', 'bad')]:
            with self.subTest(key=key):
                self.setUp()
                self.env[key] = value
                with self.assertRaisesRegex(SystemExit, 'Unsafe publication identity'):
                    self.execute()
                self.assertEqual(self.calls, [])

    def test_local_digest_failure_precedes_any_github_call(self):
        self.env['EXPECTED_SHA256'] = '0' * 64
        with self.assertRaisesRegex(SystemExit, 'digest mismatch'):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_workflow_permissions_concurrency_and_verification_order_remain_isolated(self):
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
        self.assertIn('artifact-ids: ${{ needs.build.outputs.artifact-id }}', release)
        self.assertIn('digest-mismatch: error', release)
        self.assertNotIn("api('POST', 'releases'", release)
        self.assertNotIn('-build.', release)
        self.assertNotIn("api('DELETE', f'releases/{release_id}'", release)
        self.assertIn("tag = f'v{version}'", release)
        self.assertIn("'force': False", release)
        self.assertIn("'body': 'Always use the latest.'", release)
        self.assertLess(build.index('Verify Java quality gates'), build.index('Verify Javadoc'))
        self.assertIn('git diff --check HEAD^ HEAD', build)
        self.assertLess(build.index('clean javadoc'), build.index('clean build -PexcludeIntegration'))
        for reference in re.findall(r'uses: ([^\s]+)', WORKFLOW):
            self.assertRegex(reference, r'@[0-9a-f]{40}$')

    def test_all_embedded_python_compiles(self):
        for index, script in enumerate(re.findall(
                r"          python3 <<'PY'\n(.*?)          PY", WORKFLOW, re.DOTALL)):
            compile('\n'.join(line[10:] if line.startswith('          ') else line
                              for line in script.splitlines()), f'build.yml:python{index}', 'exec')


if __name__ == '__main__':
    unittest.main()
