import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sync_r2 as sync


class Conflict(Exception):
    response = {'ResponseMetadata': {'HTTPStatusCode': 412}}


class Missing(Exception):
    response = {'Error': {'Code': 'NoSuchKey'}}


class SyncTests(unittest.TestCase):
    def test_legacy_and_modern_asset_names(self):
        for name in ['iwan-client-oidc-x86_64-musl.zip', 'iwan-client-oidc-linux-x86_64-musl.zip']:
            info = sync.describe_asset({'name': name, 'size': 1, 'state': 'uploaded'})
            self.assertEqual(info['platform'], 'Linux')
            self.assertEqual(info['binary'], 'iwan-client-oidc')
        self.assertEqual(len(sync.expected_assets()), 29)
        with self.assertRaises(ValueError):
            sync.describe_asset({'name': '../bad.zip', 'size': 1, 'state': 'uploaded'})

    def test_backfill_does_not_change_latest_and_prerelease_is_not_latest(self):
        current = {'tag': 'v26.9.1', 'published_at': '2026-09-11', 'prerelease': False, 'files': []}
        old = {'tag': 'v2.1.3', 'published_at': '2026-01-01', 'prerelease': False, 'files': []}
        preview = {'tag': 'v27.0.0-beta', 'published_at': '2026-10-01', 'prerelease': True, 'files': []}
        index = sync.merge_index(None, current, current['tag'])
        index = sync.merge_index(index, old, current['tag'])
        index = sync.merge_index(index, preview, current['tag'])
        self.assertEqual(index['latest'], current['tag'])
        self.assertEqual(len(index['releases']), 3)
        index = sync.merge_index(index, old, old['tag'])
        self.assertEqual(index['latest'], current['tag'])

    def test_compare_and_swap_retries_with_new_etag(self):
        release = {'tag': 'v1', 'published_at': '2026-01-01', 'prerelease': False, 'files': []}
        with patch.object(sync, 'read_json', side_effect=[(None, None), ({'schema': 1, 'releases': []}, 'new')]), patch.object(sync, 'put_json', side_effect=[Conflict(), None]) as put:
            sync.publish_index(None, 'bucket', release, 'v1')
            self.assertEqual(put.call_args_list[0].kwargs, {'IfNoneMatch': '*'})
            self.assertEqual(put.call_args_list[1].kwargs, {'IfMatch': 'new'})

    def test_upload_failure_never_publishes_manifest_or_index(self):
        release = {'tag_name': 'v1', 'published_at': '2026-01-01', 'prerelease': False}
        asset = {'name': 'iwan-client-x86_64-musl.zip', 'size': 3, 'state': 'uploaded'}
        with patch.object(sync.urllib.request, 'urlopen', side_effect=lambda *args, **kwargs: io.BytesIO(b'zip')), patch.object(sync, 'upload_file', side_effect=RuntimeError('upload failed')), patch.object(sync, 'put_json') as manifest, patch.object(sync, 'publish_index') as index:
            with self.assertRaisesRegex(RuntimeError, 'upload failed'):
                sync.synchronize(None, 'bucket', release, [asset], 'v1')
            manifest.assert_not_called()
            index.assert_not_called()

    def test_checksum_mismatch_never_uploads(self):
        release = {'tag_name': 'v1', 'published_at': '2026-01-01', 'prerelease': False}
        asset = {'name': 'iwan-client-x86_64-musl.zip', 'size': 3, 'state': 'uploaded', 'digest': 'sha256:bad'}
        with patch.object(sync.urllib.request, 'urlopen', side_effect=lambda *args, **kwargs: io.BytesIO(b'zip')), patch.object(sync, 'verify_object', side_effect=Missing()), patch.object(sync.time, 'sleep'), patch.object(sync, 'upload_file') as upload:
            with self.assertRaisesRegex(RuntimeError, 'checksum/size mismatch'):
                sync.synchronize(None, 'bucket', release, [asset], 'v1')
            upload.assert_not_called()

    def test_existing_object_must_match(self):
        class Client:
            def head_object(self, **kwargs):
                return {'ContentLength': 3, 'Metadata': {'sha256': 'old'}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'test.zip')
            path.write_bytes(b'zip')
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                sync.verify_object(Client(), 'bucket', 'key', path, 'new')


if __name__ == '__main__':
    unittest.main()
