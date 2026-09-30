#!/usr/bin/env python3
"""Mirror published GitHub release files to R2, then publish a complete index."""
import argparse
import hashlib
import http.client
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = 'yyy1mu/ustc-iwan'
TAG = re.compile(r'v[0-9][A-Za-z0-9._-]*\Z')
ASSET = re.compile(r'(iwan-client-oidc|iwan-client|iwan-server)-(?:((?:linux|macos|windows))-)?(x86_64|aarch64|armv7|riscv64)(?:-(gnu|musl))?\.zip\Z')


def gh(endpoint, paginate=False):
    command = ['gh', 'api', f'repos/{REPO}/{endpoint}']
    if paginate:
        command += ['--paginate', '--slurp']
    for attempt in range(3):
        try:
            data = json.loads(subprocess.check_output(command, timeout=120))
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    return [item for page in data for item in page] if paginate else data


def expected_assets():
    linux = ['x86_64-gnu', 'x86_64-musl', 'aarch64-gnu', 'aarch64-musl', 'armv7-gnu', 'armv7-musl', 'riscv64-musl']
    result = {f'{binary}-linux-{target}.zip' for binary in ['iwan-client', 'iwan-client-oidc', 'iwan-server'] for target in linux}
    result.update(f'{binary}-{platform}-{arch}.zip' for binary in ['iwan-client', 'iwan-client-oidc'] for platform in ['macos', 'windows'] for arch in ['x86_64', 'aarch64'])
    return result


def describe_asset(asset):
    match = ASSET.fullmatch(asset['name'])
    if not match:
        raise ValueError(f"Unsupported release filename: {asset['name']}")
    binary, platform, arch, libc = match.groups()
    if asset.get('state') != 'uploaded' or asset['size'] <= 0:
        raise ValueError(f"Incomplete release asset: {asset['name']}")
    return {'name': asset['name'], 'size': asset['size'], 'binary': binary,
            'platform': {'linux': 'Linux', 'macos': 'macOS', 'windows': 'Windows'}[platform or 'linux'],
            'arch': arch, 'libc': libc or ''}


def missing(error):
    return getattr(error, 'response', {}).get('Error', {}).get('Code') in ('NoSuchKey', '404', 'NotFound')


def conflict(error):
    return getattr(error, 'response', {}).get('ResponseMetadata', {}).get('HTTPStatusCode') in (409, 412)


def read_json(client, bucket, key):
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except Exception as error:
        if missing(error):
            return None, None
        raise
    try:
        return json.loads(response['Body'].read()), response['ETag']
    finally:
        response['Body'].close()


def put_json(client, bucket, key, data, **conditions):
    return client.put_object(Bucket=bucket, Key=key, Body=(json.dumps(data, ensure_ascii=False, sort_keys=True) + '\n').encode(),
                             ContentType='application/json', CacheControl='no-cache', **conditions)


def merge_index(index, release, latest_tag):
    if index and index.get('schema') != 1:
        raise ValueError('Unsupported index schema')
    releases = {r['tag']: r for r in (index or {}).get('releases', [])}
    releases[release['tag']] = release
    ordered = sorted(releases.values(), key=lambda r: (r['published_at'], r['tag']), reverse=True)
    stable = [r for r in ordered if not r['prerelease']]
    preferred = next((r for r in stable if r['tag'] == latest_tag), None)
    latest = (preferred if preferred and preferred['published_at'] >= stable[0]['published_at'] else stable[0])['tag'] if stable else None
    return {'schema': 1, 'latest': latest, 'releases': ordered}


def publish_index(client, bucket, release, latest_tag):
    for _ in range(5):
        index, etag = read_json(client, bucket, 'index.json')
        updated = merge_index(index, release, latest_tag)
        try:
            put_json(client, bucket, 'index.json', updated, **({'IfMatch': etag} if etag else {'IfNoneMatch': '*'}))
            return
        except Exception as error:
            if not conflict(error):
                raise
    raise RuntimeError('Concurrent index updates; retry synchronization')


def verify_object(client, bucket, key, path, digest):
    head = client.head_object(Bucket=bucket, Key=key)
    expected_size = path if isinstance(path, int) else path.stat().st_size
    if head['ContentLength'] != expected_size or head.get('Metadata', {}).get('sha256') != digest:
        raise RuntimeError(f'Existing R2 object differs; publish a new version: {key}')
    response = client.get_object(Bucket=bucket, Key=key)
    checksum = hashlib.sha256()
    try:
        for block in iter(lambda: response['Body'].read(1024 * 1024), b''):
            checksum.update(block)
    finally:
        response['Body'].close()
    if checksum.hexdigest() != digest:
        raise RuntimeError(f'R2 readback checksum mismatch: {key}')


def upload_file(client, bucket, key, path, digest):
    with path.open('rb') as source:
        try:
            client.put_object(Bucket=bucket, Key=key, Body=source, ContentLength=path.stat().st_size,
                              ContentType='application/zip' if path.suffix == '.zip' else 'text/plain; charset=utf-8',
                              ContentDisposition=f'attachment; filename="{path.name}"',
                              CacheControl='public, max-age=31536000, immutable', Metadata={'sha256': digest}, IfNoneMatch='*')
        except Exception as error:
            if not conflict(error):
                raise
    verify_object(client, bucket, key, path, digest)


def download_archive(tag, asset, path):
    # Public release URLs require no credentials; redirects never receive our GitHub token.
    url = f"https://github.com/{REPO}/releases/download/{tag}/{asset['name']}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=120) as response, path.open('wb') as destination:
                checksum = hashlib.sha256()
                total = 0
                for chunk in iter(lambda: response.read(1024 * 1024), b''):
                    total += len(chunk)
                    if total > asset['size']:
                        raise RuntimeError(f"Unexpected size: {asset['name']}")
                    checksum.update(chunk)
                    destination.write(chunk)
            digest = checksum.hexdigest()
            if total != asset['size'] or (asset.get('digest') and asset['digest'] != f'sha256:{digest}'):
                raise RuntimeError(f"GitHub checksum/size mismatch: {asset['name']}")
            return digest
        except (OSError, http.client.HTTPException, RuntimeError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def synchronize(client, bucket, release, assets, latest_tag, jobs=4):
    tag = release['tag_name']
    manifest = {'tag': tag, 'published_at': release['published_at'], 'prerelease': release['prerelease'], 'files': []}
    with tempfile.TemporaryDirectory(prefix='iwan-r2-') as directory:
        def transfer(asset):
            info = describe_asset(asset)
            path = Path(directory, info['name'])
            expected_digest = asset.get('digest', '') or ''
            if expected_digest.startswith('sha256:'):
                digest = expected_digest.removeprefix('sha256:')
                key = f"releases/{tag}/{info['name']}"
                try:
                    verify_object(client, bucket, key, info['size'], digest)
                    print(f"Verified existing {tag}/{info['name']}", flush=True)
                    return {**info, 'key': key, 'sha256': digest}
                except Exception as error:
                    if not missing(error):
                        raise
            digest = download_archive(tag, asset, path)
            key = f"releases/{tag}/{info['name']}"
            upload_file(client, bucket, key, path, digest)
            result = {**info, 'key': key, 'sha256': digest}
            path.unlink()
            print(f"Verified {tag}/{info['name']}", flush=True)
            return result
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            manifest['files'] = list(executor.map(transfer, assets))
        sums = Path(directory, 'SHA256SUMS')
        sums.write_text(''.join(f"{f['sha256']}  {f['name']}\n" for f in manifest['files']))
        upload_file(client, bucket, f'releases/{tag}/SHA256SUMS', sums, hashlib.sha256(sums.read_bytes()).hexdigest())
    old, _ = read_json(client, bucket, f'releases/{tag}/manifest.json')
    if old is not None and old != manifest:
        raise RuntimeError(f'Published manifest changed: {tag}; publish a new version')
    if old is None:
        try:
            put_json(client, bucket, f'releases/{tag}/manifest.json', manifest, IfNoneMatch='*')
        except Exception as error:
            if not conflict(error):
                raise
            old, _ = read_json(client, bucket, f'releases/{tag}/manifest.json')
            if old != manifest:
                raise RuntimeError(f'Concurrent manifest conflict: {tag}') from error
    publish_index(client, bucket, manifest, latest_tag)
    print(f'Published download index for {tag}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--tag')
    group.add_argument('--all', action='store_true')
    parser.add_argument('--jobs', type=int, choices=range(1, 17), default=4, help='Concurrent archive transfers (1-16)')
    parser.add_argument('--wrangler', action='store_true', help='Use local Wrangler login instead of S3 credentials')
    parser.add_argument('--plan', action='store_true', help='List versions/files without accessing R2')
    parser.add_argument('--require-current-matrix', action='store_true')
    args = parser.parse_args()
    if args.tag and not TAG.fullmatch(args.tag):
        parser.error('Invalid tag')
    releases = gh('releases?per_page=100', True) if args.all else [gh(f'releases/tags/{args.tag}')]
    releases = sorted((r for r in releases if not r['draft'] and TAG.fullmatch(r['tag_name'])), key=lambda r: r['published_at'])
    if not releases:
        parser.error('No published releases found')
    prepared = []
    for release in releases:
        assets = sorted(gh(f"releases/{release['id']}/assets?per_page=100", True), key=lambda a: a['name'])
        # Only binary archives are mirrored; other release attachments stay on GitHub.
        assets = [a for a in assets if a['name'].endswith('.zip')]
        if not assets:
            raise ValueError(f"Release has no archives: {release['tag_name']}")
        for asset in assets:
            describe_asset(asset)
        if args.require_current_matrix and {a['name'] for a in assets} != expected_assets():
            raise ValueError('Release assets do not match the complete build matrix')
        prepared.append((release, assets))
        print(f"{release['tag_name']}: {len(assets)} archives, {sum(a['size'] for a in assets)} bytes", flush=True)
    if args.plan:
        return
    bucket = os.environ.get('R2_BUCKET_NAME', 'ustc-iwan-downloads')
    if args.wrangler:
        from wrangler_client import WranglerClient
        client = WranglerClient()
    else:
        import boto3
        from botocore.config import Config
        account = os.environ['CLOUDFLARE_ACCOUNT_ID']
        client = boto3.client('s3', endpoint_url=f'https://{account}.r2.cloudflarestorage.com', region_name='auto',
                              aws_access_key_id=os.environ['R2_ACCESS_KEY_ID'], aws_secret_access_key=os.environ['R2_SECRET_ACCESS_KEY'],
                              config=Config(retries={'max_attempts': 5, 'mode': 'standard'}, request_checksum_calculation='when_required', response_checksum_validation='when_required'))
    try:
        latest_tag = gh('releases/latest')['tag_name']
        for release, assets in prepared:
            synchronize(client, bucket, release, assets, latest_tag, args.jobs)
    finally:
        client.close()



if __name__ == '__main__':
    main()
