import assert from 'node:assert/strict';
import { getPlatformProxy } from 'wrangler';
import worker from '../src/index.ts';

const proxy = await getPlatformProxy({ persist: false });
const pending = [];
const ctx = { waitUntil: promise => pending.push(promise) };
try {
  const bucket = proxy.env.DOWNLOADS;
  const bytes = new TextEncoder().encode('0123456789');
  const sha256 = Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('hex');
  const name = 'iwan-client-linux-x86_64-musl.zip';
  const key = `releases/v0.0.0-test/${name}`;
  await bucket.put(key, bytes, { customMetadata: { sha256 } });
  await bucket.put('index.json', JSON.stringify({ schema: 1, latest: 'v0.0.0-test', releases: [{ tag: 'v0.0.0-test', files: [{ name, key, size: bytes.length, sha256 }] }] }));
  const request = headers => new Request(`https://test.invalid/files/v0.0.0-test/${name}`, { headers });
  let response = await worker.fetch(request(), proxy.env, ctx);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '0123456789');
  const etag = response.headers.get('ETag');
  response = await worker.fetch(request({ Range: 'bytes=3-5' }), proxy.env, ctx);
  assert.equal(response.status, 206);
  assert.equal(await response.text(), '345');
  response = await worker.fetch(request({ 'If-None-Match': etag }), proxy.env, ctx);
  assert.equal(response.status, 304);
  response = await worker.fetch(request({ Range: 'bytes=100-' }), proxy.env, ctx);
  assert.equal(response.status, 416);
  console.log('Local R2 runtime: full download, range, ETag and 416 passed.');
} finally {
  await Promise.all(pending);
  await proxy.dispose();
}
