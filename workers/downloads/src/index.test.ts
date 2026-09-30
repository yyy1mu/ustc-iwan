import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { parseRange, precondition } from './index.ts';

const modified = new Date('2026-09-01T00:00:00Z');
const request = (headers = {}, method = 'GET', path = '/files/v26.9.1/iwan-client-linux-x86_64-musl.zip') => new Request(`https://iwan.test${path}`, { headers, method });
const file = { name: 'iwan-client-linux-x86_64-musl.zip', key: 'releases/v26.9.1/iwan-client-linux-x86_64-musl.zip', size: 10, sha256: 'abc' };
function environment() {
  const metadata = { size: 10, httpEtag: '"test"', etag: 'test', uploaded: modified, customMetadata: { sha256: 'abc' } };
  return {
    ASSETS: { fetch: async () => new Response('static page') },
    DOWNLOADS: {
      head: async () => metadata,
      get: async (key, options) => {
        if (key === 'index.json') return { json: async () => ({ schema: 1, latest: 'v26.9.1', releases: [{ tag: 'v26.9.1', files: [file] }] }) };
        const range = options?.range;
        const text = range ? '0123456789'.slice(range.offset, range.offset + range.length) : '0123456789';
        return { ...metadata, body: new Response(text).body };
      },
    },
  };
}
const ctx = { waitUntil() {} };

test('range boundaries, suffixes and invalid inputs', () => {
  assert.deepEqual(parseRange('bytes=2-4', 10), { offset: 2, length: 3 });
  assert.deepEqual(parseRange('bytes=-3', 10), { offset: 7, length: 3 });
  assert.deepEqual(parseRange('bytes=7-999', 10), { offset: 7, length: 3 });
  assert.deepEqual(parseRange('bytes=0-', 10), { offset: 0, length: 10 });
  for (const value of ['bytes=10-', 'bytes=-0', 'bytes=4-2', 'bytes=0-1,3-4', 'bytes=-', 'bytes=99999999999999999999-']) assert.equal(parseRange(value, 10), 'invalid');
  assert.equal(parseRange('bytes=0-', 0), 'invalid');
});

test('conditional precedence and weak/strong ETag behavior', () => {
  assert.equal(precondition(request({ 'If-None-Match': 'W/"test"' }), '"test"', modified), 304);
  assert.equal(precondition(request({ 'If-Match': 'W/"test"' }), '"test"', modified), 412);
  assert.equal(precondition(request({ 'If-None-Match': '"different"', 'If-Modified-Since': modified.toUTCString() }), '"test"', modified), null);
});

test('GET, HEAD, Range, If-Range and unsatisfiable ranges', async () => {
  const env = environment();
  let response = await worker.fetch(request(), env, ctx);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '0123456789');
  response = await worker.fetch(request({}, 'HEAD'), env, ctx);
  assert.equal(await response.text(), '');
  assert.equal(response.headers.get('Content-Length'), '10');
  response = await worker.fetch(request({ Range: 'bytes=2-4' }), env, ctx);
  assert.equal(response.status, 206);
  assert.equal(response.headers.get('Content-Range'), 'bytes 2-4/10');
  assert.equal(await response.text(), '234');
  response = await worker.fetch(request({ Range: 'bytes=20-' }), env, ctx);
  assert.equal(response.status, 416);
  response = await worker.fetch(request({ Range: 'bytes=2-4', 'If-Range': '"old"' }), env, ctx);
  assert.equal(response.status, 200);
  response = await worker.fetch(request({ 'If-None-Match': '"test"' }), env, ctx);
  assert.equal(response.status, 304);
});

test('unlisted files, incomplete objects and unsupported methods stay unavailable', async () => {
  const env = environment();
  assert.equal((await worker.fetch(request({}, 'GET', '/files/v26.9.1/hidden.zip'), env, ctx)).status, 404);
  assert.equal((await worker.fetch(request({}, 'POST'), env, ctx)).status, 405);
  env.DOWNLOADS.head = async () => null;
  assert.equal((await worker.fetch(request(), env, ctx)).status, 503);
});

test('empty bucket, unavailable bucket and static routing', async () => {
  const env = environment();
  env.DOWNLOADS.get = async () => null;
  const response = await worker.fetch(request({}, 'GET', '/api/releases'), env, ctx);
  assert.deepEqual(await response.json(), { schema: 1, latest: null, releases: [] });
  env.DOWNLOADS.get = async () => { throw new Error('offline'); };
  assert.equal((await worker.fetch(request({}, 'GET', '/api/releases'), env, ctx)).status, 503);
  assert.equal(await (await worker.fetch(request({}, 'GET', '/'), env, ctx)).text(), 'static page');
});
