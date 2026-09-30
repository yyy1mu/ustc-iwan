interface ReleaseFile {
  name: string;
  key: string;
  size: number;
  sha256: string;
  binary: string;
  platform: string;
  arch: string;
  libc: string;
}
interface Release {
  tag: string;
  published_at: string;
  prerelease: boolean;
  files: ReleaseFile[];
}
interface ReleaseIndex {
  schema: number;
  latest: string | null;
  releases: Release[];
}
export interface Bindings {
  ASSETS: Fetcher;
  DOWNLOADS: R2Bucket;
}

export function parseRange(value: string | null, size: number): { offset: number; length: number } | 'invalid' | null {
  if (!value) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(value);
  if (!match || (!match[1] && !match[2])) return 'invalid';
  let start: number;
  let end: number;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) return 'invalid';
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Number(match[2]) : size - 1;
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || start > end) return 'invalid';
  return { offset: start, length: Math.min(end, size - 1) - start + 1 };
}

function matchesEtag(header: string, etag: string, weak: boolean): boolean {
  return header.split(',').some(value => {
    const tag = value.trim();
    return tag === '*' || (weak ? tag.replace(/^W\//, '') : tag) === etag;
  });
}

export function precondition(request: Request, etag: string, modified: Date): number | null {
  const h = request.headers;
  const time = Math.floor(modified.getTime() / 1000) * 1000;
  if (h.has('If-Match') && !matchesEtag(h.get('If-Match')!, etag, false)) return 412;
  if (!h.has('If-Match') && h.has('If-Unmodified-Since') && time > Date.parse(h.get('If-Unmodified-Since')!)) return 412;
  if (h.has('If-None-Match')) {
    if (matchesEtag(h.get('If-None-Match')!, etag, true)) return 304;
  } else if (h.has('If-Modified-Since') && time <= Date.parse(h.get('If-Modified-Since')!)) return 304;
  return null;
}

const failure = (message: string, status: number, method: string) => new Response(method === 'HEAD' ? null : message, {
  status,
  headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
});

async function readIndex(env: Bindings): Promise<ReleaseIndex> {
  const object = await env.DOWNLOADS.get('index.json');
  if (!object) return { schema: 1, latest: null, releases: [] };
  const data = await object.json<ReleaseIndex>();
  if (data.schema !== 1 || !Array.isArray(data.releases)) throw new Error('Invalid release index');
  return data;
}

export default {
  async fetch(request: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const response = failure('Method Not Allowed', 405, request.method);
      response.headers.set('Allow', 'GET, HEAD');
      return response;
    }
    const head = request.method === 'HEAD';
    if (url.pathname === '/health') return new Response(head ? null : '{"status":"ok"}', { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    if (url.pathname !== '/api/releases' && !url.pathname.startsWith('/files/')) {
      if (url.pathname.startsWith('/api/')) return failure('Not Found', 404, request.method);
      return env.ASSETS.fetch(request);
    }
    try {
      const index = await readIndex(env);
      if (url.pathname === '/api/releases') {
        return new Response(head ? null : JSON.stringify(index), {
          headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=60', 'X-Content-Type-Options': 'nosniff' },
        });
      }
      const match = /^\/files\/(v[0-9][A-Za-z0-9._-]*)\/([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(url.pathname);
      if (!match) return failure('Not Found', 404, request.method);
      const release = index.releases.find(item => item.tag === match[1]);
      const file = release?.files.find(item => item.name === match[2]);
      if (!file || file.key !== `releases/${match[1]}/${match[2]}`) return failure('Not Found', 404, request.method);
      const cacheable = !head && !['range', 'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since', 'if-range'].some(name => request.headers.has(name));
      const cacheKey = new Request(`${url.origin}${url.pathname}`, { method: 'GET' });
      const cache = typeof caches !== 'undefined' ? caches.default : undefined;
      if (cacheable && cache) {
        const cached = await cache.match(cacheKey);
        if (cached) return cached;
      }
      const metadata = await env.DOWNLOADS.head(file.key);
      if (!metadata || metadata.size !== file.size || metadata.customMetadata?.sha256 !== file.sha256) return failure('Download temporarily unavailable', 503, request.method);
      const headers = new Headers({
        'Content-Type': file.name.endsWith('.zip') ? 'application/zip' : 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="${file.name}"`,
        'Content-Length': String(metadata.size),
        'Accept-Ranges': 'bytes',
        ETag: metadata.httpEtag,
        'Last-Modified': metadata.uploaded.toUTCString(),
        'Cache-Control': 'public, max-age=31536000, immutable',
        'X-Content-Type-Options': 'nosniff',
      });
      const condition = precondition(request, metadata.httpEtag, metadata.uploaded);
      if (condition) {
        headers.delete('Content-Length');
        if (condition === 412) headers.set('Cache-Control', 'no-store');
        return new Response(null, { status: condition, headers });
      }
      let rangeHeader = head ? null : request.headers.get('Range');
      const ifRange = request.headers.get('If-Range');
      if (ifRange && ifRange !== metadata.httpEtag && !(Date.parse(ifRange) >= Math.floor(metadata.uploaded.getTime() / 1000) * 1000)) rangeHeader = null;
      const range = parseRange(rangeHeader, metadata.size);
      if (range === 'invalid') {
        headers.set('Content-Range', `bytes */${metadata.size}`);
        headers.set('Cache-Control', 'no-store');
        headers.delete('Content-Length');
        return new Response(null, { status: 416, headers });
      }
      if (head) return new Response(null, { headers });
      const object = await env.DOWNLOADS.get(file.key, { onlyIf: { etagMatches: metadata.etag }, ...(range ? { range } : {}) });
      if (!object || !('body' in object)) return failure('Download changed; retry', 503, request.method);
      if (range) {
        headers.set('Content-Range', `bytes ${range.offset}-${range.offset + range.length - 1}/${metadata.size}`);
        headers.set('Content-Length', String(range.length));
      }
      const response = new Response(object.body, { status: range ? 206 : 200, headers });
      if (cacheable && cache) ctx.waitUntil(cache.put(cacheKey, response.clone()).catch(() => {}));
      return response;
    } catch {
      return failure('Download service temporarily unavailable; use GitHub Releases', 503, request.method);
    }
  },
} satisfies ExportedHandler<Bindings>;
