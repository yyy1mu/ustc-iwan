import { getPlatformProxy } from 'wrangler';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const config = JSON.parse(await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
const directory = await mkdtemp(join(tmpdir(), 'iwan-r2-bridge-'));
const configPath = join(directory, 'wrangler.json');
await writeFile(configPath, JSON.stringify({
  name: 'ustc-iwan-r2-sync',
  compatibility_date: config.compatibility_date,
  ...(process.env.CLOUDFLARE_ACCOUNT_ID ? { account_id: process.env.CLOUDFLARE_ACCOUNT_ID } : {}),
  r2_buckets: [{ binding: 'DOWNLOADS', bucket_name: process.env.R2_BUCKET_NAME || config.r2_buckets[0].bucket_name, remote: true }],
}));
const reply = data => process.stdout.write(`IWAN_RPC:${JSON.stringify(data)}\n`);
let proxy;
try {
  proxy = await getPlatformProxy({ configPath, persist: false, remoteBindings: true });
  reply({ ready: true });
  const bucket = proxy.env.DOWNLOADS;
  for await (const line of createInterface({ input: process.stdin })) {
    try {
      const args = JSON.parse(line);
      if (args.op === 'close') break;
      let object;
      if (args.op === 'head' || args.op === 'get') {
        object = await bucket[args.op](args.Key);
        if (!object) { reply({ code: 'NoSuchKey', status: 404 }); continue; }
        const result = { ContentLength: object.size, ETag: object.httpEtag, Metadata: object.customMetadata };
        if (args.op === 'get') result.body = Buffer.from(await object.arrayBuffer()).toString('base64');
        reply({ result });
      } else if (args.op === 'put') {
        const body = Buffer.from(args.body, 'base64');
        object = await bucket.put(args.Key, body, {
          customMetadata: args.Metadata,
          httpMetadata: { contentType: args.ContentType, contentDisposition: args.ContentDisposition, cacheControl: args.CacheControl },
          onlyIf: args.IfMatch ? { etagMatches: args.IfMatch.replace(/^"|"$/g, '') } : args.IfNoneMatch ? { etagDoesNotMatch: args.IfNoneMatch } : undefined,
        });
        reply(object ? { result: { ETag: object.httpEtag } } : { code: 'PreconditionFailed', status: 412 });
      } else {
        reply({ code: 'UnknownOperation', status: 400 });
      }
    } catch {
      reply({ code: 'RemoteBindingError', status: 502 });
    }
  }
} finally {
  await proxy?.dispose();
  await rm(directory, { recursive: true, force: true });
}
