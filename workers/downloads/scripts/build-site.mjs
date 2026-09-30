import { readFile, writeFile, mkdir, cp, rm } from 'node:fs/promises';
import { resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import MarkdownIt from 'markdown-it';
import GithubSlugger from 'github-slugger';
import sanitizeHtml from 'sanitize-html';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(project, '../..');
const output = resolve(project, 'public');
const repo = 'https://github.com/yyy1mu/ustc-iwan/blob/main/';
const pages = new Map([
  ['README.md', 'index.html'],
  ['CONTRIBUTING.md', 'contributing/index.html'],
  ['doc/usage-tips.md', 'doc/usage-tips/index.html'],
  ['workers/downloads/README.md', 'development/index.html'],
]);
const escape = (value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} });
export function layout(title, content, script = '') {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="USTC iWAN 跨平台命令行客户端：使用文档与版本下载"><title>${escape(title)} · USTC iWAN</title><link rel="stylesheet" href="/site.css"></head><body><a class="skip" href="#content">跳转到正文</a><header><a class="brand" href="/">iWAN<span> / USTC</span></a><nav aria-label="主导航"><a href="/">文档</a><a href="/downloads/">下载</a><a href="https://github.com/yyy1mu/ustc-iwan">GitHub ↗</a></nav></header><main id="content">${content}</main><footer>USTC iWAN · 开源命令行客户端 <a href="https://github.com/yyy1mu/ustc-iwan">查看源码 ↗</a></footer>${script ? `<script type="module" src="${script}"></script>` : ''}</body></html>`;
}

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp(resolve(project, 'web'), output, { recursive: true });
await cp(resolve(root, 'doc'), resolve(output, 'doc'), { recursive: true, filter: (path) => !['.md', '.py'].includes(extname(path)) });
for (const [source, destination] of pages) {
  const md = new MarkdownIt({ html: false, linkify: true });
  const slugger = new GithubSlugger();
  md.renderer.rules.heading_open = (tokens, index, options, env, self) => {
    const inline = tokens[index + 1];
    const text = (inline.children || []).filter(t => ['text', 'code_inline'].includes(t.type)).map(t => t.content).join('');
    tokens[index].attrSet('id', slugger.slug(text));
    return self.renderToken(tokens, index, options);
  };
  md.core.ruler.after('inline', 'local-links', state => {
    for (const block of state.tokens) for (const token of block.children || []) {
      const attr = token.type === 'image' ? 'src' : token.type === 'link_open' ? 'href' : null;
      if (!attr) continue;
      const value = token.attrGet(attr);
      if (!value || /^(?:[a-z][a-z\d+.-]*:|\/|#)/i.test(value)) continue;
      const url = new URL(value, `https://source.invalid/${source}`);
      const path = decodeURIComponent(url.pathname.slice(1));
      const target = pages.get(path);
      token.attrSet(attr, target ? `/${target.replace(/index\.html$/, '')}${url.hash}` : path.startsWith('doc/') && !path.endsWith('.md') ? `/${path}${url.hash}` : `${repo}${path}${url.hash}`);
    }
  });
  const markdown = await readFile(resolve(root, source), 'utf8');
  const content = sanitizeHtml(md.render(markdown), {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, '*': ['id'], img: ['src', 'alt', 'title'], code: ['class'] },
  });
  const title = markdown.match(/^# (.+)/m)?.[1] || '使用文档';
  const hero = source === 'README.md' ? '<section class="hero"><p class="eyebrow">CONNECT FROM YOUR TERMINAL</p><h1>校园网络，<br>从命令行出发。</h1><p>Linux、macOS、Windows。一个客户端，三种连接方式。</p><a class="button" href="/downloads/">下载客户端 ↓</a><a class="secondary" href="#快速开始">快速开始 →</a></section>' : '';
  const file = resolve(output, destination);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, layout(title, `${hero}<article class="markdown">${content}</article>`));
}
await mkdir(resolve(output, 'downloads'), { recursive: true });
await writeFile(resolve(output, 'downloads/index.html'), layout('下载', `<section class="hero compact"><p class="eyebrow">RELEASES / DOWNLOADS</p><h1>选择你的客户端。</h1><p>按系统与架构选择版本，使用 Cloudflare 或 GitHub 下载。</p></section><section class="downloads"><div class="filters"><label>版本<select id="version" disabled></select></label><label>系统<select id="platform"><option value="">全部系统</option><option>Linux</option><option>macOS</option><option>Windows</option></select></label><label>架构<select id="arch"><option value="">全部架构</option><option>x86_64</option><option>aarch64</option><option>armv7</option><option>riscv64</option></select></label></div><p class="hint">推荐 iwan-client-oidc。Apple Silicon 选 aarch64；Linux musl 版本可独立运行。系统识别仅作初选，请确认架构。</p><p id="status" role="status" aria-live="polite">正在读取已同步版本…</p><div id="files" class="files"></div><noscript><p>下载列表需要 JavaScript。请前往 GitHub Releases 下载。</p></noscript><p><a href="https://github.com/yyy1mu/ustc-iwan/releases">查看所有 GitHub Releases ↗</a></p></section>`, '/downloads.js'));
console.log('Built README, supporting documentation and download page.');
