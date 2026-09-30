const version = document.querySelector('#version');
const platform = document.querySelector('#platform');
const arch = document.querySelector('#arch');
const status = document.querySelector('#status');
const files = document.querySelector('#files');
let releases = [];
const os = navigator.userAgent;
platform.value = /Windows/i.test(os) ? 'Windows' : /Macintosh|Mac OS X/i.test(os) ? 'macOS' : /Linux/i.test(os) ? 'Linux' : '';
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function link(label, href, className) {
  const node = element('a', label, className);
  node.href = href;
  return node;
}
function render() {
  files.replaceChildren();
  const release = releases.find(r => r.tag === version.value);
  if (!release) return;
  const selected = release.files.filter(f => (!platform.value || f.platform === platform.value) && (!arch.value || f.arch === arch.value));
  status.textContent = `${release.tag} · ${selected.length} 个文件${release.prerelease ? ' · 预发布版本' : ''}`;
  if (!selected.length) files.append(element('p', '当前版本没有匹配文件，请切换系统、架构或版本。'));
  for (const file of selected) {
    const card = element('article', '', 'file');
    card.append(element('p', `${file.platform} / ${file.arch}${file.libc ? ` / ${file.libc}` : ''}`, 'eyebrow'));
    card.append(element('h2', file.binary));
    card.append(element('p', `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB`, 'filename'));
    const actions = element('div', '', 'actions');
    actions.append(link('Cloudflare 下载 ↓', `/files/${encodeURIComponent(release.tag)}/${encodeURIComponent(file.name)}`, 'button'));
    actions.append(link('GitHub ↗', `https://github.com/yyy1mu/ustc-iwan/releases/download/${encodeURIComponent(release.tag)}/${encodeURIComponent(file.name)}`, 'secondary'));
    card.append(actions);
    const details = element('details');
    details.append(element('summary', 'SHA-256 校验值'), element('code', file.sha256));
    card.append(details);
    files.append(card);
  }
}
for (const input of [version, platform, arch]) input.addEventListener('change', render);
try {
  const response = await fetch('/api/releases');
  if (!response.ok) throw new Error('release index unavailable');
  const data = await response.json();
  releases = data.releases;
  for (const release of releases) {
    const option = element('option', `${release.tag}${release.tag === data.latest ? ' · 最新稳定版' : ''}${release.prerelease ? ' · 预发布' : ''}`);
    option.value = release.tag;
    version.append(option);
  }
  if (data.latest) version.value = data.latest;
  version.disabled = releases.length === 0;
  if (releases.length) render();
  else status.textContent = '暂时没有已同步到 Cloudflare 的版本，请使用下方 GitHub Releases。';
} catch {
  status.textContent = 'Cloudflare 下载列表暂时不可用，请使用下方 GitHub Releases。';
}
