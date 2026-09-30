# Cloudflare 网站与 R2 下载服务

项目网站目标域名为 `https://iwan.novusapp.app`。根目录 README 在构建时转成网页，客户端下载文件存放在私有 R2 桶，由 Worker 提供公开的只读下载接口。GitHub Release 继续保留，Actions 不保存中转 artifact。

## 项目结构

```text
workers/downloads/
├── src/index.ts             # R2 下载、HTTP 条件请求与缓存
├── src/index.test.ts        # 下载接口测试
├── web/                    # 网站样式、下载页面脚本与响应头
├── scripts/build-site.mjs   # README 与辅助文档转 HTML
├── scripts/sync_r2.py       # Release 同步、校验、历史补传
├── scripts/test_sync_r2.py  # 同步失败、重试及索引测试
├── wrangler.jsonc           # 域名、静态资源与 R2 绑定
└── package-lock.json        # 固定 Node 依赖
```

`public/`、`dist/`、`.wrangler/` 和生成的类型声明不提交。新增页面逻辑放在 `web/`，下载服务放在 `src/`，维护介绍与使用说明时直接修改仓库原来的 Markdown。

## 本地开发

使用 Node.js 24 LTS 和 Python 3.10 或更新版本：

```bash
cd workers/downloads
npm ci
npm run check
npm test
npm run dev
```

打开 `http://localhost:8787`。本地 R2 默认为空，下载页显示空状态和 GitHub 备用入口，不读取或修改线上桶。`npm run dev` 启动前生成网页；修改 Markdown 后执行 `npm run site` 重新生成。

```bash
npm run site    # 只生成 HTML、CSS、图片及下载页面
npm run check   # 生成绑定类型并检查 TypeScript
npm test       # HTTP 与同步行为测试
npm run test:runtime # 真实本地 R2 模拟运行时验证
npm run build  # 本地打包，不部署
```

| 路径 | 行为 |
|---|---|
| `/` | 根 README 渲染的项目文档 |
| `/downloads/` | 按版本、系统和架构筛选，显示大小、SHA-256 和两个下载入口 |
| `/doc/usage-tips/` | 使用技巧 |
| `/contributing/` | 开发规范 |
| `/development/` | 本文件的网页版本 |
| `/api/releases` | 仅包含完整同步版本的清单 |
| `/files/<tag>/<name>` | R2 流式下载；支持 HEAD、单段 Range、ETag 与日期条件请求 |
| `/health` | Worker 进程健康状态，不代表 R2 已开通或同步完成 |

文件仅在发布索引中列出后可下载；不接受任意上游地址或任意桶路径。多段、无效或超出长度的 Range 返回 416。完整 GET 使用 Cloudflare Cache API；Range 和条件请求直接读取 R2，以保留正确的 HTTP 语义。带版本文件缓存一年，版本内容不可覆盖；下载索引缓存 60 秒。

## 首次配置

1. 在 Cloudflare 控制台开通 R2；若出现计费确认，需要账号所有者处理。
2. 执行 `npx wrangler login`，确认目标账号；创建私有 Standard 桶：

   ```bash
   npx wrangler r2 bucket create ustc-iwan-downloads
   ```

3. 保持桶公共访问关闭。在 Cloudflare R2 创建仅限该桶的 Object Read & Write S3 凭据。
4. 确认 `novusapp.app` 在当前 Cloudflare 账号内，`iwan.novusapp.app` 未被其他服务占用。`wrangler.jsonc` 通过 Custom Domain 绑定域名。
5. 配置 GitHub 仓库变量和 Secrets（不要提交密钥或写入网页）：

| 类型 | 名称 | 用途 |
|---|---|---|
| Variable | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare 账号 ID |
| Variable | `R2_BUCKET_NAME` | 默认 `ustc-iwan-downloads`；改名时同时修改 Wrangler 绑定 |
| Secret | `R2_ACCESS_KEY_ID` | R2 S3 上传凭据 |
| Secret | `R2_SECRET_ACCESS_KEY` | R2 S3 上传凭据 |
| Secret | `CLOUDFLARE_API_TOKEN` | 网站部署；按 Wrangler 要求授予目标账号的 Workers 部署及 R2 绑定所需权限，Custom Domain 涉及对应 zone 权限 |

Worker 运行时使用绑定访问 R2，不使用 S3 凭据。同步脚本从环境变量读取凭据；如使用本地 `.env`，需自行加载到进程环境，脚本不会自动加载它。

## 网站部署

```bash
npm run deploy
npm run logs
```

`.github/workflows/workers.yml` 在 PR 中检查网站，在 `main` 的网站、README 或文档变更后检查并部署，也支持手动运行。研究分支不会自动部署到生产。流水线不上传构建 artifact，部署任务重新构建静态资源。

## Release 与 R2 同步

`.github/workflows/release.yml` 保持 `v*` tag 触发；全部平台构建发布到 GitHub 后，调用 `r2-sync.yml` 同步到 R2。新版本要求全部 29 个平台压缩包齐全。

同步过程：

1. 从正式 GitHub Release 获取压缩包，不使用 Actions artifact。
2. 校验文件大小和 GitHub 提供的 SHA-256（旧附件可能没有摘要，此时计算本地摘要）。
3. 创建版本对象，设置下载响应头和 SHA-256 元数据；不覆盖已有文件。
4. 读回 R2 对象重新计算 SHA-256，确认内容一致。
5. 写入 `SHA256SUMS`、`manifest.json`，最后以条件写更新 `index.json`。并发更新发生冲突时重新读取并重试，避免丢失其他版本。

```text
releases/v26.9.1/<binary>-<platform>-<arch>.zip
releases/v26.9.1/SHA256SUMS
releases/v26.9.1/manifest.json
index.json
```

上传失败不会发布不完整版本，GitHub Release 不受影响。已上传的正式版本文件留待重试复用；runner 临时目录自动清理。重跑会验证同名文件，内容不同则失败，要求发新版本。不要通过覆盖同版本文件修复发布。

R2 中的压缩包是长期托管的最终附件，不设置自动过期删除；未建立额外 staging 桶或 Actions 中转存储。

## 历史版本补传

先只读检查计划，不需要 R2 凭据：

```bash
python3 scripts/sync_r2.py --all --plan
python3 scripts/sync_r2.py --tag v26.9.1 --plan --require-current-matrix
```

GitHub 手动执行 **Sync releases to R2**，`tag` 填 `all` 补传所有历史版本，填具体 tag 则补传该版本。历史版本关闭 `require_current_matrix`。工作流需先存在于默认分支，才会出现在手动运行列表。

本机已通过 `wrangler login` 和 `gh auth login` 登录时，可直接使用官方远程 R2 绑定补传，无需 S3 密钥：

```bash
python3 scripts/sync_r2.py --all --wrangler
```

`--wrangler` 明确写入线上桶，不是本地模拟。它使用独立临时配置，不改变普通 `npm run dev` 的本地 R2 行为；当前该模式限制单文件不超过 64 MiB。较大附件与 CI 使用下面的 S3 方式。

本地使用 S3 凭据执行（已设置上表中的账号、桶及 R2 环境变量，并通过 `gh auth login` 登录）：

```bash
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements.txt
.venv/bin/python scripts/sync_r2.py --all
```

兼容旧版省略 `linux` 的附件名称。跳过草稿和非 zip 附件，预发布版本单独标识，不作为最新稳定版。旧版补传不回退新版本推荐入口。

## 验证上线

```bash
curl -f https://iwan.novusapp.app/health
curl -f https://iwan.novusapp.app/api/releases
curl -I https://iwan.novusapp.app/files/v26.9.1/iwan-client-oidc-linux-x86_64-musl.zip
curl -H 'Range: bytes=0-99' -D - -o /tmp/iwan-range.bin https://iwan.novusapp.app/files/v26.9.1/iwan-client-oidc-linux-x86_64-musl.zip
```

同时打开首页和下载页，检查图片、目录锚点、系统筛选与实际下载。完整文件下载后使用页面给出的 SHA-256 校验。

参考：[Workers 静态资源](https://developers.cloudflare.com/workers/static-assets/)、[R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)、[R2 S3 凭据](https://developers.cloudflare.com/r2/get-started/s3/)。
