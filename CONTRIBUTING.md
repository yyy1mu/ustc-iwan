# 贡献指南

感谢参与 ustc-iwan。本文说明如何提交 issue、修改代码和发起 Pull Request。

## 开始之前

- 使用前请阅读 [README.md](README.md) 了解项目功能与使用方式。
- 使用 Coding Agent 辅助开发时，请同时阅读 [AGENTS.md](AGENTS.md)。
- 提交前请确认改动符合当地网络与服务的使用规则（见 README 免责声明）。

## 环境要求

- Rust stable（edition 2021），与 CI 使用的 `dtolnay/rust-toolchain@stable` 一致。
- TUN 模式仅在 Linux 可用，需要 root 或 `CAP_NET_ADMIN`；macOS/Windows 只能开发与验证 SOCKS5/HTTP 模式。
- 交叉编译需要 `cargo install cargo-zigbuild` 和对应 target。

## 构建与运行

```bash
cargo build                                              # debug 构建全部
cargo build --release --bin iwan-client-oidc             # OIDC 客户端
cargo build --release --bin iwan-client                  # 手动客户端
cargo build --release --bin iwan-server                  # 测试服务端（仅 Linux）
cargo run --bin iwan-client-oidc -- --list               # 离线查看线路
```

交叉编译示例：

```bash
cargo zigbuild --bin iwan-client-oidc --target aarch64-unknown-linux-musl --release
cargo zigbuild --bin iwan-client --target x86_64-unknown-linux-gnu.2.17 --release
```

## 提交前检查

请在本地依次执行，确保全部通过：

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
cargo build --release --bin <受影响的二进制>
```

注意：CI（`.github/workflows/release.yml`）只在推送 `v*` tag 时构建发布，不会自动跑 fmt/clippy/test。

## 代码规范

- 使用默认 `rustfmt`（4 空格缩进、尾逗号）。
- 命名：函数/变量/模块 `snake_case`，类型/trait `PascalCase`，常量 `SCREAMING_SNAKE_CASE`。
- 错误处理统一用 `anyhow::Result`，用 `.context(...)`/`.with_context(...)` 补充上下文。
- 平台差异用 `#[cfg(target_os = "linux")]` 门控，保证非 Linux 目标仍可编译。
- 调试输出必须通过 `iwan::core::util::debug_enabled()`（`IWAN_DEBUG` 环境变量）门控；用户可见状态用 `println!`/`eprintln!`。
- 禁止打印 token、密码、密文等敏感数据。
- 代码注释用英文、保持稀疏；README/文档用中文。
- 单元测试写在同一文件的 `#[cfg(test)] mod tests` 中，不新建 `tests/` 目录。

## 架构约定

- 共享逻辑放 `src/core`，`src/bin/*` 只做 CLI 参数解析与流程编排。
- `protocol.rs`、`crypto.rs`、`gcm.rs` 是与 iWAN 服务端的 wire-level 兼容层，修改前先确认协议兼容性。
- `src/bin/oidc/controller.rs` 的 `CONTROLLER`/`APP_ID`/`APP_SECRET` 与 `src/bin/oidc/main.rs` 的 `DOMAIN` 是服务端约定常量，不要改动。
- `src/core/netstack/` 是 smoltcp 胶水层，涉及用户态 TCP/IP 正确性，改动后必须跑测试。
- 新增依赖前请说明必要性，项目依赖刻意保持精简。

## 提交信息

使用 Conventional Commits，主题用英文祈使句，正文解释原因：

```text
feat: add cross-platform SOCKS5 client
fix: keep TUN sessions alive with echo packets
docs: document --server and --dns options
refactor: harden DNS resolver parsing
perf: enlarge UDP buffers for all client sockets
style: cargo fmt
ci: initialize MSVC tools for Windows releases
merge: release v2.2.0 SOCKS5 support
release: rebuild iwan unified client
```

一次提交只做一件事，不要混入无关格式化或重命名。

## Pull Request

1. Fork 仓库，从 `main` 创建功能分支（如 `feat/server-selection`）。
2. 在分支上完成修改，确保「提交前检查」全部通过。
3. 向 `main` 发起 PR，描述动机、改动内容和验证方式；涉及 CLI/配置变更时同步更新 README。
4. 维护者会以 merge commit 方式合入；合入后请勿复用或 force-push 已合并的分支。

## 不要提交的内容

- `target/` 等构建产物。
- 密钥、凭证、`~/.config/iwan/servers.json` 等本机配置。
- `Cargo.lock` 只能通过 cargo 命令更新，依赖变更时随提交一起更新。

## 发布

发布由维护者推送 `v*` tag 触发，会自动构建 Linux/macOS/Windows 产物并创建 GitHub Release。普通贡献者无需打 tag。
