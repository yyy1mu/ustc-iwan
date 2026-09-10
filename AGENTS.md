# AGENTS.md

本文件面向 Coding Agent，用于安全地修改本仓库。内容基于当前代码与配置，未确认的规则标为 TODO。

## 1. 项目简介

`ustc-iwan` 是 USTC iWAN 的 Rust 命令行客户端，通过统一身份认证（OIDC）获取线路配置，并用 Linux TUN 隧道或跨平台用户态 SOCKS5 代理连接。

- 语言/构建：Rust 2021（`Cargo.toml` 的 `version = "0.1.0"` 与发布版本无关，发布版本由 Git tag `v*` 决定）。
- 三个二进制：`iwan-client-oidc`（推荐）、`iwan-client`（手动参数/调试）、`iwan-server`（自建测试服务端，仅 Linux）。
- 平台限制：TUN 模式仅 Linux 且需 root/CAP_NET_ADMIN；macOS/Windows 只有 SOCKS5 模式。

## 2. 目录结构及职责

```text
Cargo.toml / Cargo.lock      依赖与构建配置（Cargo.lock 已提交，保持同步）
src/lib.rs                   库 crate `iwan` 的入口，re-export core 公共模块
src/core/                    客户端与服务端共享逻辑
  auth.rs                    认证握手（OPEN/ACK、TLV 解析）
  crypto.rs                  MD5/SHA256/HMAC/AES/XOR 等底层原语
  gcm.rs                     纯 Rust AES-GCM 解密线路密码、base64url
  protocol.rs                数据包类型、TLV 常量与编解码
  socks.rs                   用户态 SOCKS5 数据面（smoltcp，跨平台）
  util.rs                    IWAN_DEBUG、ip 命令封装
  proxy.rs / route.rs / tun.rs   TUN 数据面与路由（仅 Linux，cfg 门控）
  netstack/                  smoltcp 胶水层（device/dns/tunnel，crate 内部）
src/bin/client/              手动客户端（cli/auth/ping/proxy/socks）
src/bin/oidc/                OIDC 客户端（cli/controller/oidc + main 流程）
src/bin/server/              测试服务端（cli/handler/session，仅 Linux）
doc/                         README 引用的截图、参考脚本 full_flow.py
.github/workflows/release.yml  tag `v*` 触发的发布构建
target/                      构建产物，已 gitignore，勿提交
```

## 3. 安装、启动、构建

```bash
cargo build                          # debug 构建全部
cargo build --release --bin iwan-client-oidc
cargo build --release --bin iwan-client
cargo build --release --bin iwan-server
cargo run --bin iwan-client-oidc -- --list
```

交叉编译（需 `cargo install cargo-zigbuild` 与对应 target）：

```bash
cargo zigbuild --bin iwan-client-oidc --target aarch64-unknown-linux-musl --release
cargo zigbuild --bin iwan-client --target x86_64-unknown-linux-gnu.2.17 --release
```

## 4. lint / typecheck / test

```bash
cargo fmt --check                    # 当前通过，使用默认 rustfmt 配置（无 rustfmt.toml）
cargo clippy --all-targets           # 当前无警告（无 clippy.toml，CI 不跑 lint）
cargo test                           # 单元测试，当前 9 个全过
cargo check                          # Rust 无独立 typecheck，用 check/clippy 代替
```

注意：CI（`release.yml`）只做发布构建，不会自动跑 fmt/clippy/test，必须本地手动执行。

## 5. 代码风格与命名规范

- 使用默认 `rustfmt`（4 空格缩进、尾逗号），改动后必须 `cargo fmt`。
- 命名：函数/变量/模块 `snake_case`，类型/trait `PascalCase`，常量 `SCREAMING_SNAKE_CASE`，字段 `snake_case`。
- 错误处理统一 `anyhow::Result`，用 `.context(...)`/`.with_context(...)` 补充信息；不引入新错误库。
- 用户可见输出：状态/错误用 `println!`/`eprintln!`（CLI 中常见两空格缩进前缀）；调试细节必须用 `iwan::core::util::debug_enabled()`（`IWAN_DEBUG` 环境变量）门控。
- 禁止打印 token、密码、密文等敏感数据（近期提交专门移除了 token 输出）。
- 注释：代码内注释与文档注释用英文、保持稀疏；README/文档用中文。
- 单元测试写在同一文件内的 `#[cfg(test)] mod tests`，不新建 `tests/` 目录（当前不存在）。
- 提交信息使用 Conventional Commits：`feat:` `fix:` `docs:` `ci:` `refactor:` `release:` `merge:`，主题英文、祈使句，正文解释原因。

## 6. 架构原则

- 共享逻辑放 `src/core`（库），`src/bin/*` 只做 CLI 参数解析与流程编排，保持薄封装。
- 平台差异用 `#[cfg(target_os = "linux")]` 门控，非 Linux 目标必须能编译：Linux 专属功能在非 Linux 上要么整体 `cfg` 掉，要么给出明确报错（参考 `src/bin/server/main.rs`）。
- 协议/加密是 wire-level 兼容层：`protocol.rs`、`crypto.rs`、`gcm.rs` 的常量与算法必须与 iWAN 服务端一致，改动前先确认兼容性。
- SOCKS5 走 `core/socks.rs` + `core/netstack/`（smoltcp，用户态组包）；TUN 走 `core/proxy.rs` + `route.rs` + `tun.rs`。两条路径共享 `auth`/`protocol`/`crypto`。
- OIDC 流程的 HTTP 签名、时间戳、nonce 逻辑在 `src/bin/oidc/controller.rs`；`APP_ID`/`APP_SECRET`/`CONTROLLER`/`DOMAIN` 是服务端约定常量，不要改动。
- 新增依赖前先确认必要性；当前依赖刻意精简（见 `Cargo.toml`），不要随意引入大型框架。

## 7. 不要随意修改的文件/目录

- `src/core/protocol.rs`：包类型、TLV 常量、签名格式，改动会破坏与上游服务端的兼容。
- `src/core/crypto.rs`、`src/core/gcm.rs`：密码解密与加密算法，错误改动会导致认证失败。
- `src/bin/oidc/controller.rs` 中的 `CONTROLLER`/`APP_ID`/`APP_SECRET`、`src/bin/oidc/main.rs` 中的 `DOMAIN`/`APP_SECRET`。
- `src/core/netstack/`：smoltcp 胶水与 MTU 相关逻辑，涉及用户态 TCP/IP 正确性，改后必须跑测试。
- `.github/workflows/release.yml`：发布与交叉编译流程；改动前先确认 tag 触发方式。
- `Cargo.lock`：只能通过 cargo 命令更新，不要手改。
- `doc/*.png`：被 README 直接引用，勿删除或重命名。
- `target/`、构建产物：已 gitignore，不要提交。

## 8. 新增功能放哪里

- 共享协议/加密/数据面逻辑 → `src/core/<module>.rs`，在 `src/core/mod.rs` 注册；对外暴露再更新 `src/lib.rs`（Linux-only 模块需加 `cfg`）。
- 新 CLI 子命令 → 在对应 `src/bin/<bin>/cli.rs` 定义 clap 参数，新建处理模块，并在该 bin 的 `main.rs` match 中接线。
- OIDC/配置相关 → `src/bin/oidc/`；服务端 → `src/bin/server/`。
- 平台专属代码 → 新建模块并用 `#[cfg(target_os = "linux")]` 门控；非 Linux 路径给出清晰错误。
- 测试 → 与被测代码同文件的 `#[cfg(test)] mod tests`。

## 9. 修改完成后的验证步骤

1. `cargo fmt`（或至少 `cargo fmt --check`）。
2. `cargo clippy --all-targets`，确保无新增警告。
3. `cargo test`，确保全部通过。
4. `cargo build --release --bin <受影响的二进制>`；若涉及 `cfg` 分支，尽量验证非 Linux 目标仍可 `cargo check --target <target>`（TODO：确认团队是否要求跨平台 check）。
5. 若改了 CLI 参数、配置文件格式或用户可见行为，同步更新 `README.md`（中文）。
6. TUN/路由改动只能在 Linux + root 环境做真实联调；macOS 本地至少验证 SOCKS5 路径。

## 10. Git / commit 注意事项

- 当前主分支 `main`，远端 `origin`（github.com/yyy1mu/ustc-iwan）。
- 遵循 Conventional Commits（见第 5 节），一次提交只做一件事；需要时可写正文说明原因与验证方式。
- 不要提交 `target/`、密钥/凭证、`~/.config/iwan/servers.json` 等本机配置；`Cargo.lock` 要随依赖变更提交。
- 不要主动 commit/push/tag，除非用户明确要求。
- 发布由 tag 触发：推送 `v*` tag 会运行 `.github/workflows/release.yml` 构建并创建 Release；不要随意打 tag。
- TODO：仓库未配置 PR 模板/分支保护说明，如需协作流程请补充。
