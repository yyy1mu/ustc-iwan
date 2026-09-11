# ustc-iwan

USTC iWAN 命令行客户端：通过统一身份认证（OIDC）获取线路配置，并提供三种连接方式。

| 连接方式 | 平台 | 需要 root | 说明 |
|----------|------|-----------|------|
| TUN 隧道 | 仅 Linux | 是（或 `CAP_NET_ADMIN`） | 创建虚拟网卡，按 IP/域名/CIDR 精确路由 |
| SOCKS5 代理 | Linux / macOS / Windows | 否 | 用户态 TCP/IP 栈，默认监听 1080 |
| HTTP 代理 | Linux / macOS / Windows | 否 | 用户态 TCP/IP 栈，默认监听 8080 |

SOCKS5/HTTP 模式由 smoltcp 在用户态生成完整的 TCP/IPv4 数据包，不创建网卡、不修改系统路由。

仓库包含三个二进制：

| 二进制 | 用途 |
|--------|------|
| `iwan-client-oidc` | 推荐使用。负责登录、保存线路配置、选择线路并连接。 |
| `iwan-client` | 手动指定服务器、用户名和密码，适合调试或自定义接入。 |
| `iwan-server` | 自建兼容测试服务端，普通用户通常不需要。 |

## 目录

- [快速开始](#快速开始)
- [安装](#安装)
- [获取线路配置](#获取线路配置)
- [选择线路](#选择线路)
- [连接方式](#连接方式)
- [高级选项](#高级选项)
- [命令行参数](#命令行参数)
- [手动客户端](#手动客户端)
- [服务端](#服务端)
- [使用技巧](#使用技巧)
- [参与贡献](#参与贡献)

## 快速开始

```bash
# 1. 下载对应平台二进制并加执行权限（见「安装」）
chmod +x iwan-client-oidc-*

# 2. 登录并保存线路配置
./iwan-client-oidc --fetch

# 3. 查看本地线路
./iwan-client-oidc --list

# 4. 连接（Linux 推荐 TUN，其他平台用 SOCKS5/HTTP）
sudo ./iwan-client-oidc --connect            # TUN 隧道
./iwan-client-oidc --connect --socks         # SOCKS5 代理
./iwan-client-oidc --connect --http          # HTTP 代理
```

## 安装

从 [GitHub Releases](https://github.com/yyy1mu/ustc-iwan/releases) 下载对应平台的压缩包：

```text
iwan-client-oidc-linux-x86_64-musl      iwan-client-oidc-linux-aarch64-musl
iwan-client-oidc-macos-x86_64           iwan-client-oidc-macos-aarch64
iwan-client-oidc-windows-x86_64.exe     iwan-client-oidc-windows-aarch64.exe
```

- Linux 的 musl 产物为静态链接，可直接运行；另有 gnu/armv7/riscv64 等变体。
- macOS 的 Intel 机器选 `x86_64`，Apple Silicon 选 `aarch64`。
- 手动客户端 `iwan-client` 有对应平台的产物；测试服务端 `iwan-server` 仅提供 Linux 产物。

从源码构建：

```bash
cargo build --release --bin iwan-client-oidc
cargo build --release --bin iwan-client
cargo build --release --bin iwan-server
```

交叉编译（需要 `cargo install cargo-zigbuild` 与对应 target）：

```bash
cargo zigbuild --bin iwan-client-oidc --target aarch64-unknown-linux-musl --release
cargo zigbuild --bin iwan-client --target x86_64-unknown-linux-gnu.2.17 --release
```

## 获取线路配置

```bash
./iwan-client-oidc --fetch
```

命令会输出登录链接。用浏览器打开链接并完成认证后，将回调 URL 粘贴回终端。

如果浏览器提示打开 `iWAN.app`，选择取消，保留在当前网页：

![取消打开 iWAN.app](doc/oidc-cancel-app-dialog.png)

随后在页面按钮上复制链接地址，将复制到的 `com.panabit.mobile://...` 回调 URL 粘贴回终端：

![复制回调链接](doc/oidc-copy-redirect-url.png)

配置保存到 `~/.config/iwan/servers.json`（可用 `--config-dir` 修改目录），包含线路地址、
用户名和加密后的线路密码。`--list` 只读取线路信息，不解密密码。

## 选择线路

```bash
./iwan-client-oidc --list
```

示例输出：

```text
 1. 教育网线路                          <server-ip>:6001
 2. 电信线路                           <server-ip>:6002
 3. 联通线路                           <server-ip>:6001
 4. 移动线路                           <server-ip>:6001
```

`--connect` 时默认交互输入序号；也可以显式指定线路，适合脚本或 systemd 无人值守启动：

```bash
./iwan-client-oidc --connect --server 电信   # 按名称关键字
./iwan-client-oidc --connect --server 2      # 按 1 起始的序号
```

配置用普通用户执行 `--fetch` 保存即可。连接时即使使用 `sudo`，也不需要把配置文件复制到 root 用户目录。

## 连接方式

### TUN 隧道

Linux 下以 root 运行，创建 TUN 设备（需要 `/dev/net/tun`）并建立隧道：

```bash
sudo ./iwan-client-oidc --connect
```

默认只创建并配置 `iwan0`，不修改业务流量路由。需要让指定目标走 iWAN 时，显式传入路由参数：

```bash
sudo ./iwan-client-oidc --connect \
  --proxy-ip 1.1.1.1,2.2.2.2 \
  --proxy-domain example.com,api.example.com \
  --proxy-cidr 10.0.0.0/8
```

| 参数 | 说明 |
|------|------|
| `--proxy-ip` | 指定 IPv4 地址，自动转换为 `/32` 路由。 |
| `--proxy-domain` | 连接前解析域名，并把解析得到的 IPv4 地址加入路由。 |
| `--proxy-cidr` | 指定 CIDR 网段，例如 `10.0.0.0/8` 或 `0.0.0.0/0`。 |
| `--tun` | TUN 设备名，默认 `iwan0`。 |
| `--tun-mtu` | 握手协商的 MTU，同时设置到 TUN 设备，默认 `1400`，上限 `2040`。 |
| `--encrypt` | 协议加密模式，默认 `1`。 |

路由参数可以重复，也可以用逗号分隔。将全部流量路由到 iWAN：

```bash
sudo ./iwan-client-oidc --connect --proxy-cidr 0.0.0.0/0
```

注意：域名只在连接时解析一次，连接后解析变化不会自动同步到路由表。以上路由参数仅 TUN 模式可用。

### SOCKS5 代理

免 root，Linux / macOS / Windows 通用：

```bash
./iwan-client-oidc --connect --socks
curl --socks5-hostname 127.0.0.1:1080 https://www.example.com/
```

默认监听 `127.0.0.1:1080`，可用 `--socks-listen` 修改。支持 `CONNECT`、IPv4 地址目标和
域名目标；不支持 IPv6、`BIND` 或 `UDP ASSOCIATE`（会收到对应的错误响应）。

### HTTP 代理

用 `--http` 启用，默认监听 `127.0.0.1:8080`：

```bash
./iwan-client-oidc --connect --http
curl -x http://127.0.0.1:8080 https://www.example.com/   # CONNECT（HTTPS）
curl -x http://127.0.0.1:8080 http://www.example.com/    # 明文转发
```

支持 `CONNECT host:port`（任意 TCP 隧道）和明文 HTTP 转发（`GET http://host/path` 改写为
`GET /path` 后转发）。限制：仅 IPv4 目标；不支持代理认证；明文 HTTP 每个连接只处理一个请求
（转发时强制 `Connection: close`）。`--socks` 与 `--http` 互斥。

## 高级选项

### 域名解析

SOCKS5/HTTP 模式下，域名由客户端在本机解析为 IPv4 地址，默认使用 `114.114.114.114:53`，
可用 `--dns` 指定其他解析器：

```text
--dns 223.5.5.5                         # 普通 UDP（可带端口：223.5.5.5:5353）
--dns tls://dns.alidns.com              # DNS over TLS（默认端口 853）
--dns https://dns.alidns.com/dns-query  # DNS over HTTPS
```

当本机 DNS 被代理工具接管（如 TUN + fake-ip）时，建议改用 DoT 或 DoH，避免解析到假地址。

### 网络接口绑定

客户端默认把连接服务器的 UDP 套接字绑定到**当前活跃的物理网卡** IPv4 地址：优先有线网卡，
其次无线网卡；虚拟网卡（VPN/TUN、docker、veth 等）会被排除。连接时会打印实际选择：

```text
  bind en0 (192.168.1.5)
```

需要指定其他网卡或地址时使用 `--bind`：

```bash
./iwan-client-oidc --connect --bind eth0          # 按网卡名（Linux）
./iwan-client-oidc --connect --bind en0           # 按网卡名（macOS）
./iwan-client-oidc --connect --bind 192.168.1.5   # 按本机 IP
./iwan-client-oidc --connect --bind 0.0.0.0       # 交还内核按路由选择
```

`iwan-client` 的 `ping`/`auth`/`proxy`/`socks`/`http` 子命令同样支持 `--bind`。按网卡名绑定时，
Linux 会额外尝试 `SO_BINDTODEVICE` 锁定出口（需要 `CAP_NET_ADMIN`，失败时仅保留源地址绑定并
打印警告），macOS 使用 `IP_BOUND_IF`，Windows 使用源地址绑定。

### MTU

| 选项 | 适用模式 | 默认 | 作用 |
|------|----------|------|------|
| `--tun-mtu`（oidc）/ `--mtu`（`iwan-client proxy`） | TUN | 1400 | 握手上报的 MTU，服务器确认后设置到 TUN 设备，上限 2040。 |
| `--proxy-mtu`（oidc，旧名 `--socks-mtu`）/ `--mtu`（`iwan-client socks/http`） | SOCKS5/HTTP | 1380 | 用户态内层 MTU，决定发出的包长；超长下行包会被丢弃，实际取与服务器确认值的较小者。 |
| `--mtu`（`iwan-server`） | 服务端 | 1400 | 服务端 TUN 设备 MTU，应不小于客户端上报值。 |

TUN 默认 1400、用户态默认 1380：后者需为外层 IP+UDP 及协议头预留空间，取更保守的值。

### 性能调优

客户端会把连接服务器的 UDP 套接字收发缓冲区请求为 16 MB。Linux 默认的
`net.core.rmem_max`/`wmem_max`（约 208 KB）会把它钳制到系统上限，高带宽场景可按需调大：

```bash
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

用 `IWAN_DEBUG=1` 运行时会打印实际生效的 `rcvbuf`/`sndbuf`，便于确认是否被钳制。

### 调试输出

设置 `IWAN_DEBUG=1` 可输出 DNS 解析、VPN 收发包与 TCP 状态等诊断信息：

```bash
# Linux / macOS
IWAN_DEBUG=1 ./iwan-client-oidc --connect --socks
```

```powershell
# Windows PowerShell
$env:IWAN_DEBUG = "1"
.\iwan-client-oidc-windows-x86_64.exe --connect --socks
```

```bat
:: Windows CMD
set IWAN_DEBUG=1
iwan-client-oidc-windows-x86_64.exe --connect --socks
```

Windows 上还可用 `setx IWAN_DEBUG 1` 设为用户级永久变量（新开终端生效，`setx IWAN_DEBUG ""` 清除）。
调试信息输出到标准错误，可重定向保存：`... 2> debug.log`。

## 命令行参数

| 参数 | 行为 |
|------|------|
| `--fetch` | 通过 OIDC 登录并保存线路配置。 |
| `--list` | 读取本地配置并列出线路，不联网、不解密密码。 |
| `--connect` | 读取本地配置，选择线路并连接。 |
| `--all` | 依次完成 `--fetch` → `--list` → `--connect`。 |
| `--server <序号\|关键字>` | 非交互选择线路。 |
| `--socks` / `--http` | 启用用户态 SOCKS5 / HTTP 代理，二者互斥。 |
| `--socks-listen <addr>` / `--http-listen <addr>` | 代理监听地址，默认 `127.0.0.1:1080` / `127.0.0.1:8080`。 |
| `--proxy-mtu <mtu>` | 用户态内层 MTU，默认 `1380`。 |
| `--dns <resolver>` | SOCKS5/HTTP 的域名解析器。 |
| `--bind <网卡\|IP>` | 绑定隧道 UDP 套接字的出口网卡或源地址，默认活跃物理网卡（有线优先）。 |
| `--config-dir <dir>` | 配置目录，默认 `~/.config/iwan`。 |
| `--tun <name>` | TUN 设备名（Linux），默认 `iwan0`。 |
| `--tun-mtu <mtu>` | TUN 协商 MTU（Linux），默认 `1400`。 |
| `--proxy-ip` / `--proxy-domain` / `--proxy-cidr` | TUN 路由规则（Linux）。 |
| `--encrypt <0\|1\|2>` | 加密模式：0=None，1=XOR，2=AES，默认 `1`。 |

必须指定 `--fetch`、`--list`、`--connect`、`--all` 中的至少一个动作。

## 手动客户端

`iwan-client` 不使用 OIDC，需要手动提供服务器、用户名和密码。

```bash
# 测试连通性
./iwan-client ping --server <SERVER_IP> --port 6001

# 仅测试认证
./iwan-client auth --server <SERVER_IP> --port 6001 --user <USER> --pass '<PASSWORD>'

# 建立 TUN 隧道（Linux，root）
sudo ./iwan-client proxy --server <SERVER_IP> --port 6001 \
  --user <USER> --pass '<PASSWORD>' --proxy-ip 1.1.1.1,2.2.2.2

# 用户态 SOCKS5 / HTTP 代理（免 root）
./iwan-client socks --server <SERVER_IP> --port 6001 \
  --user <USER> --pass '<PASSWORD>' --listen 127.0.0.1:1080
./iwan-client http  --server <SERVER_IP> --port 6001 \
  --user <USER> --pass '<PASSWORD>' --listen 127.0.0.1:8080
```

## 服务端

`iwan-server` 用于自建测试环境，连接 USTC iWAN 不需要运行服务端：

```bash
sudo ./iwan-server \
  --port 6001 \
  --tun iwan-srv \
  --mtu 1400 \
  --server-ip 198.18.0.1 \
  --subnet 198.18.0.0/16 \
  --dns 114.114.114.114 \
  --users /etc/iwan/users.txt \
  --nat-if eth0
```

用户文件格式为每行 `username:password`。服务端所在机器需要开启 IPv4 转发和 NAT：

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -s 198.18.0.0/16 -o eth0 -j MASQUERADE
```

## 使用技巧

与 Clash / Mihomo / Stash / Surge 等分流软件配合使用时，可在其配置中添加一个指向本程序
本地端口的出站代理（SOCKS5 默认 `127.0.0.1:1080`，HTTP 默认 `127.0.0.1:8080`），再用规则
把需要走 iWAN 的目标流量导过去。本程序默认绑定物理网卡，不会走进分流软件的虚拟网卡造成
环路；完整配置示例、防环路与 fake-ip 处理见 [doc/usage-tips.md](doc/usage-tips.md)，
现成的 USTC 网段与域名规则见 [doc/iwan-rules.yaml](doc/iwan-rules.yaml)。

## 参与贡献

欢迎反馈与贡献，但请遵守以下约定：

- **先讨论再提交**：提交 Pull Request 前，请先创建 issue 说明需求与方案，达成一致后再动手。
- **不接受与官方程序重复的功能**：USTC iWAN 官方客户端已有的能力（例如 Windows 上使用 WinTUN 建立 TUN）不再重复实现。
- **补充而非替代**：本项目是官方程序的轻量补充（命令行、免 root 代理），不追求复刻或取代官方客户端。

详细开发规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 免责声明

本项目仅供学习、研究和合法授权访问使用。使用者应自行确认其使用方式符合所在网络和服务的规则。
