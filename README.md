# ustc-iwan

USTC iWAN 命令行客户端，用于通过统一身份认证获取线路配置，并通过 SOCKS5
代理或 Linux TUN 隧道连接。

主要功能：

- 通过 OIDC 登录获取 iWAN 线路配置。
- 将线路配置保存到本机，后续可直接离线查看线路列表。
- 选择线路建立 Linux TUN 隧道。
- 按 IP、域名或 CIDR 精确控制哪些流量进入隧道。

仓库包含三个二进制：

| 二进制 | 用途 |
|--------|------|
| `iwan-client-oidc` | 推荐使用。负责登录、保存线路配置、选择线路并连接。 |
| `iwan-client` | 手动指定服务器、用户名和密码，适合调试或自定义接入。 |
| `iwan-server` | 自建兼容测试服务端，普通用户通常不需要。 |

两个客户端均支持无 TUN 的 SOCKS5/HTTP 模式。该模式由 smoltcp 在用户态生成完整
TCP/IPv4 数据包，不创建网卡、不修改系统路由，也不需要 root 或
`CAP_NET_ADMIN`。

## 系统要求

- TUN 模式仅支持 Linux，需要 `/dev/net/tun`。
- TUN 模式连接时需要 root 权限，或为程序授予 `CAP_NET_ADMIN`。
- SOCKS5/HTTP 模式支持 Linux、macOS 和 Windows，不创建 TUN，不需要上述权限。
- macOS 和 Windows 版本只包含 SOCKS5/HTTP 模式。

## 下载

从 GitHub Releases 下载对应架构的二进制。

常用文件：

- `iwan-client-oidc-linux-aarch64-musl`
- `iwan-client-oidc-linux-x86_64-musl`
- `iwan-client-linux-aarch64-musl`
- `iwan-client-linux-x86_64-musl`
- `iwan-client-oidc-macos-aarch64`
- `iwan-client-oidc-macos-x86_64`
- `iwan-client-oidc-windows-aarch64.exe`
- `iwan-client-oidc-windows-x86_64.exe`

下载后加执行权限：

```bash
chmod +x iwan-client-oidc-*
```

源码构建产物位于：

```text
target/<target>/release/
```

## OIDC 使用流程

### 1. 获取线路配置

```bash
./iwan-client-oidc --fetch
```

命令会输出登录链接。用浏览器打开链接并完成认证后，将回调 URL 粘贴回终端。

如果浏览器提示打开 `iWAN.app`，选择取消，保留在当前网页：

![取消打开 iWAN.app](doc/oidc-cancel-app-dialog.png)

随后在页面按钮上复制链接地址，将复制到的 `com.panabit.mobile://...` 回调 URL 粘贴回终端：

![复制回调链接](doc/oidc-copy-redirect-url.png)

配置保存位置：

```text
~/.config/iwan/servers.json
```

配置文件包含线路地址、用户名和加密后的线路密码。`--list` 只读取线路信息，不解密密码。

### 2. 列出本地线路

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

如果配置文件不存在，命令会提示先执行 `--fetch`。

### 3. 连接

```bash
sudo ./iwan-client-oidc --connect
```

命令会读取本地配置并显示线路列表。输入序号后，只解密所选线路的密码，并建立 TUN 隧道。

也可以用 `--server` 跳过交互选择，适合脚本或 systemd 无人值守启动：

```bash
sudo ./iwan-client-oidc --connect --server 电信
```

`--server` 接受线路序号（如 `2`）或线路名称中的关键字（如 `电信`）。

配置用普通用户执行 `--fetch` 保存即可。连接时即使使用 `sudo`，也不需要把配置文件复制到 root 用户目录。

### 无 TUN 的 SOCKS5 模式

Linux：

```bash
./iwan-client-oidc --connect --socks
```

macOS（无 TUN，仅支持 SOCKS5/HTTP）：

```bash
./iwan-client-oidc-macos-aarch64 --connect --socks \
  --socks-listen 127.0.0.1:1080 \
  --proxy-mtu 1380
```

Intel Mac 请将文件名替换为 `iwan-client-oidc-macos-x86_64`。

Windows PowerShell（无 TUN，仅支持 SOCKS5/HTTP）：

```powershell
.\iwan-client-oidc-windows-x86_64.exe --connect --socks `
  --socks-listen 127.0.0.1:1080 `
  --proxy-mtu 1380
```

Windows ARM64 请将文件名替换为
`iwan-client-oidc-windows-aarch64.exe`。

三个平台均使用 `--socks` 显式启用 SOCKS5 模式。默认监听
`127.0.0.1:1080`，默认用户态内层 MTU 为 `1380`，可以通过
`--socks-listen` 和 `--proxy-mtu` 修改这两个值。

当前 SOCKS5 模式支持 `CONNECT`、IPv4 地址目标和域名目标。域名由客户端
在本机解析为 IPv4 地址，默认使用 `114.114.114.114:53`，可以通过
`--dns` 指定其他解析器：

```text
--dns 223.5.5.5              # 普通 UDP（可带端口：223.5.5.5:5353）
--dns tls://dns.alidns.com   # DNS over TLS（默认端口 853）
--dns https://dns.alidns.com/dns-query   # DNS over HTTPS
```

当本机 DNS 被代理工具接管（如 TUN + fake-ip）时，建议改用 DoT 或 DoH，
避免解析到假地址。

使用示例：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://www.example.com/
```

不支持 IPv6、SOCKS5 `BIND` 或 `UDP ASSOCIATE`。这些请求会收到对应的
SOCKS5 错误响应。

### 无 TUN 的 HTTP 代理模式

与 SOCKS5 模式相同，用 `--http` 显式启用：

```bash
./iwan-client-oidc --connect --http
```

macOS/Windows 示例：

```bash
./iwan-client-oidc-macos-aarch64 --connect --http \
  --http-listen 127.0.0.1:8080
```

默认监听 `127.0.0.1:8080`，可用 `--http-listen` 修改；内层 MTU 与 SOCKS5
共用 `--proxy-mtu`（旧名 `--socks-mtu` 仍可用），域名解析同样使用 `--dns`。`--socks` 与 `--http` 互斥。

支持两种请求：

- `CONNECT host:port`：用于 HTTPS 等任意 TCP 隧道。
- 明文 HTTP 转发：`GET http://host/path HTTP/1.1`，代理改写为
  `GET /path HTTP/1.1` 后转发。

使用示例：

```bash
curl -x http://127.0.0.1:8080 https://www.example.com/
curl -x http://127.0.0.1:8080 http://www.example.com/
```

限制：仅支持 IPv4 目标；不支持代理认证；明文 HTTP 每个连接只处理一个
请求（转发时强制 `Connection: close`），后续请求由客户端重新连接。

### 4. 一次完成

```bash
sudo ./iwan-client-oidc --all
```

该命令依次完成：

```text
--fetch -> --list -> --connect
```

## 路由规则

默认连接只创建并配置 `iwan0`，不会修改业务流量路由。

需要让指定目标走 iWAN 时，显式传入代理规则：

```bash
sudo ./iwan-client-oidc --connect \
  --proxy-ip 1.1.1.1,2.2.2.2 \
  --proxy-domain example.com,api.example.com \
  --proxy-cidr 10.0.0.0/8
```

参数说明：

| 参数 | 说明 |
|------|------|
| `--proxy-ip` | 指定 IPv4 地址，自动转换为 `/32` 路由。 |
| `--proxy-domain` | 连接前解析域名，并把解析得到的 IPv4 地址加入路由。 |
| `--proxy-cidr` | 指定 CIDR 网段，例如 `10.0.0.0/8` 或 `0.0.0.0/0`。 |
| `--tun` | TUN 设备名，默认 `iwan0`。 |
| `--tun-mtu` | 握手协商的 MTU，同时设置到 TUN 设备，默认 `1400`，上限 `2040`（仅 Linux）。 |
| `--encrypt` | 协议加密模式，默认 `1`。 |

代理参数可以重复，也可以用逗号分隔：

```bash
--proxy-ip 1.1.1.1,2.2.2.2
--proxy-ip 1.1.1.1 --proxy-ip 2.2.2.2
```

将全部流量路由到 iWAN：

```bash
sudo ./iwan-client-oidc --connect --proxy-cidr 0.0.0.0/0
```

注意：域名只在连接时解析一次。连接后域名解析变化不会自动同步到路由表。

## MTU 说明

| 选项 | 适用模式 | 默认 | 作用 |
|------|----------|------|------|
| `--tun-mtu`（oidc）/ `--mtu`（`iwan-client proxy`） | TUN | 1400 | 握手时上报的 MTU，服务器确认后设置到 TUN 设备。上限 2040（客户端上行批量发送槽为 2048 字节）。 |
| `--proxy-mtu`（oidc，旧名 `--socks-mtu`）/ `--mtu`（`iwan-client socks/http`） | SOCKS5/HTTP | 1380 | 用户态 TCP/IP 栈的内层 MTU，决定发出的包长；超过该长度的下行包会被丢弃。实际取与服务器确认值的较小者。 |
| `--mtu`（`iwan-server`） | 服务端 | 1400 | 服务端 TUN 设备的 MTU，应不小于客户端上报值，避免下行包被丢弃。 |

TUN 模式默认 1400、用户态模式默认 1380：后者需要为外层 IP+UDP 及协议头预留空间，
且不依赖内核路由，取更保守的值。

## OIDC 命令参数

| 参数 | 行为 |
|------|------|
| `--fetch` | 通过 OIDC 登录并保存线路配置。 |
| `--list` | 读取本地配置并列出线路，不联网，不解密密码。 |
| `--connect` | 只读取本地配置，选择线路并连接。 |
| `--all` | 拉配置、列线路、选择并连接。 |
| `--config-dir <DIR>` | 指定配置目录，默认 `~/.config/iwan`。 |

必须指定 `--fetch`、`--list`、`--connect`、`--all` 中的至少一个动作。

## 手动客户端

`iwan-client` 不使用 OIDC，需要手动提供服务器、用户名和密码。

```bash
./iwan-client ping --server <SERVER_IP> --port 6001
```

仅测试认证：

```bash
./iwan-client auth \
  --server <SERVER_IP> \
  --port 6001 \
  --user <USER> \
  --pass '<PASSWORD>'
```

建立隧道：

```bash
sudo ./iwan-client proxy \
  --server <SERVER_IP> \
  --port 6001 \
  --user <USER> \
  --pass '<PASSWORD>' \
  --proxy-ip 1.1.1.1,2.2.2.2
```

不创建 TUN，启动用户态 SOCKS5 代理：

```bash
./iwan-client socks \
  --server <SERVER_IP> \
  --port 6001 \
  --user <USER> \
  --pass '<PASSWORD>' \
  --listen 127.0.0.1:1080
```

不创建 TUN，启动用户态 HTTP 代理：

```bash
./iwan-client http \
  --server <SERVER_IP> \
  --port 6001 \
  --user <USER> \
  --pass '<PASSWORD>' \
  --listen 127.0.0.1:8080
```

## 从源码构建

本地构建：

```bash
cargo build --release --bin iwan-client-oidc
cargo build --release --bin iwan-client
cargo build --release --bin iwan-server
```

交叉编译到 aarch64 Linux musl：

```bash
cargo install cargo-zigbuild
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --bin iwan-client-oidc --target aarch64-unknown-linux-musl --release
```

GNU 目标可以指定 glibc 版本：

```bash
cargo zigbuild --bin iwan-client --target x86_64-unknown-linux-gnu.2.17 --release
cargo zigbuild --bin iwan-client --target aarch64-unknown-linux-gnu.2.17 --release
```

## 服务端

`iwan-server` 用于自建测试环境。连接 USTC iWAN 不需要运行服务端。

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

用户文件格式：

```text
username:password
```

服务端所在机器需要开启 IPv4 转发和 NAT：

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -s 198.18.0.0/16 -o eth0 -j MASQUERADE
```

## 免责声明

本项目仅供学习、研究和合法授权访问使用。使用者应自行确认其使用方式符合所在网络和服务的规则。
