# ustc-iwan

USTC iWAN 的 Linux 命令行客户端。

这个仓库主要解决两件事：

- 使用统一身份认证获取 iWAN 线路配置，并在本机保存。
- 选择一条线路建立 Linux TUN 隧道，按需把指定 IP、域名或网段路由进隧道。

项目包含三个二进制：

| 二进制 | 用途 |
|--------|------|
| `iwan-client-oidc` | 推荐入口。通过 OIDC 拉取 USTC iWAN 配置、列出线路、选择线路并连接。 |
| `iwan-client` | 手动指定服务器、用户名和密码连接，主要用于调试。 |
| `iwan-server` | 自建兼容测试服务端。普通使用者一般不需要。 |

## 系统要求

- Linux。
- 连接时需要 root 权限，或给程序授予 `CAP_NET_ADMIN`。
- 系统需要 `/dev/net/tun`。

## 下载

到 GitHub Releases 页面下载对应架构的二进制。

常用文件：

- `iwan-client-oidc-aarch64-musl`
- `iwan-client-oidc-x86_64-musl`
- `iwan-client-aarch64-musl`
- `iwan-client-x86_64-musl`

下载后加执行权限：

```bash
chmod +x iwan-client-oidc-*
```

如果你是从源码构建，二进制会在：

```text
target/<target>/release/
```

## OIDC 使用流程

### 1. 拉取配置

```bash
./iwan-client-oidc --fetch
```

程序会输出登录链接。用浏览器打开后，把跳转回来的 `com.panabit.mobile://...` URL 粘贴回终端。

成功后会保存：

```text
~/.config/iwan/servers.json
```

这个文件包含线路地址、用户名和加密后的密码。`--list` 不会解密密码。

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

如果本地没有配置文件，会报错并提示先执行 `--fetch`。

### 3. 连接

```bash
sudo ./iwan-client-oidc --connect
```

程序会读取本地配置，列出线路，让你输入序号。选择后只解密这一条线路的密码，并建立 TUN 隧道。

`sudo` 下默认仍会读取发起 sudo 用户的配置，例如：

```text
/home/x/.config/iwan/servers.json
```

不会改读 `/root/.config/iwan/servers.json`。

### 4. 一次完成

```bash
sudo ./iwan-client-oidc --all
```

等价于：

```text
--fetch -> --list -> --connect
```

## 路由规则

默认连接只创建并配置 `iwan0`，不会劫持任何业务流量。

要让指定目标走 iWAN，需要显式传参数：

```bash
sudo ./iwan-client-oidc --connect \
  --proxy-ip 1.1.1.1,2.2.2.2 \
  --proxy-domain example.com,api.example.com \
  --proxy-cidr 10.0.0.0/8
```

参数说明：

| 参数 | 说明 |
|------|------|
| `--proxy-ip` | 指定 IPv4 地址。程序会自动转成 `/32` 路由。 |
| `--proxy-domain` | 连接前解析域名，把解析出的 IPv4 地址加入路由。 |
| `--proxy-cidr` | 指定 CIDR 网段，例如 `10.0.0.0/8` 或 `0.0.0.0/0`。 |
| `--tun` | TUN 设备名，默认 `iwan0`。 |
| `--encrypt` | 协议加密模式，默认 `1`。 |

这些参数可以重复，也可以用逗号分隔：

```bash
--proxy-ip 1.1.1.1,2.2.2.2
--proxy-ip 1.1.1.1 --proxy-ip 2.2.2.2
```

全流量走 iWAN：

```bash
sudo ./iwan-client-oidc --connect --proxy-cidr 0.0.0.0/0
```

注意：域名只在连接时解析一次。域名后续 DNS 变化不会自动更新路由。

## OIDC 命令参数

| 参数 | 行为 |
|------|------|
| `--fetch` | 通过 OIDC 登录并保存线路配置。 |
| `--list` | 只读取本地配置并列出线路，不联网，不解密密码。 |
| `--connect` | 只读取本地配置，选择线路并连接。 |
| `--all` | 拉配置、列线路、选择并连接。 |
| `--config-dir <DIR>` | 指定配置目录，默认 `~/.config/iwan`。 |

不带 `--fetch`、`--list`、`--connect`、`--all` 中任意一个会直接报错。

## 手动客户端

`iwan-client` 不走 OIDC，需要你自己提供服务器、用户名和密码。

```bash
./iwan-client ping --server <SERVER_IP> --port 6001
```

只测试认证：

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

## GitHub Release 为什么不在代码列表里

GitHub Actions 构建出来的二进制不会自动提交到仓库根目录，也不会出现在 Code 页面的文件列表中。

这个项目的 workflow 只监听 tag push：

```yaml
on:
  push:
    tags: ['v*']
```

推送 `v*` tag 后，Actions 会构建所有 matrix 目标，并把 zip 文件上传到 GitHub Releases 的对应 tag 页面。

如果 Releases 页面没有看到文件，先检查：

- 这个 tag 是否真的 push 到 GitHub。
- Actions 是否被仓库启用。
- 对应 tag 的 workflow run 是否成功。
- Release job 是否因为某个 matrix 构建失败而没有执行。

## 从源码构建

本机构建：

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

GNU 目标可指定 glibc 版本：

```bash
cargo zigbuild --bin iwan-client --target x86_64-unknown-linux-gnu.2.17 --release
cargo zigbuild --bin iwan-client --target aarch64-unknown-linux-gnu.2.17 --release
```

## 服务端

`iwan-server` 用于自建测试，不是连接 USTC iWAN 的必要组件。

```bash
sudo ./iwan-server \
  --port 6001 \
  --tun iwan-srv \
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

服务端所在机器需要开启转发和 NAT：

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -s 198.18.0.0/16 -o eth0 -j MASQUERADE
```

## 安全说明

- `servers.json` 中保存的是加密后的线路密码。
- `--list` 不会解密密码。
- `--connect` 只在内存中解密用户选择的线路密码。
- 不建议把配置文件提交到公开仓库。

## 免责声明

本项目仅供学习、研究和合法授权访问使用。使用者应自行确认其使用方式符合所在网络和服务的规则。
