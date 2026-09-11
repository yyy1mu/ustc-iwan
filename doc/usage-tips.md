# 使用技巧：与 Clash 类软件配合使用

本文介绍如何把 iWAN 作为一条线路接入 Clash / Mihomo（Clash Verge、Clash Meta）、
Stash、Surge 等分流软件：由分流软件负责规则匹配，把需要走 iWAN 的目标流量转发到本程序
的本地 SOCKS5/HTTP 端口。

## 1. 启动本程序的本地代理

```bash
# 交互选线路
./iwan-client-oidc --connect --socks

# 或非交互指定线路
./iwan-client-oidc --connect --socks --server 教育网

# 本地 DNS 被 fake-ip 接管时，建议用 DoH/DoT
./iwan-client-oidc --connect --socks --dns https://dns.alidns.com/dns-query
```

默认监听 `127.0.0.1:1080`；用 `--http` 则默认监听 `127.0.0.1:8080`。
看到 `SOCKS5 listening on 127.0.0.1:1080` 即表示可以接入。

## 2. 在分流软件中添加出站代理

以 Clash / Mihomo 配置为例：

```yaml
proxies:
  - name: iwan
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: false        # 本程序仅支持 TCP CONNECT，没有 UDP ASSOCIATE

proxy-groups:
  - name: iwan-auto
    type: select
    proxies: [iwan, DIRECT]
```

HTTP 端口则用 `type: http`、`port: 8080`。

## 3. 添加分流规则

仓库提供了现成的规则文件 [`doc/iwan-rules.yaml`](iwan-rules.yaml)，包含 USTC 的 11 个网段
和 `ustc.edu.cn` / `ustc.edu` 域名。以 Mihomo / Clash Meta 的 rule-provider 为例：

```yaml
rule-providers:
  iwan:
    type: file
    behavior: classical
    path: ./rules/iwan.yaml        # 把规则文件复制到配置目录下

rules:
  - RULE-SET,iwan,iwan
  - IP-CIDR,<iWAN服务器IP>/32,DIRECT,no-resolve   # 防止环路（见第 4 节）
  - MATCH,DIRECT
```

经典 Clash 不支持 rule-provider 时，可把规则文件 `payload:` 下的条目逐条复制进 `rules:`，
并在每条末尾追加 `,iwan`，例如：

```yaml
  - IP-CIDR,202.38.64.0/19,iwan,no-resolve
  - DOMAIN-SUFFIX,ustc.edu.cn,iwan
```

规则从上到下匹配，把 iWAN 规则放在 `MATCH` 之前；需要其他目标时按同样格式追加。

## 4. 避免流量环路

本程序的隧道底层是发往 iWAN 服务器的 UDP 数据包。如果分流软件开启了 TUN 模式并接管默认
路由，这段 UDP 有可能被再次劫持，形成环路。

- 自 **v26.9.1** 起，本程序默认把隧道 UDP 套接字绑定到**当前活跃的物理网卡**（有线优先，
  自动排除 VPN/TUN、docker 等虚拟网卡），连接时会打印实际选择：

  ```text
    bind en0 (192.168.1.5)
  ```

  因此正常情况下它不会再走进分流软件的虚拟网卡。
- 仍建议在分流软件中为 iWAN 服务器 IP 添加 `DIRECT` 规则作为兜底，尤其是在：
  - Windows 上只有源地址绑定；
  - Linux 上以普通用户运行，无法使用 `SO_BINDTODEVICE` 锁定出口。
- 也可以显式指定出口，例如 `--bind eth0` / `--bind en0` / `--bind 0.0.0.0`。

## 5. 域名与 fake-ip

分流软件使用 fake-ip 时，域名规则可能把假地址交给本程序。两种处理方式：

1. 用 `DOMAIN-SUFFIX`/`DOMAIN-KEYWORD` 等域名规则，让分流软件把域名直接转发给 SOCKS5；
2. 给本程序加 `--dns https://...`（DoH）或 `--dns tls://...`（DoT），绕开被劫持的本地 DNS。

另外注意：本程序的 SOCKS5 仅支持 IPv4 的 `CONNECT`，不支持 IPv6、`BIND` 和 `UDP ASSOCIATE`，
因此分流软件的代理项请设置 `udp: false`，并避免把纯 IPv6 目标规则指向它。

## 6. 常见问题

| 现象 | 排查 |
|------|------|
| 连不上 | 确认本程序已打印 `SOCKS5 listening on ...`，端口未被占用 |
| 请求超时 | 用真实 IP 直连测试（`curl --socks5-hostname 127.0.0.1:1080 https://<真实IP>/`）排除 fake-ip；确认线路可用 |
| 分流不生效 | 检查规则顺序，iWAN 规则需在 `MATCH` 之前；确认代理组选中了 `iwan` |
| 开启 TUN 后 iWAN 掉线 | 为服务器 IP 添加 `DIRECT` 规则，或用 `--bind` 指定物理网卡 |
