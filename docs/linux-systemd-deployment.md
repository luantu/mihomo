# Linux systemd 部署方案

本方案用于在 Linux 上运行第二个独立的 CorpLink/Mihomo 实例，同时保留
Windows 正式实例 `SG-Node`。Linux 对外节点名称为 `SG-Node-Linux`。

## 代码分支

使用 GitHub 分支 `feat/corplink-sg-wg-tcp`。当前关键提交包括：

- `c742ab45`：支持独立的 CorpLink device ID/device name；
- `bab38092`：目标超时不拆除健康隧道；
- `2749c582`：WireGuard TCP 数据面处理；
- `2e61b42e`：保留 CorpLink 协商的 MTU 1400。

部署前应确认远端 Git 分支包含这些提交；不要只拿旧的默认分支构建。

## 工作方式

1. `corplink-rs` 用账号登录并生成/刷新 Linux 实例的授权信息。
2. `mihomo-sg` 负责 WireGuard-TCP 隧道和代理端口；systemd 负责常驻、重启和日志。
3. Linux Mihomo 配置使用独立的 device ID、device name、Cookie、私钥、公钥和隧道地址。
4. Linux 代理以混合 HTTP/SOCKS5 方式暴露在 `:7999`，控制器在 `:9198`。
5. Clash Party 复写脚本将 `SG-Node-Linux` 指向 `172.18.34.110:7999`；Windows `SG-Node` 仍指向 `127.0.0.1:7899`。

## Linux 构建

推荐直接在 Linux 构建，避免 Windows 交叉编译时遗漏构建标签：

```bash
GOOS=linux GOARCH=amd64 go build -tags with_gvisor \
  -o /root/mihomo-device-test-20260822/mihomo-linux-amd64-device-test .
```

`with_gvisor` 是必须的；缺少它会在启动时出现：
`gVisor is not included in this build`。

## 配置要点

- `mixed-port: 7999`
- `external-controller: 0.0.0.0:9198`
- WireGuard-TCP endpoint 使用 CorpLink 选中的国际节点，例如 `140.224.74.169:34080`；不要误用普通节点的 `33080`。
- `remote-dns-resolve: true` 必须保留。
- DoH 使用 `8.8.8.8` 和 `1.1.1.1`，并确保 DNS 请求通过隧道访问。
- MTU 使用 CorpLink 下发值 1400；不要重新加入 TCP 模式 1280 强制截断。
- 配置中保留 `corplink:` 刷新段，使 Mihomo 启动时能根据 Cookie 获取最新会话参数。

## systemd 安装

将仓库中的 `mihomo-intl-node.service` 安装为：

```bash
install -m 644 mihomo-intl-node.service /etc/systemd/system/mihomo-intl-node.service
systemctl daemon-reload
systemctl enable --now mihomo-intl-node.service
```

服务必须使用独立工作目录，例如：
`/root/mihomo-device-test-20260822`。日志同时保留在 journald 和配置指定的
`logs/mihomo.log`：

```bash
systemctl status mihomo-intl-node.service
journalctl -u mihomo-intl-node.service -f
tail -f /root/mihomo-device-test-20260822/logs/mihomo.log
```

## 验收顺序

```bash
systemctl is-enabled mihomo-intl-node.service
systemctl is-active mihomo-intl-node.service
ss -ltnp | grep -E ':7999|:9198'
curl -k -L --max-time 30 -x http://127.0.0.1:7999 \
  -o /dev/null -sS -w 'http=%{http_code}\n' \
  https://chatgpt.com/robots.txt
```

日志中必须能看到：

- `corplink refreshed`；
- `WireGuard handshake completed`；
- DoH 目标 `8.8.8.8:443` 或 `1.1.1.1:443` 通过 Linux 节点访问；
- 代理监听 `:7999` 和控制器监听 `:9198`。

随后在 Windows 上用原有 `127.0.0.1:7899` 再做一次 ChatGPT 请求，确认两个实例同时在线。

## 安全和持久化注意事项

不要把以下内容提交 GitHub：用户名密码、TOTP、Cookie、私钥、设备授权 JSON、完整生产配置。
这些内容应在目标 Linux 主机上单独生成并备份。每个实例必须使用自己的 device ID、
device name、Cookie 和密钥，不能复制 Windows 的授权文件。

`SG-Node` 是 Windows 节点，`SG-Node-Linux` 是 Linux 节点；复写脚本中不能用 Linux
节点覆盖或重命名 Windows 节点。
