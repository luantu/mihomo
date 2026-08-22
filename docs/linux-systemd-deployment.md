# Linux systemd 部署方案

本方案用于在 Linux 上运行第二个独立的 CorpLink/Mihomo 实例，同时保留
Windows 正式实例 `SG-Node`。Linux 对外节点名称为 `SG-Node-Linux`。

## 代码分支

代码仓库为 `https://github.com/luantu/mihomo.git`；CorpLink 授权生成器仓库为
`https://github.com/luantu/corplink-rs.git`。

使用 GitHub 分支 `feat/corplink-sg-wg-tcp`。当前关键提交包括：

- `c742ab45`：支持独立的 CorpLink device ID/device name；
- `bab38092`：目标超时不拆除健康隧道；
- `2749c582`：WireGuard TCP 数据面处理；
- `2e61b42e`：保留 CorpLink 协商的 MTU 1400；
- `0698410c`：本部署文档。

部署前应确认远端 Git 分支包含这些提交；不要只拿旧的默认分支构建。

全新机器获取代码：

```bash
git clone --branch feat/corplink-sg-wg-tcp https://github.com/luantu/mihomo.git /opt/mihomo-sg
cd /opt/mihomo-sg
git log -1 --oneline
```

`git log` 至少应能看到 `2e61b42e` 和 `0698410c`。

授权生成器使用 `master` 分支：

```bash
git clone --depth 1 --branch master https://github.com/luantu/corplink-rs.git /opt/corplink-rs
cd /opt/corplink-rs
git log -1 --oneline
```

## 全新 Linux 前置条件

以下命令以 Debian/Ubuntu amd64 为例：

```bash
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git build-essential pkg-config jq openssl
```

构建 `corplink-rs` 还需要 Rust/Cargo。安装 Rust 后执行：

```bash
cd /opt/corplink-rs/libwg
./build.sh
cd /opt/corplink-rs
cargo build --release
install -m 755 target/release/corplink-rs /usr/local/bin/corplink-rs
```

本方案最终由 `mihomo-intl-node.service` 对外提供代理；`corplink-rs` 只用于生成或
刷新授权信息，不要让两个服务争用同一个接口名或 Cookie。

本项目 `go.mod` 要求 Go 1.20 或更高版本。安装后确认：

```bash
go version
```

如果服务器不能访问 Go module proxy，应预先准备 Go module cache 或配置内部 `GOPROXY`，不要在依赖未完成时替换生产二进制。

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

构建后检查产物：

```bash
file /root/mihomo-device-test-20260822/mihomo-linux-amd64-device-test
sha256sum /root/mihomo-device-test-20260822/mihomo-linux-amd64-device-test
```

必须显示 `ELF 64-bit ... x86-64`，不能是 `PE32` 或 Windows 文件。

## 生成全新 CorpLink 授权

授权生成器 `corplink-rs` 不应复用 Windows 的配置目录。准备独立目录，例如：

```text
/opt/corplink-sg/config.json
/opt/corplink-sg/wgdevtest22_cookies.json
```

`config.json` 的关键初始字段应类似：

```json
{
  "username": "现场填写",
  "password": "现场填写",
  "device_id": null,
  "public_key": null,
  "private_key": null,
  "device_name": "SG-Node-Linux-<hostname>",
  "interface_name": "wgdevtest22"
}
```

`device_id`、`public_key`、`private_key` 必须使用 `null`，让生成器创建新值；Linux
接口名不超过 15 个字符。首次运行命令格式为：

```bash
sudo /usr/local/bin/corplink-rs /opt/corplink-sg/config.json
```

按 2FA 流程完成登录，确认生成独立 Cookie、公私钥、设备 ID。不要把密码、2FA、
Cookie 或密钥写进 GitHub。

如发行版命令与此不同，以仓库 README 和 `corplink-rs --help` 为准。成功标准是登录
成功、`/vpn/conn` 返回 WG 信息，并且授权文件属于本 Linux 实例。

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
