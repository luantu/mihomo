# CorpLink 同账号多实例连接

## 本次持久化的核心改动

`adapter/outbound/wireguard_corplink.go` 支持在调用 `/vpn/conn` 时，除了已有的
session Cookie 和 `csrf-token`，额外发送：

- `device_id`
- `device_name`

这两个值通过 `corplink-device-id` 和 `corplink-device-name` 配置项传入，并追加到
HTTP Cookie 头中。它们用于把同一账号的不同客户端标识为不同设备；同时每个实例
必须使用独立的 WireGuard 公私钥、Cookie 文件和接口名。

## 为什么可以同时在线

服务器并不是只按用户名密码区分 VPN 会话。登录成功后，`/vpn/conn` 还会根据设备
身份和 WireGuard 公钥分配隧道信息。原来的实例复用了账号会话，但没有发送独立的
设备标识，服务器会把两个连接视为同一客户端，后建立的连接会影响先建立的连接。

现在每个实例具备独立的：

1. `device_id` / `device_name`
2. WireGuard private/public key
3. Cookie 文件
4. WireGuard interface

因此服务器可以分别保存两个 peer，会话不会因为客户端身份相同而互相覆盖。

## Linux 配置要求

`corplink-rs` 的配置字段不能用空字符串表示“自动生成”。需要使用 JSON `null`：

```json
{
  "device_id": null,
  "public_key": null,
  "private_key": null,
  "device_name": "mihomo-device-test-20260822",
  "interface_name": "wgdevtest22"
}
```

程序会据此生成独立设备 ID 和 WireGuard 密钥。Linux 网卡名最长 15 个字符，超过
长度会导致 `Failed to create TUN device: invalid argument`。

不要复制正式实例的 Cookie、公私钥或接口名到第二个实例，也不要把真实账号密码、
Cookie、TOTP 密钥写入 Git。

## 验证标准

必须同时满足：

- Linux 登录成功、`/vpn/conn` 返回 WG 配置、接口为 `UP` 并出现 WireGuard handshake；
- Windows 正式 `SgProxy` 保持 Running，7899/9098 正常，真实代理请求成功；
- Linux 实例保持运行期间，Windows 真实代理请求仍成功。
