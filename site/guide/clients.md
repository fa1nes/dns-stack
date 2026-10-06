# 客户端接入

## 拿到接入地址

真实地址不写进任何文档：仓库是公开的，写进去等于泄露。在服务器上执行：

```bash
sudo dns-stack doh-path
```

输出类似：

```
DOH_PATH=/<32 位十六进制>/dns-query
DOH_URL=https://<服务器IP>/<32 位十六进制>/dns-query
DOH_PATH_IS_DEFAULT=0
DOT_URL=tls://<服务器IP>:853
DOQ_URL=quic://<服务器IP>:853
```

也可以在面板「设置 → 接入」里查看并复制，三种协议的地址都在那里。

| 协议 | 地址 |
|---|---|
| DoH / DoH3 | `https://<服务器IP>/<私密路径>/dns-query` |
| DoT | `tls://<服务器IP>:853` |
| DoQ | `quic://<服务器IP>:853` |

::: tip 必须按 IP 访问
证书是 Let's Encrypt 签发的 **IP 证书**，证书里的名字就是那个 IP。不要另外编一个域名指过去，那样证书校验会失败。
:::

## sing-box

```json
{
  "dns": {
    "servers": [
      {
        "tag": "self-doh",
        "address": "https://<服务器IP>/<私密路径>/dns-query",
        "detour": "direct"
      }
    ]
  }
}
```

`detour` 用直连即可：分流已经在服务端做完了，再套一层代理反而多绕一圈。

## Windows 11

路径是自定义的，不能用「自动模板」（那只认公共 DNS 的已知模板），要先手工登记：

```powershell
# 管理员 PowerShell
netsh dns add encryption server=<服务器IP> dohtemplate=https://<服务器IP>/<私密路径>/dns-query autoupgrade=yes
```

然后在 设置 → 网络和 Internet → 以太网 / WLAN → DNS 服务器分配 → 编辑 → 手动，IPv4 打开，首选 DNS 填 `<服务器IP>`，「DNS over HTTPS」选「打开（手动模板）」。

## Android

系统的「私人 DNS」只接受主机名，填不了 IP 也填不了路径。Android 上用支持 DoH 的客户端（例如 sing-box）来配。

## Firefox

设置 → 隐私与安全 → 启用基于 HTTPS 的 DNS → 自定义 → 填完整的 DoH 地址。

## 命令行自测

```bash
DOH="$(sudo dns-stack doh-path | grep ^DOH_URL= | cut -d= -f2-)"
curl -s -H 'accept: application/dns-message' \
  "${DOH}?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" | xxd | head
```

`dns=` 后面是 `example.com A` 查询的 base64url 编码。拿到二进制应答就说明入口、证书和路径都是通的。

## 路径泄露了怎么办

```bash
sudo dns-stack doh-path --rotate
```

换完之后所有客户端都要同步更新，旧地址立即失效。详见 [加密入口](/guide/entry#私密-doh-路径)。
