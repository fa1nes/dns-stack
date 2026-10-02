# 证书

## 用的是什么证书

加密入口使用 Let's Encrypt 签发的 **IP 证书**：证书里的名字就是服务器的公网 IP，有效期约 6 天。所以客户端必须按 IP 访问。

| 文件 | 用途 |
|---|---|
| `/etc/dns-stack/secrets/doh-dot.pem` / `.key` | mosproxy 的四个入口 |
| `/etc/dns-stack/secrets/panel/cert.pem` / `key.pem` | 面板的副本，属主 `dns-stack-panel`，权限 0400 |

## 自动续签

续签由例行维护 `dns-stack-maintenance` 承担（每 6 小时一次）：

1. 检查剩余天数、证书里有没有当前的 `PUBLIC_IPV4`、私钥是否匹配；
2. 剩余不到 3 天，或者 IP 对不上，才调用 acme.sh 续签；
3. 续签成功后同步面板的副本并重启面板。

mosproxy 不需要重启：它会在 10 秒内发现证书文件变了并自行加载，**缓存和在途连接都保得住**。新证书加载失败时继续用旧证书，因为 ACME 客户端写证书和私钥不是原子的，那个窗口里握手失败比继续用一张仍然有效的旧证书更糟。

::: tip 2026-10-01 修正
续签后的处理曾经按旧的版本号格式判断 mosproxy 支不支持热重载，结果每次续签（约 3 天一次）都会重启 mosproxy，丢掉整个缓存。现在按 fork 的 semver 版本号判断，不再重启。
:::

## 命令

```bash
sudo dns-stack cert-check   # 剩余天数、到期时间、SAN 是否含 IP、私钥是否匹配
sudo dns-stack cert-renew   # 立即走一遍续签判断（仍然只在需要时才真正续签）
```

## 首次签发

安装时如果还没有证书，`install.sh` 会先放一张自签证书占位，让服务能起来。对外服务之前需要先用 acme.sh 为公网 IP 签发一次，并设置好 `PUBLIC_IPV4`，之后才由例行维护接管。

## 证书过期了怎么办

如果服务器长时间关机超过有效期，回来后执行一次 `sudo dns-stack cert-renew` 即可。自检会在 acme.sh 没登记重载命令时提示。
