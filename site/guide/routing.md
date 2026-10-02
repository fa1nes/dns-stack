# 出口分流

出口分流是整套系统的核心：**Unbound 递归时发出的每一个包，按目标权威的位置决定走哪条路。**

## 落地方式

| 机制 | 作用 |
|---|---|
| `nft inet dns_route` 的 `output` 链 | 只匹配 Unbound 进程（按 uid）。目标不在 `@direct4`、`@cn_authority`、`@tunnel_endpoints` 里，就打上 fwmark `0x1d5` |
| `ip rule fwmark 0x1d5 lookup 100` | 打了标的包查路由表 100，走 `wg0` 隧道 |
| `ip rule fwmark 0x1d5 prohibit` | 隧道断开时，打了标的包被**显式拒绝** |
| `postrouting` 链 | 出隧道的包做源地址改写 |

作用范围只有 Unbound 进程，本机其它流量不受影响。

### 隧道断了宁可失败

默认的故障策略是 `closed`：隧道断开时境外查询直接失败，不回落直连。回落直连拿到的是被污染的答案——看着成功，实际更危险。

可以在 `config.env` 里把 `TUNNEL_FAIL_MODE` 设为 `open` 换取可用性，代价是隧道断开期间境外解析可能拿到伪造地址。不建议。

## 两个集合

### `@direct4`：大陆 IPv4 网段

- 来源是 APNIC 的一手委派记录，用纯真库（qqwry）补充并反向排除，每天重建。
- 只收全局可路由地址：私有、保留、组播网段一律不进。
- 安装分流链前会做语义校验：集合不能含非全局网段；本机公网地址必须在集合里；隧道对端（香港）必须不在集合里。任何一条不满足都拒绝安装。
- 集合条数低于下限时拒绝安装分流链，否则国内递归查询会被全部导进隧道。

### `@cn_authority`：已知的国内权威

「权威含大陆地址」的区域，由流水线从 Unbound 的 infra 记录里学习，每 15 分钟更新：

- 大陆权威按网段聚合；
- 境外权威**严格按 /32** 收录——一些境外 CDN 和国内服务共用 anycast 地址，按网段聚合会误伤；共享 anycast 地址由专门的步骤每小时识别并排除。

## 判断一个域名走哪条路

```bash
sudo dns-stack test www.example.com
```

输出会逐台列出注册域的权威、它们的地址和判定（在大陆 → 直连 / 属于国内权威 → 直连 / 在境外 → 经隧道），再给出最终答案落在大陆还是境外，以及本机 Unbound 与香港 Unbound 两个视角的 A / AAAA / CNAME / HTTPS 记录。

一次解析里直连和隧道可以交替出现：问根和 `.com` 的包多半走隧道，问国内 CDN 权威的那一跳走直连。

## 人工干预

绝大多数情况不需要。国内权威集合每 15 分钟自动学习，一个域名第一次被查询时可能还没被收录，第二次就会纠正。持续不纠正时再人工补：

| 文件（`/var/lib/dns-stack/`） | 作用 |
|---|---|
| `manual-cn-zones.txt` | 人工补充「应当按国内权威对待」的区域，下一轮流水线生效 |
| `manual-gfw.txt` | 强制只交给香港 Unbound。用于国内权威返回空应答这类特例 |
| `manual-exclude.txt` | 把域名从 `manual-gfw.txt` 里摘出来，回到默认路径 |

```bash
echo "example.cn" | sudo tee -a /var/lib/dns-stack/manual-cn-zones.txt
sudo dns-stack routing-refresh     # 立即重建分流数据，不必等定时器

echo "example.com" | sudo tee -a /var/lib/dns-stack/manual-gfw.txt
sudo dns-stack reload              # 重载 mosproxy 域名表，不中断解析
```

匹配是域匹配：写 `example.com` 就覆盖 `www.example.com` 等全部子域。

## 查看现状

```bash
sudo dns-stack routing-status
```

面板「设置 → 数据与证书」可以查看并整表导出直连域名、污染 IP 等分流数据集。

## 看门狗

`dns-stack-routing-watchdog` 每分钟检查一次：分流链在不在、策略路由在不在、集合规模是否正常。异常时自动重建，并通过告警通道推送。详见 [健康检查与告警](/ops/health)。
