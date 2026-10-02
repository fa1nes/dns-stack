# 健康检查与告警

## 自检

```bash
sudo dns-stack health      # 日常检查
sudo dns-stack preflight   # 完整体检，升级、改配置之后都该跑
```

两者是同一套判据（`selfcheck`），`preflight` 额外检查入口探针、权限、conntrack、面板鉴权和 Unbound 配置漂移。每一项给出 ✓ 通过、! 关注、✗ 失败、– 跳过，失败项附带排查或恢复命令。

主要覆盖：

| 分组 | 检查 |
|---|---|
| 模块健康 | 各模块是否在运行、有没有失败的 systemd 单元、二进制是否和 CI 构建一致 |
| 出口分流 | 大陆集合与国内权威集合的规模 |
| 解析链路 | 本机 Unbound 能否应答、香港递归是否可用、境外域名能否解析、上游是否全部在线、Unbound 运行配置与模板是否一致 |
| ECS 就近调度 | 白名单非空且新鲜、`client-subnet-always-forward` 是否打开 |
| 采集 | 采集器有没有在写、数据是不是停在过去 |
| 访问控制 | 清单与内核链是否一致 |
| 入口 | 限流有没有被打满、DoH 路径是不是默认值 |

::: tip 文档里不写项数
检查项会随着系统演进增减，写死的数字每加一项就过期一次。以实际输出为准。
:::

### Unbound 配置漂移

`preflight` 会逐项读取 Unbound 的**运行值**（`unbound-control get_option`），和仓库里的 `unbound/unbound.template.conf` 比较。面板可调的 `serve-expired-ttl`、`cache-min-ttl` 不参与比较；这一版 Unbound 读不到的项（例如 `client-subnet-always-forward`）会单独计数，由专门的检查覆盖。

这项检查来自一次真实故障：线上配置是很早以前手写的，`do-ip6: yes`，而模板早就是 `no`。见 [设计取舍](/intro/tradeoffs#只做-ipv4-出口)。

## 看门狗

`dns-stack-routing-watchdog` 每分钟运行一次，检查：

- 分流链在不在、有没有打标规则；
- NAT 源地址改写链在不在；
- fwmark 策略路由规则在不在；
- 大陆集合是否不少于 1000 条；国内权威集合是否不少于基线的 40%；
- 配了访问控制时，访问控制链在不在。

发现问题就重启分流服务重建，重建成功后清空 Unbound 缓存（故障期间可能缓存了污染答案）。隧道没起来时只等待、不计失败。**连续 5 次修复失败就停手**，等人工处理（处理完删掉 `/var/lib/dns-stack/routing-watchdog.fail`）。

## 告警推送

在 `config.env` 里设置 `ALERT_WEBHOOK` 即可启用。看门狗每分钟汇总一次异常：

- 看门狗自己发现、且没能修好的问题；
- mosproxy 指标接口无响应；
- 离线的上游（例如「上游 foreign-hk 离线」）。

只在异常**出现、变化、恢复**时各推一条，不会每分钟重复刷屏；发送失败会在下一分钟重试，不会因为一次网络抖动就把这次故障漏掉。

消息以 JSON `{"title": …, "body": …}` POST 过去，可以直接填 Bark 的推送地址：

```bash
ALERT_WEBHOOK=https://api.day.app/<你的 key>
```

不设置就不发送，也不报错。

## 面板

侧栏状态点与概览横幅汇总模块状态与解析链路状态；上游表格逐个列出成功率、延迟和在线状态。见 [管理面板](/guide/panel#健康状态怎么看)。
