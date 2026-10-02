# 故障排查

**第一步永远是：**

```bash
sudo dns-stack preflight
```

失败项会附上排查命令。下面按现象列出常见路径。

## 完全解析不了

```bash
dig @127.0.0.1 -p 5335 example.com        # 绕过 mosproxy，直接问本机 Unbound
sudo journalctl -u mosproxy -n 50 --no-pager
sudo tail -n 50 /var/log/dns-stack/unbound.log   # Unbound 写自己的日志文件，不进 journal
```

- Unbound 能解析、设备不行 → 问题在 mosproxy、证书或 DoH 路径（`dns-stack doh-path` 核对客户端填的地址）。
- Unbound 也不行 → 看递归链路：`sudo dns-stack routing-status`。
- 设置了访问控制、家里换了公网地址 → SSH 登录执行 `sudo dns-stack acl disable`。

## 境外域名解析失败、国内正常

几乎总是隧道问题。

```bash
sudo wg show wg0 latest-handshakes        # 握手时间是否在 2 分钟内
dig @10.100.0.3 -p 5335 www.wikipedia.org # 香港 Unbound 本身是否正常
```

- 隧道断开时境外查询**刻意失败**，不会回落直连。
- 香港机每月 1 号 01:00 例行重启，期间会短暂出现这种情况并收到告警。

## 个别域名一直 SERVFAIL

```bash
dig @127.0.0.1 -p 5335 <域名>
sudo dns-stack query-log --domain <域名> --since 24h
```

逐跳看它的权威：

```bash
sudo dns-stack test <域名>
```

如果它的权威有很多 IPv6 地址，确认 Unbound 的 `do-ip6` 是 `no`（`unbound-control get_option do-ip6`）。国内节点没有 IPv6 路由，开着它会让 Unbound 把发送预算全耗在不可达的地址上。`preflight` 的「Unbound 运行配置与模板一致」会报出这种漂移。

要看 Unbound 内部到底发生了什么，可以短暂提高日志级别（看完一定要恢复）：

```bash
unbound-control flush <域名>
unbound-control verbosity 4
dig @127.0.0.1 -p 5335 <域名>
unbound-control verbosity 1
grep -E "sending to target|exceeded|SERVFAIL" /var/log/dns-stack/unbound.log | tail
```

## 某个国内站被解析到境外节点

```bash
sudo dns-stack test <域名>
sudo dns-stack test <域名> 219.141.136.0/24   # 带上运营商网段，看设备实际会拿到什么
```

- 权威在大陆却拿到境外节点 → 多半是冷启动：这个域名刚被第一次解析，还没进国内权威集合。等一轮流水线（15 分钟）或 `sudo dns-stack routing-refresh`。
- 权威全在境外、但确认它该按国内对待 → 写进 `/var/lib/dns-stack/manual-cn-zones.txt` 后 `routing-refresh`。
- CDN 在大陆有节点、答案却在境外 → ECS 没送达：`sudo dns-stack cdn-hit --fresh`。

## 某个网站变慢

```bash
sudo dns-stack query-log --domain <域名> --since 1h
```

看耗时和递归类型。缓存命中应在 1 ms 以内；一次冷递归几百毫秒是正常的。持续很慢时用 `dns-stack test` 看它的权威走哪条路。

## 面板打不开

不影响解析，可以慢慢修：

```bash
sudo systemctl restart dns-stack-panel
sudo journalctl -u dns-stack-panel -n 50 --no-pager
```

面板监听非回环地址时，没设密码或读不到证书会拒绝启动——日志里会写明是哪一条。

## 证书过期

```bash
sudo dns-stack cert-check
sudo dns-stack cert-renew
```

## 统计数字停住了

查询照常、统计不动，是采集器出了问题——这类故障不影响解析，所以最容易被忽视。

```bash
sudo dns-stack health          # 「采集」一组会报出数据停在什么时候
sudo journalctl -u mosproxy -n 50 --no-pager
```
