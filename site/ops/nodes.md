# 两台节点

## 国内节点 `cn-resolver`

| 项 | 内容 |
|---|---|
| 系统 | Debian 12，systemd |
| 内存 | 1.8GB——所有批处理单元都设了内存上限 |
| 职责 | 加密入口、递归、出口分流、数据流水线、采集、面板、告警 |
| 隧道地址 | `wg0` 10.100.0.2 |
| 安装方式 | `install.sh`，按 `ROLE=cn-resolver` 部署 |

国内节点的 Unbound 只监听回环和隧道地址（`127.0.0.1:5335`、`10.100.0.2:5335`），客户端永远经 mosproxy 的加密入口进来。它的配置模板是仓库里的 `unbound/unbound.template.conf`，自检会比对线上运行值是否和模板一致。

出口只走 IPv4：`do-ip6: no`。原因见 [设计取舍](/intro/tradeoffs#只做-ipv4-出口)。

## 香港节点 `offshore`

| 项 | 内容 |
|---|---|
| 系统 | Alpine，OpenRC（没有 systemd） |
| 规格 | 约 430MB 内存、1GB 磁盘 |
| 职责 | ① 国内节点经隧道过来的递归从这里出网；② mosproxy 的降级上游 `foreign-hk` |
| 隧道地址 | `wg0` 10.100.0.3，Unbound 监听 `10.100.0.3:5335`，只放行 10.100.0.2 |
| 安装方式 | `install-hk.sh` |

它上面**没有需要维护的业务逻辑**：不生成数据、不写数据库、不对外发布。dns-stack 二进制在这里只用来每天给日志瘦身。

### `install-hk.sh` 做了什么

1. 创建目录，校验 `/opt/dns-stack/bin/dns-stack-go` 能在本机执行（CI 构建的静态二进制，不依赖 musl/glibc）。
2. 写 `ROLE=offshore` 到 `/etc/dns-stack/config.env`。
3. 在 root 的 crontab 里写一条每日 04:41 的 `trim-logs`，每份日志保留末尾 2MB。
4. 让 Unbound 扛住开机顺序和崩溃：
   - 写 `ip-freebind: yes`，Unbound 不必等 `wg0` 起来就能绑定隧道地址；
   - 改由 `supervise-daemon` 守护，进程崩溃会被拉起；
   - 先确认旧进程真的退出，再切换守护方式。
5. 用 `dig` 验证本机 Unbound 能应答。

香港 Unbound 的主配置和 WireGuard 配置目前是手工维护的，不在安装脚本里。

### 每月例行重启

香港机每月 1 号 01:00 会按计划重启（这条 cron 属于机器主人，不属于 dns-stack）。重启期间：

- 国内节点经隧道的境外递归会失败（显式失败，不回落直连）；
- mosproxy 把 `foreign-hk` 标记为离线，看门狗推送告警，恢复后再推一条「已恢复」；
- 开机后 Unbound 靠 `ip-freebind` 与 supervise-daemon 自行就位，不需要人工介入。

::: warning BusyBox 的坑
Alpine 用的是 BusyBox：`pkill -x unbound` 匹配不到进程。要停进程用 `start-stop-daemon -K -x /usr/sbin/unbound`，再轮询 `/proc/*/comm` 确认它真的退出了。
:::

## 两台机器之间

```
国内 10.100.0.2  ⇄  WireGuard  ⇄  香港 10.100.0.3
```

- 国内 Unbound 发往境外权威的包打上 fwmark，按策略路由进 `wg0`，在香港做 NAT 出网。
- 国内 mosproxy 的降级上游直接指向 `10.100.0.3:5335`。
- 国内节点上的 `dns-stack wg-peer root@<香港机>` 可以把本机注册成香港的 WireGuard peer，默认只预演，加 `--apply` 才执行。
