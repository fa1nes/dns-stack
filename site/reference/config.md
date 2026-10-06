# 配置项

国内节点的配置在 `/etc/dns-stack/config.env`，格式是一行一个 `键=值`。仓库里的 `config.example.env` 是起点：`install.sh` 首次安装时复制它，之后每次运行只补齐缺失的键，**不改动已有的值**。

香港节点的 `config.env` 只有 `ROLE=offshore`，由 `install-hk.sh` 写入。

## 要填的

样例里只有这几个键，其它全部有默认值：

| 键 | 说明 |
|---|---|
| `ROLE` | 节点角色，由安装脚本强制写入 |
| `PUBLIC_IPV4` | 公网 IPv4。证书主体、DoH 接入地址、分流集合的大陆样本校验都用它。**必填** |
| `DNS_STACK_BINARY_REPO` | 代码仓库（`owner/name`）。二进制从它的 `binaries-latest` 下载，归属库镜像和 CDN 规则集的来源也从它推出来。**必填** |
| `DOH_PATH` | DoH 私密路径。留空时安装脚本生成随机路径并写回；之后用 `dns-stack doh-path --rotate` 轮换 |
| `PANEL_LISTEN` | 面板监听地址，默认 `127.0.0.1:8080`。非回环地址要求已设密码且证书可读，否则拒绝启动；安装脚本也据此决定用 http 还是 https 探活 |
| `ALERT_WEBHOOK` | 告警推送地址，见 [健康检查与告警](/ops/health#告警推送) |

## 有默认值、需要时再加

| 键 | 默认 | 说明 |
|---|---|---|
| `DOH_PORT` / `DOT_PORT` | `443` / `853` | 入口端口，也是访问控制保护的端口 |
| `BACKUP_INTERVAL_HOURS` | `24` | 自动备份间隔（小时）；`0` 关闭。例行维护每 6 小时跑一次，所以小于 6 等于 6 |
| `BACKUP_RETENTION_DAILY` / `BACKUP_RETENTION_WEEKLY` | `3` / `2` | 保留几份日备份、周备份。这三项在面板「设置 → 维护 → 备份」里改 |
| `BACKUP_ZSTD_LEVEL` / `BACKUP_ZSTD_THREADS` | `6` / `2` | 备份压缩级别与线程 |
| `PANEL_CORS_ORIGINS` | 空 | 允许跨域的来源，逗号分隔，不接受通配符 |
| `MOSPROXY_REPO` | `versions.lock` 里的仓库 | mosproxy fork 所在的仓库 |
| `GEOIP_RELEASE_REPO` | `DNS_STACK_BINARY_REPO` | 归属库镜像所在的仓库（`geoip-latest` Release） |
| `CDN_RULES_BASE` / `CDN_RULES_MIRROR_1` / `CDN_RULES_MIRROR_2` | 由 `DNS_STACK_BINARY_REPO` 推出 jsDelivr 与 raw.githubusercontent 两个来源 | CDN 直连规则集的来源，按顺序尝试 |
| `GEOIP_ENABLE_CITY` | 开 | 写 `0` 不下载 GeoLite2-City（多源交叉校验会少一个源） |
| `GEO_CROSS_MAX_AGE_SEC` | `172800` | 多源交叉校验结果的最长有效期 |
| `TUNNEL_FAIL_MODE` | `closed` | 隧道断开时境外查询直接失败；`open` 回落直连，见 [出口分流](/guide/routing#隧道断了宁可失败) |

分流的内部参数 `NFT_TABLE`、`ROUTE_TABLE`、`FWMARK`、`MIN_SET_ENTRIES`、`GUARD_MIN_RATIO`、`APNIC_URL`、`GEOIP_*_URL` 也能覆盖，一般用不到。

## 固定不变的

这些值写在代码里，不能配置——它们散在 mosproxy、Unbound、nftables、systemd 和面板的很多地方，改一处等于把系统劈成两半：

| 项 | 值 |
|---|---|
| 隧道 | `wg0`，国内 `10.100.0.2`、香港 `10.100.0.3`，网段 `10.100.0.0/24` |
| Unbound | 两端都监听 `5335` |
| mosproxy 控制接口 | `127.0.0.1:8888` |

::: warning 不要把公共 DNS 写进配置
任何路径——包括降级路径——都不使用公共 DNS。降级上游只有香港的自建 Unbound。
:::

## 不在 config.env 里的设置

| 设置 | 位置 |
|---|---|
| 乐观缓存时长、最小 TTL | 面板「设置 → 缓存与数据」，写在 Unbound 与 mosproxy 的配置里 |
| 拦截名单 | `/var/lib/dns-stack/blocklist.txt` |
| 访问控制 | `/var/lib/dns-stack/acl.txt` |
| 国内解析 / 香港解析名单 | `/var/lib/dns-stack/manual-cn-zones.txt`、`manual-gfw.txt`（面板「设置 → 域名规则」或 `dns-stack route` 维护）；`manual-exclude.txt` 把域名从香港名单里摘出来 |
| 面板用户名、密码与二次认证 | `/etc/dns-stack/secrets/panel/auth.json`，只能经 `dns-stack panel-password` / 面板修改 |
