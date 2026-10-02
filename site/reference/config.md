# 配置项

国内节点的配置在 `/etc/dns-stack/config.env`，格式是一行一个 `键=值`。仓库里的 `config.example.env` 是起点：`install.sh` 首次安装时复制它，之后每次运行只补齐缺失的键，**不改动已有的值**。

香港节点的 `config.env` 只有 `ROLE=offshore`，由 `install-hk.sh` 写入。

## 基础

| 键 | 默认 | 说明 |
|---|---|---|
| `ROLE` | `cn-resolver` | 节点角色，由安装脚本强制写入 |
| `PUBLIC_IPV4` | — | 公网 IPv4。证书主体、DoH 接入地址、分流集合的大陆样本校验都用它。**必填** |
| `PUBLIC_IPV6` | — | 目前只在迁移导入时保留 |

## 入口

| 键 | 默认 | 说明 |
|---|---|---|
| `DOH_PORT` | `443` | DoH / DoH3 端口，也是访问控制保护的端口 |
| `DOT_PORT` | `853` | DoT / DoQ 端口，也是访问控制保护的端口 |
| `DOH_PATH` | 空 | DoH 私密路径。留空时安装脚本生成随机路径并写回；之后用 `dns-stack doh-path --rotate` 轮换 |
| `UNBOUND_PORT` | `5335` | 本机与香港 Unbound 的端口 |
| `FOREIGN_DNS_WG_IP` | `10.100.0.3` | 香港节点的隧道地址（`wg-peer` 使用） |

## 软件来源

| 键 | 说明 |
|---|---|
| `MOSPROXY_REPO` | mosproxy fork 所在的 GitHub 仓库，安装时从它的 Release 下载 |
| `DNS_STACK_BINARY_REPO` | dns-stack 二进制所在的仓库，安装时从 `binaries-latest` 下载 |
| `GEOIP_RELEASE_REPO` | 归属库镜像所在的仓库（`geoip-latest` Release）；不填时用 `DNS_STACK_BINARY_REPO` |
| `CDN_RULES_BASE` / `CDN_RULES_MIRROR_1` / `CDN_RULES_MIRROR_2` | CDN 直连规则集的来源，按顺序尝试 |

## 面板

| 键 | 默认 | 说明 |
|---|---|---|
| `PANEL_LISTEN` | `127.0.0.1:8080` | 监听地址。非回环地址要求已设密码且证书可读，否则拒绝启动 |
| `PANEL_PUBLIC` | `false` | 安装脚本据此决定用 http 还是 https 做面板探活 |
| `PANEL_CORS_ORIGINS` | 空 | 允许跨域的来源，逗号分隔，不接受通配符 |

## 告警与备份

| 键 | 默认 | 说明 |
|---|---|---|
| `ALERT_WEBHOOK` | 空 | 告警推送地址，见 [健康检查与告警](/ops/health#告警推送) |
| `BACKUP_RETENTION_DAILY` | `3` | 保留几份日备份（1–365） |
| `BACKUP_RETENTION_WEEKLY` | `2` | 保留几份周备份（1–104） |
| `BACKUP_ZSTD_LEVEL` | `6` | 压缩级别（1–19） |
| `BACKUP_ZSTD_THREADS` | `2` | 压缩线程（1–8） |

## 归属库

| 键 | 默认 | 说明 |
|---|---|---|
| `GEOIP_ENABLE_CITY` | `1` | 是否下载 GeoLite2-City |
| `GEO_CROSS_MAX_AGE_SEC` | `172800` | 多源交叉校验结果的最长有效期 |

## 不在样例里、但可以覆盖的键

这些键有合理的默认值，一般不需要改：`TUNNEL_IF`、`TUNNEL_ADDR`、`NFT_TABLE`、`ROUTE_TABLE`、`FWMARK`、`TUNNEL_FAIL_MODE`（`closed` / `open`）、`MIN_SET_ENTRIES`、`GUARD_MIN_RATIO`、`APNIC_URL`、`GEOIP_*_URL`、`CN_SERVER_WG_IP`、`GLOBAL_SERVER_WG_IP`。

::: warning 不要把公共 DNS 写进配置
任何路径——包括降级路径——都不使用公共 DNS。降级上游只有香港的自建 Unbound。
:::

## 不在 config.env 里的设置

| 设置 | 位置 |
|---|---|
| 乐观缓存时长、最小 TTL | 面板「设置 → 数据与证书 → 缓存策略」，写在 Unbound 与 mosproxy 的配置里 |
| 域名黑名单 | `/var/lib/dns-stack/blocklist.txt` |
| 访问控制 | `/var/lib/dns-stack/acl.txt` |
| 人工分流规则 | `/var/lib/dns-stack/manual-cn-zones.txt`、`manual-gfw.txt`、`manual-exclude.txt` |
| 面板用户名、密码与二次认证 | `/etc/dns-stack/secrets/panel/auth.json`，只能经 `dns-stack panel-password` / 面板修改 |
