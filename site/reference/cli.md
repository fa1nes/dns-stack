# 命令参考

所有功能都在一个二进制里：`dns-stack <子命令> [参数]`。`dns-stack help` 打印完整列表；不记命令时直接运行 `sudo dns-stack`，会进交互菜单。

改动系统状态的命令需要 root。

## 日常运维

| 命令 | 作用 |
|---|---|
| `status` | 一屏看完本机全部模块：分组、状态、上次 / 下次运行。`--json` 输出机器可读格式 |
| `health` | 健康检查（等同 `selfcheck`） |
| `preflight` | 投产校验（等同 `selfcheck --full`）：追加入口探针、权限、conntrack、面板鉴权、Unbound 配置漂移 |
| `test <域名> [子网]` | 解析一个域名并解释出口分流、CDN 归属与就近结果；带子网时模拟该网段的设备 |
| `reload` | 重载 mosproxy 域名表（及 Unbound） |
| `restart` | 重启 mosproxy 与 Unbound |
| `logs [单元]` | 查看最近 100 行日志 |
| `cert-check` / `cert-renew` | 检查 / 续签 TLS 证书 |
| `doh-path` | 打印 DoH 接入地址；`--rotate` 随机换一个私密路径，`--set <路径>` 换成指定路径 |
| `routing-status` | 查看递归出口分流现状 |
| `routing-refresh` | 立即重建全部分流数据 |

## 递归管理

| 命令 | 作用 |
|---|---|
| `blocklist` | 域名黑名单：命中的查询由 mosproxy 直接回 NXDOMAIN |
| `acl` | 访问控制：只放行授权网段访问加密入口（回环与隧道始终放行） |
| `query-log` | 查询日志：按时间、递归类型、域名、来源子网筛选，`--csv` 导出，`--breakdown` 看构成 |
| `cdn-hit` | 以真实中国 /24 的身份解析大厂域名，判定是否拿到了大陆 CDN 节点；`--fresh` 先清缓存 |

## 备份与迁移

| 命令 | 作用 |
|---|---|
| `backup` / `export` / `import` / `verify` / `list-packages` | 备份与迁移包 |
| `migrate <root@新机> [--port N] [--identity 私钥] [--dry-run]` | 一键迁移到新服务器 |
| `migration-finish` | 停掉旧服务器上的服务（不删数据） |
| `migration-export` / `migration-restore` | 与面板「导出迁移数据」共用同一份清单，一条密钥都不含；恢复支持 `--dry-run` |
| `db-migrate` | 备份数据库并按当前 schema 就地迁移 |
| `wg-peer <root@香港机> [--apply]` | 把本机注册成香港的 WireGuard peer（默认预演） |

## 面板凭据与数据清理

| 命令 | 作用 |
|---|---|
| `panel-password` | 设置 / 重置面板密码 |
| `panel-2fa-reset` | 关闭面板二次认证 |
| `clear-audit` | 清空审计记录 |
| `clear-domains [天数\|all]` | 清理超过 N 天（默认 7）没出现过的域名及其查询记录；`all` 清空全部 |
| `set-arch-epoch [时间戳]` | 重设统计起点（默认现在）：面板上所有「近 24 小时」的数字从此刻重新累计 |
| `purge-legacy` | 删除早于统计起点的查询记录并压缩数据库 |
| `vacuum-logs [7d\|2w]` | 删除指定时长之前的 systemd 日志（`journalctl --vacuum-time`） |

以上清理命令都会先显示影响范围并要求确认。

## 判据与数据工具

这些主要由流水线和自检调用，也可以单独运行来排查：

| 命令 | 作用 |
|---|---|
| `domain-check` | 对每行域名输出形态判据结果 |
| `ipset-check` | 加载 CIDR 集合并对每行 IP 输出是否命中 |
| `geoip-check` / `geoip-verify` | 查询 IP 归属 / 校验归属库是否可信 |
| `infra-check` | 解析 Unbound infra 快照，输出区域、权威 IP、rto |
| `chnroute` | 由 APNIC 委派记录生成 `direct4` |
| `cn-authority` | 由 infra 记录生成国内权威集合与 ECS 白名单 |
| `shared-anycast` | 生成共享 anycast 权威清单 |
| `ecs-zone` | 生成 ECS 缓存分片表 |
| `polluted-evidence` | 聚合污染 IP 观测证据 |
| `cdn-rules` | CDN 直连规则集：`build` / `verify` / `lookup` |
| `direct4-audit` | 多个归属库交叉验证 `direct4` |
| `ecs-orphans` / `ecs-audit` / `ecs-forward` | ECS 白名单与转发链路的审计 |
| `doh-probe` / `helper-probe` | 入口与助手的探针 |

## 服务进程

由 systemd 启动，一般不需要手工运行：

| 命令 | 作用 |
|---|---|
| `panel` | 管理面板（前端已内嵌） |
| `helper` | 以 root 运行的受限管理助手，监听 unix socket |
| `collect consume-stdin` | 消费 mosproxy 查询日志 |
| `trim-logs` | 原地截断过大的运行日志 |
| `version` | 显示版本 |
