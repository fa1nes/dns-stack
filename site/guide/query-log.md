# 查询日志与统计

## 数据从哪来

mosproxy 由采集器包着运行：它的 JSON 查询日志经内存管道交给采集器，采集器只取需要的字段写进 SQLite（`/var/lib/dns-stack/collector.db`）。

- **不记录客户端 IP**：日志里根本不读这个字段，数据库也没有这一列。
- **ECS 子网会被截短**：IPv4 截到 /24、IPv6 截到 /48 再落盘。
- **保留 7 天**，最多 200 万条，每小时清理一次。
- 采集出错时继续读空管道，绝不拖住 DNS。

每条记录包含：时间、域名、记录类型、rcode、递归类型、出口路径、来源子网、ECS 分片、应答来源、入口、是否预取、耗时。

## 递归类型

| 值 | 含义 |
|---|---|
| `cache` | mosproxy 缓存命中 |
| `recursive` | 本机 Unbound 完整递归 |
| `forward` | 转给香港 Unbound |
| `blocked` | 命中域名黑名单 |
| `refused` | 被入口限流拒绝（访问控制在内核里丢包，那些查询到不了 mosproxy，不会出现在日志里） |

出口路径（`--exit`）：`cache`、`recursive`（本机递归，逐跳分流，没有单一出口）、`hongkong`（香港 Unbound）、`failed`。

## 命令行

```bash
sudo dns-stack query-log                          # 近 24 小时最新 200 条
sudo dns-stack query-log --since 1h --domain qq   # 域名模糊匹配
sudo dns-stack query-log --kind recursive --limit 50
sudo dns-stack query-log --subnet 219.141         # 按来源子网（ECS）筛选
sudo dns-stack query-log --exit hongkong
sudo dns-stack query-log --breakdown              # 只看各递归类型的数量与占比
sudo dns-stack query-log --csv /tmp/q.csv         # 导出 CSV（最多 10 万条，带 BOM，Excel 可直接打开）
sudo dns-stack query-log --json
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--since` | `24h` | 回看时长 |
| `--kind` | — | `blocked` / `refused` / `cache` / `forward` / `recursive` |
| `--domain` | — | 域名模糊匹配 |
| `--subnet` | — | 来源子网模糊匹配 |
| `--exit` | — | `recursive` / `hongkong` / `cache` / `failed` |
| `--limit` | 200 | 最多返回多少条（上限 10 万） |
| `--breakdown` | — | 只输出构成 |
| `--csv FILE` | — | 导出到文件 |
| `--json` | — | JSON 输出 |

表格输出会给来源子网标上归属地，给答案标上 CDN 归属。

## 面板

面板的「查询」页有两个标签：

- **请求**：最新的查询流，进入页面就自动连上实时推送，每条都带真实耗时；可以按类型、来源、结果、时间筛选，删除单条记录。
- **域名**：请求最多、最近新增、失败最多、解析最慢的域名。点开一个域名能看到它的解析详情，并能直接把它加进国内解析或香港解析名单。

「概览」页是近 1 小时请求、缓存命中、响应速度、24 小时解析失败率，请求趋势，以及各上游的转发、出错次数与延迟（平均值和按直方图插值的 p95）。

### 统计起点

所有「近 24 小时」的数字共用同一个起点。改了架构或排查完一次故障，想让数字从零开始，可以「重设统计起点」（「设置 → 维护 → 清理 → 统计起点」，或 `dns-stack set-arch-epoch`）。之前的记录不会被删除；要删掉它们，再执行「清理旧架构数据」（`dns-stack purge-legacy`）。

## 导出

面板的导出接口可以把查询、域名、分流数据集导成 JSON 或 CSV。导出是流式的，不会把全部数据一次读进内存。
