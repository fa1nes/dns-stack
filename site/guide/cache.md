# 缓存

查询会先后经过两层缓存：mosproxy 的入口缓存和 Unbound 的递归缓存。九成的查询在第一层就返回了。

## mosproxy：入口缓存

| 设置 | 值 | 含义 |
|---|---|---|
| `mem_size` | 64MB | 内存缓存上限 |
| `maximum_ttl` | 3600 | 缓存条目的 TTL 上限（秒） |
| `prefetch_threshold` | 0.25 | 剩余 TTL 不到 1/4 时，命中会触发后台刷新 |
| `optimistic_ttl` | 默认 7 天，可在面板调整 | 过期之后还允许先回旧答案、后台刷新的时长 |

**乐观缓存**：过期的条目不会让设备等递归，而是先把旧答案回给设备，同时在后台刷新。热门域名因此几乎从不让设备等待。

带 ECS 的答案按「省份 + 运营商」分片缓存，见 [ECS 就近调度](/guide/ecs#按片缓存)。

## Unbound：递归缓存

| 设置 | 值 | 含义 |
|---|---|---|
| `msg-cache-size` / `rrset-cache-size` | 128MB / 256MB | 报文与记录缓存 |
| `cache-min-ttl` | 300，可在面板调整（0–300） | 强制最小 TTL |
| `cache-max-ttl` | 86400 | TTL 上限 |
| `prefetch` | yes | 热门记录在过期前预取 |
| `serve-expired` | yes | 递归失败或太慢时回过期答案 |
| `serve-expired-ttl` | 默认 7 天，可在面板调整 | 过期答案最多还能用多久 |
| `serve-expired-client-timeout` | 100 ms | 递归 100 ms 内没回来就先回过期答案 |
| `aggressive-nsec` | yes | 用 DNSSEC 的 NSEC 记录直接合成「不存在」 |

### 为什么最小 TTL 的上限压得这么低

强制最小 TTL 会一并抬高 CDN 那些几十秒的短 TTL，而 CDN 正是靠短 TTL 做故障转移和就近调度的。抬得越高，命中率越高，调度精度越差。所以面板只允许 0–300 秒。

## 在面板里调整

面板「设置 → 数据与证书 → 缓存策略」里有两个下拉框：

- **乐观缓存**：同时修改 Unbound 的 `serve-expired-ttl`（立即生效）和 mosproxy 的 `optimistic_ttl`（重启 mosproxy 后生效），两者保持成对。上限 30 天。
- **最小 TTL**：修改 Unbound 的 `cache-min-ttl`，立即生效。

两者都会同步写回配置文件，重启后不丢。重新运行 `install.sh` 时，安装脚本会保留这几项调过的值，不会被模板默认值覆盖。

自检的「Unbound 运行配置与模板一致」会跳过这两项：它们归面板管。

## 清缓存

同一张卡片里的「清理缓存」可以清掉某个域名及其子域，留空则全部清空：

```bash
unbound-control flush_zone example.com   # 等价的命令行
```

注意两点：

- 它只清 **Unbound** 的缓存。mosproxy 的条目最多再保留 `maximum_ttl`（1 小时），过期后的第一次刷新就会拿到新答案。要立刻清掉 mosproxy 的缓存只能重启它。
- 被清掉的名字接下来都要重新走完整递归，短时间内延迟会明显升高。全部清空要慎用。
