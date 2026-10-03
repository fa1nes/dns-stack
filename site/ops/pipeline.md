# 分流数据流水线

出口分流和 ECS 需要的所有数据，都由同一条 Go 流水线 `dns-stack routing-data` 生成。它由 `dns-stack-routing-data.timer` 每 15 分钟触发一次（开机 3 分钟后首次运行），每个步骤按自己的周期决定这一轮要不要跑。

## 步骤

| 步骤 | 周期 | 依赖 | 产物（`/var/lib/dns-stack/` 下） |
|---|---|---|---|
| `geoip` 归属库更新 | 24 小时 | — | `geoip/` 下的 GeoLite2-ASN、GeoLite2-City、纯真 qqwry、DB-IP |
| `chnroute` 大陆网段重建（关键） | 24 小时 | — | `chnroute/direct4.txt`，并装入 nft 集合 `direct4` |
| `geo-cross` 多源归属交叉校验 | 24 小时 | chnroute | `chnroute/geo-disputed.txt`、`geo-promoted.txt` |
| `anycast` 共享 anycast 识别 | 1 小时 | chnroute | `chnroute/shared-anycast.txt` |
| `cdn-rules` CDN 直连规则集 | 24 小时 | — | `cdn-direct.txt` |
| `cn-authority` 国内权威与 ECS 白名单 | 15 分钟 | chnroute、geo-cross、anycast | `chnroute/cn-authority.txt`（并装入 nft 集合 `cn_authority`）、Unbound 的 ECS 白名单配置 |
| `ecs-zone` ECS 缓存分片表 | 24 小时 | chnroute、geo-cross | `ecs-ip-zone.txt` |

## 失败时怎么办

- 依赖的步骤这一轮失败了，下游步骤标记为「阻断」，**不拿旧输入硬算**。
- 关键步骤（`chnroute`）失败会中止整轮。
- 每份产物都有骤降护栏：APNIC 记录少于 5000 条、大陆地址少于 2 亿个时拒绝更新 `direct4`；国内权威集合和 ECS 白名单缩水到不足原来 40% 时拒绝下发。
- 判据缺席（例如归属库下载失败）时保留上一版产物，不写空结果冒充健康。
- ECS 白名单写入后先跑 `unbound-checkconf`，不通过就回滚；通过才热重载（缓存保留）。

## 数据源

全部是一手或可追溯的外部数据，**不用本系统自己观测生成的结果当判据**——那会让判定结果变成判定输入，自我强化。

| 数据 | 来源 |
|---|---|
| 大陆 IP 段 | APNIC 官方委派记录 |
| 国内归属 | 纯真 qqwry（只在 CN/HK/TW/MO 范围内可信） |
| 境外 ASN / 地理 | MaxMind GeoLite2-ASN / City |
| 交叉验证 | DB-IP |
| CDN 节点段 | 各家官方前缀源与 ASN 通告，由本仓库的 Action 每日合成 |

### 归属判定：按字段取长补短

不做「整条记录二选一」——信息量不等于准确度。

| 字段 | 取法 |
|---|---|
| 地区 | qqwry 优先（国内省市准确），两边都空时退到城市（香港这类「城市即地区」） |
| 运营商 | 云厂商 AS 优先（注册事实），其次可信范围内的 qqwry，最后 MaxMind |
| 国家 | MaxMind 优先（qqwry 对境外只有粗略标注） |

qqwry 只在 CN / HK / TW / MO 范围内可信，这一条要贯彻到**全部**地理字段：只挡运营商不挡国家，就会输出「地名对、国家错」的结果。

### 评估过但没采用的源

- **GeoCN**：大陆精度很好，但数据来自扫描公开接口再清洗、随缘更新、没有许可证，属于推测性二手数据。可以参照，不进判定链。
- **DB-IP City Lite**：更新活跃、许可证明确，但体积大且没有运营商字段，而运营商正是判断 CDN 命中的关键。只用它做交叉验证。

### 归属库镜像

归属库由本仓库的 `geoip` Action 每天镜像到 `geoip-latest` Release，带体积门槛和已知地址抽查（只看文件大小不够，格式变了文件照样够大）。生产机优先从这个镜像拉取，避免直连境外源超时。

## 手动运行

```bash
sudo dns-stack routing-refresh                       # 忽略周期，全部重跑
sudo dns-stack routing-data --only chnroute --force  # 只重跑某几步
sudo dns-stack routing-data --dry-run                # 只列出这一轮会跑哪些步骤
sudo dns-stack routing-data --preview                # 全部算一遍，线上文件一个都不写：不动 nft、不改 ECS 配置、不重载 Unbound
```

同一时间只会有一轮在跑（`/run/lock/dns-stack-routing-data.lock`）。定时器撞上正在进行的一轮会直接跳过；手动 `--force` 撞上会报错，等那一轮结束再试。

分片表写出后会让 mosproxy 热加载一次；mosproxy 拒绝新表时，自动换回这次覆盖掉的内容。

面板「设置 → 维护 → 分流数据」的「重建」按钮效果相同。

## 资源上限

流水线是整台机器上最吃内存的任务。它的 systemd 单元设了 `MemoryHigh=384M`、`MemoryMax=512M`：失控时只杀掉它自己，不连累解析。CI 的规模闸门会用真实数据量跑一遍关键步骤，峰值超过上限就不允许发布——2026-09-07 曾经因为在生产机上跑没测过规模的代码，把整台机器的递归搞宕。
