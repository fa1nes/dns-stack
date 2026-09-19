# DNS Stack 接手手册

本文件只记录可复用的架构、判据、边界和验证入口。单次会话日志、临时数字和部署流水不要写在这里；故障背景见 [README.md](README.md)，历史档在 `.memory-archive/`。

## 1. 不可违反的目标

1. 绝不能把境外域名误纳入国内直连或国内权威集合。
2. ECS 只发给三类权威：有明确国内业务证据的、`internal/cdn` 列出的已知 geo-steering CDN、
   以及 `cdn-direct.txt` 证明**在大陆有节点段**的 CDN（2026-09-14 新增，详见 §3.3）；
   除这三类外不能把境外权威纳入白名单。2026-09-13 主人明确定调：CDN 就近优先于这条的严格版本，
   因为拿不到 ECS 的 Akamai/Apple 只能按隧道出口调度，把国内用户导去香港。
   **这三类的境外权威一律只进 ECS 白名单、永不进直连集合**（`internal/ruleset`），
   这条不依赖 shared-anycast 清单是否新鲜。
3. 境外权威位置本身不是 GFW 证据；自动 `foreign-dns` 规则只能来自明确的 `cn_view_polluted` 观测。
4. 非全局地址、无最终 A/AAAA、公共后缀、保留域、格式错误域名和 IP 字面量都不是地理或递归判定证据。
5. 不使用本系统历史 DNS 结果作为递归输入；IP/CIDR 观测只能用于审计或客户端裸 IP 规则。
6. 离线归属库（GeoIP）可以参与权威落点判定，但**只能经 §3.5 的多源交叉清单**，不能由单个库
   直接决定：否决要 ≥2 源一致，晋级要全部源一致。**运行时不查 GeoIP 做递归决策**——判据是
   每日预计算好的静态清单，解析关键路径上一次归属查询都没有。

生产配置、服务、数据库、WireGuard、防火墙、端口、Git commit/push 和 GitHub 发布，除非主人明确确认，否则只做只读检查。

## 2. 当前架构

```
客户端 -> mosproxy -> CN Unbound 完整递归
                         |
                         +-- 权威 IP 在 direct4/cn_authority -> 直连
                         +-- 其它权威 IP -> nft mark 0x1d5 -> WireGuard -> HK
```

| 角色 | 地址 | 职责 |
|---|---|---|
| CN | `10.100.0.2` | mosproxy、Unbound、collector、面板、helper、nft/WireGuard |
| HK | `10.100.0.3` | 境外递归出口 + 规则构建（候选拉取/分类/复检/发布）；Alpine，无 systemd，调度走 crond |
| Global/SG | `10.100.0.1` | **已退场**（2026-09-06），职责移交 HK |

**运行时是单个 Go 静态二进制**（`/opt/dns-stack/bin/dns-stack-go`）。CN 的面板、helper、
采集器和 HK 的分类器都是它的子命令；两端都没有任何 Python。二进制由 CI 构建后下发，
**不在生产机编译**（`install.sh` 从 `binaries-latest` Release 下载并核对 sha256）。

2026-09-06 起 CN 不再维护本地 nft 过滤防火墙（`inet dns_stack_filter` 已删，边界防护交给云安全组）；`inet dns_route` 分流表仍是产品核心。

递归出口只由目标 IP 路由决定，不加载 `cn.txt`/`gfw.txt` 做 DNS 方向判断。`@direct4` 是大陆 IP 集合；`@cn_authority` 是服务国内业务区域的权威地址集合；ECS 配置是 `unbound.conf.d/dns-stack-ecs.conf`。

关键 nft 约束：

- `output` 必须是 `type route hook output`，并且只正向匹配 Unbound uid。
- 目标不在 `@direct4`、`@cn_authority`、`@tunnel_endpoints` 时才设置 `0x1d5`。
- `ip rule` 必须同时有 `from <tunnel-ip> lookup 100`、`fwmark lookup 100` 和 `fwmark prohibit`。
- 经 `wg0` 的标记流量必须做 masquerade；隧道故障不得回落直连拿污染答案。
- 当前 IPv6 方案是模板 `do-ip6: no`；没有完整 `direct6`/IPv6 anycast 方案前，不要重新打开 IPv6 递归。

## 3. 判定规则

### 3.1 域名和权威

实现：`internal/domain/`（形态判据与 PSL）、`internal/authority/`（权威位置）、
`internal/classify/`（双视角判据与规则构建）、`internal/ruleset/` + `internal/cnauth/`（生产侧集合）。

判定顺序：

1. 规范化小写、去尾点；拒绝 malformed、保留名、公共后缀、单标签和 IP 字面量。
2. 域名必须有全局可路由的最终 A/AAAA；只有 NS/SOA、超时、SERVFAIL 或 hidden master 不得晋级。
3. 权威按实际递归链逐级查找；NS 缺失时可回退 SOA MNAME；不得拿 TLD 权威替代注册域权威。
4. 一个区域任一全局权威 IP 命中 `direct4`，区域可进入 `cn_authority`；全境外权威只能是 `unknown`，不能自动变 GFW。
5. 区域全部权威 `rto >= 120000ms` 时排除；缺失 rto 必须 fail-open 并告警。
6. 同一服务的冗余子域可以按实际最终地址折叠；折叠目标必须是**同一批判定集合里的成员**，否则等于凭子域证据给父域下全部兄弟子域发规则。
7. 客户端流量规则（`cn.txt`）额外过三道，缺一道都会让境外域名进入国内列表：
   - **共享多租户 provider 根域不得成为整体规则**（`classify.IsSharedTenancyRoot`）。规则是域后缀匹配，一条 `cloudflare.net`/`aliyuncs.com` 会把该 provider 上全部租户一起钉成直连。判据不看本轮观测到几台权威——观测易失，一次超时就会让根域在放行与拦下之间翻，而翻错的那一侧不安全。
   - **国内视角落点复核**（`Engine.confirmCNLanding`）。`direct4` 来自 APNIC delegated 记录，回答的是"这段注册在哪个国家"而不是"这台服务器在哪"：`ns5.yahoo.com`(202.165.97.53) 落在 CN 段，整个 `yimg.com` 因此被判成国内。按比例收紧不可行（`qq.com` 也只有 1/4 台权威在大陆）。只在**明确**拿到国内视角答案且其中一个大陆地址都没有时剔除；查不到答案一律保留。这道判据只在 HK 侧；CN 侧同一类误判由 §3.5 的多源交叉挡。
   - **cn 与 foreign 冲突时保留 foreign**（`dropShadowedByForeign`）。两个方向代价不对称：被墙域名走直连会彻底不可用，国内域名留在代理里只是慢一点。没有这道判据时结果由写入顺序决定，而覆盖是静默的——发布侧的父子覆盖护栏看不到交集。

**CDN 后缀表是一张**（`internal/classify/cdn.go`）。此前 Python 有两份——`GEO_STEERING_SUFFIXES`(22)
与 `NO_AUTO_MERGE`(80)，前者完全是后者子集却分在两个模块，加新 CDN 时极易只改一边。
Go 侧由 `buildProviderTable()` 构造出包含关系，`geoSteeringRoots` 必然同时带多租户标志。
匹配按**标签边界**、从右往左剥标签查 map（O(标签数)），`notfastly.net` 不会误命中 `fastly.net`。

人工例外：`manual-gfw.txt`（国内权威合法空应答）、`manual-cn-zones.txt`（权威全境外但服务国内业务）。

⚠️ 人工指定的 CDN 提供商区域（`akamaiedge.net`/`edgekey.net`/`akadns.net`，为 Apple 中国链路而加）会让**整个 Akamai 权威舰队**按后缀匹配进直连与 ECS，并经累积机制长期留存。给 Akamai 发 ECS 是 Apple 拿到中国节点的有意设计，但同地址多租户意味着其它 Akamai 租户的查询也会带上中国子网。改动这份清单前先想清楚这个代价。

### 3.2 GFW 证据

`classify.Decide()` 只在以下条件同时成立时产生 `gfw`：

- CN 视角有全局最终地址，且命中已确认污染 CIDR；
- HK 对照健康并返回可用地址；
- 对照视角没有同一污染结果；
- 记录原因必须是 `cn_view_polluted`。

境外落点、视角冲突、单侧超时、国内业务地理位置和权威所在地都不能单独产生 GFW 规则。污染地址本身也不能直接作为客户端 drop-list：真实业务地址要进入 audit-only。

**两视角答案不同但共享 geo-steering CNAME 链时判 `cn`**（`shared_geodns_chain`）。那是同一条
GeoDNS 链按位置给出的不同节点，不是污染。表里现在**同时包含中国 CDN**（alicdn/kunlun/
qcloud/cdnhwc/ourdvsss/wscdns 等）——此前只有境外 CDN，中国 CDN 会一路落到
`views_conflict_foreign_preferred`。

### 3.3 ECS 精度

配置约束：`mosproxy ecs.enabled/forward` 开启；Unbound `client-subnet-always-forward: no`，只向白名单权威发送 ECS。

白名单由三层组成，**每一层都要先减去 §3.5 的争议网段**：

1. 全局 `direct4` 网段：解决冷启动，发给大陆 IP 是安全的。
2. 当前 `cn_authority` 中实际观测到的全局权威地址：只允许精确 `/32`，不复用路由 `/24` 聚合。
3. 共享 anycast 的精确安全例外和短期累积：只能保留全局 IPv4 `/32`。

**geo-steering 区域的判定有两个来源，规则集是可核验的那个**（2026-09-14 接上）：

| 来源 | 实现 | 性质 |
|---|---|---|
| `internal/cdn` 静态后缀表 | `cdn.IsGeoSteered(zone)` | 人工维护，加新 CDN 永远滞后 |
| `cdn-direct.txt` 的大陆段证据 | `ruleset.Config.MainlandCDN` | Action 每日重建，是网络事实 |

规则集里**有大陆前缀段**的 provider，其根域全部进 `MainlandCDN`；命中的区域即便静态表
没收录也按 geo-steering 处理（境外权威进 ECS 白名单、按 `/24` 聚合、**一律不进直连集合**）。
这条只做加法：规则集读不到或没有任何大陆段时整体弃权，静态表照常生效（`cnauth.loadMainlandCDN`）。
靠规则集纳入的区域单独记账（`Result.SteeredByRuleset`），便于区分证据来源。

⚠️ 判据链两头都要接：CN 侧 `pipeline/steps.go` 传 `CDNRulesPath`，
CLI 侧 `cn-authority --cdn-rules` 默认 `<state>/cdn-direct.txt`。
少传一处，判据就退回只认静态表，而**不会有任何报错**。

必须过滤、去重、去重叠、按区间覆盖检查；数据骤降、空快照、状态文件不可读都要保留旧结果并告警。累积保留（TTL 内、本轮 infra cache 未覆盖的权威 /32）是设计内的短期留存，`dns-stack ecs-orphans` 会把它们单列；**真孤儿**按境外归属统计，超过阈值就是实际泄露。状态文件不可读时审计 fail-closed，全部按真孤儿计。

`scope > 0` 才表示权威按位置调度；没有 ECS 回显或 `scope=0` 必须单独显示。

**「无回显」此前是不可判的，2026-09-19 起可判**（`cdn-hit --fresh` / 面板「清缓存重查」）。
不可判的根因不是协议而是缓存：`scope=0` 的答案被 unbound 缓存成全局条目，
之后任何子网都命中它且不回显。`--fresh` 在探测前把域名**连同 CNAME 链**逐个
`flush_zone` 再查——⚠️ 只清查询名不够，`www.x.com → CNAME → y.cdn.net` 的
链末端 A 记录仍在缓存里，判据照样是假的；`cdnhit.flushTargets` 先做一次
priming 查询取回 `Answer.Chain` 再逐个清。清干净后仍无回显只剩一个解释：
**子网没送到那台权威**（`VerdictNotDelivered`），下一步查 ECS 白名单。
代价是这批热门域名下一次解析要走完整递归，所以面板侧 10 分钟只允许一次。

`ip_zone` 只改变缓存 key、不改变发给权威的真实客户端 `/24`——**这句话只在 mosproxy 补丁 0016 之后成立**。上游 `serverEntryHandler` 把「分片表没给这个地址打标」当成「这是本地客户端」，直接把 `ECS2Upstream` 清成零值，即整条查询不发 ECS。分片表由归属库生成、天然覆盖不全，2026-09-06 实测 `direct4` 里 **69.85% 的大陆 IPv4 地址空间没有标记**。补丁把判据改成只对非全局地址抑制。判据用 `dns-stack ecs-forward`：分片表内外各取两个 `/24`，表内有差异而表外没有就是这个缺陷的指纹。

### 3.4 数据源

| 数据 | 允许来源 | 用途 |
|---|---|---|
| `direct4` | APNIC 官方 delegated 记录 | 递归出口路由、ECS 冷启动 |
| 国内归属 | qqwry/IPDB | 展示、ECS 缓存分片、多源交叉；不在解析关键路径查询 |
| 境外归属 | MaxMind / DB-IP MMDB | 展示、共享 anycast 离线审计、多源交叉 |
| PSL | 当前有效的 ICANN Public Suffix List | 注册域/公共后缀判定 |

归属库由 `.github/workflows/geoip.yml` 每天镜像到本仓库的 `geoip-latest` 滚动 Release，生产端
由 `dns-stack routing-data --only geoip` 拉取。**只有带国家码的库才进得了交叉判据**：qqwry、GeoLite2-City、
dbip-city 三个；GeoLite2-ASN 与 dbip-asn 一个国家码都没有，拿它们交叉等于放一个
永不投票的源。拉取端与 CI 都用同一个 `dns-stack geoip-verify` 做库类型核对与国家码抽查，
并在末尾报出**可交叉源数量**——只数"下载成功几个"回答不了"交叉验证还跑不跑得起来"。

### 3.5 多归属库交叉

`dns-stack direct4-audit`（`dns-stack-geo-cross.timer`，每日）拿多个独立归属库交叉验证 `direct4`，
产出两份清单，`internal/geoaudit` 是实现：

| 清单 | 含义 | 门槛 | 用途 |
|---|---|---|---|
| `chnroute/geo-disputed.txt` | 在 direct4 内，但多个库一致判为境外 | **≥2 源一致** | 不发 ECS、不作晋级证据 |
| `chnroute/geo-promoted.txt` | 不在 direct4 内，但**全部**可用库一致判为大陆 | 全部源 | 可作晋级证据 |

两个方向门槛不同是有意的：否决只会让判定更保守，晋级会让地址**进入**国内集合，风险不对称。

处置口径：**争议地址挡 ECS + 不作晋级证据，但仍留在直连路由集**。踢出直连只会让它走隧道变慢，
收益不抵护栏被频繁触发的代价；而把中国客户端子网发给一台多源判定在境外的权威，正是 §1.2 要挡的事。
两份清单同时命中同一地址时，**争议方向赢**。

四条 fail 语义，每条都刻意选过方向：

- **可用源 < 2 → 整体 fail-open**（`MinSources`）：既不否决也不晋级。护栏自己缺席时不能伪装成被检对象的失败。
- **争议量 > direct4 的 5% / 晋级量 > 4M 地址 → 本轮整体不生效**，且**不写清单文件**。
- **清单读不到 → fail-open**（不否决）。
- **清单 kind 与期望不符 → fail-closed**：把 promoted 当 disputed 用会把真正的大陆权威整批踢出 ECS。文件头自带 `# kind`。

⚠️ **争议网段要从三个地方扣，少一个判据就形同虚设**：

1. **direct4 冷启动段**：不扣的话那条 /24 会把刚挡掉的 /32 原样覆盖回来（`ruleset.directECSPrefixes`）。
2. **本轮 infra 观测到的权威 /32**（`ruleset.Config.isDisputed`）。
3. **累积保留**：累积是从**上一版 ECS 配置**里捞 /32，完全绕开本轮的所有判据；
   它 72 小时后会自然过期消失，所以**不会有人把它归因到这次改动**（`cnauth.applyAccumulation` 的 `accumDisputed`）。

⚠️ **cnauth 曾为了打日志把第 1 层的减法重算一遍**，与 `ruleset` 里真正生效的那份是两份实现。
改错一份，日志就会谎报做了什么，而结果照常。已收敛：`ruleset.Result` 直接报出
`DirectECSPrefixes`/`DirectECSCutAddrs`，cnauth 只负责打印。

三层扣除由 `internal/cnauth` 的
`TestECSWhitelistHasZeroIntersectionWithDisputedRanges` 钉死——它不看代码长什么样，直接拿最终
ECS 白名单与争议清单求交。**做过阴性对照**：拆掉第 1 层或第 3 层，测试当场变红。
生产侧同款判据是 `dns-stack ipset-check --overlap`（由 `dns-stack selfcheck` 串起）。

ECS 分片表（`internal/ecszone`）也接了争议清单：qqwry 说是大陆、但多源判为境外的段**不打标**。
**注意能力边界**：dbip-city 没有省份与 ISP 字段，所以分片表的「省+运营商」归一
**无法**做多源交叉，能交叉的只有「这段到底在不在中国」。

`collapse` 后不能用网段首地址代表整段；护栏按覆盖地址数量或区间覆盖，不按条目数量猜数据健康。`direct4`、CIDR 元数据和发布包写入要原子化，后续写入失败必须恢复前一版。

## 4. 代码地图

运行时是**一个 Go 二进制**，下面是它的子命令与对应实现包。

| 子命令 | 包 | 作用 |
|---|---|---|
| `classify <sub>` | `internal/classify` | HK 规则构建全流程：候选拉取、双视角分类、权威位置分类、规则包构建与 GitHub 发布 |
| `panel` | `internal/panel` | 面板 HTTP 服务；前端静态资源由 `web/embed.go` 编进同一文件 |
| `helper` | `internal/helper` | 受限 root 管理助手：unix socket + 白名单操作 + 日志脱敏 |
| `collect <sub>` | `internal/collect` | mosproxy 查询日志消费、脱敏、聚合、候选导出 |
| `cn-authority` | `internal/cnauth` | 由 (区域,权威,rto) 生成直连路由集与 ECS 白名单，含累积保留 |
| `chnroute` | `internal/chnroute` | APNIC 委派记录 → direct4，含 qqwry 补充、港澳台探针护栏、反向排除与比例上限 |
| `ecs-zone` | `internal/ecszone` | 按省+运营商生成 mosproxy 的 ECS 缓存分片表 |
| `direct4-audit` | `internal/geoaudit` | 多归属库交叉，产出争议/晋级清单 |
| `ecs-orphans` | `internal/cnauth` | ECS 白名单孤儿审计（与生产者共用 `loadPrevECS`/`loadAccumState`） |
| `ecs-audit` | `cmd/dns-stack` | ECS 全链路 A/B 审计：国内漏发 / 境外误发 |
| `ecs-forward` | `cmd/dns-stack` | 直查 mosproxy DoT，验证客户端子网是否真的转发（自带 DoT 客户端） |
| `cdn-hit` | `internal/cdnhit` | 以真实中国 /24 解析大厂域名，判定是否真拿到大陆 CDN 节点；面板 `/api/cdn-hit` 与 selfcheck 共用同一实现 |
| `polluted-evidence` | `internal/polluted` | 污染 IP 观测的 TTL/门槛聚合与 CIDR 汇总 |
| `rules <sub>` | `internal/rulesync` | 规则包清洗与校验：域名形态、CIDR 汇总、不重叠、父子覆盖 |
| `shared-anycast` | `internal/anycast` | 共享 anycast 权威清单 |
| `migration-export/-restore` | `internal/panel` | 迁移包导出与恢复，**与面板的导出共用 `migrationEntries` 这一份清单** |
| `geoip-verify` | `internal/geoip` | 归属库类型核对与国家码/ASN 抽查 |
| `panel-auth <sub>` | `internal/helper` | 设置面板密码 / 关闭二次认证 |
| `doh-probe` / `helper-probe` | `cmd/dns-stack` | DoH 入口探测 / 日志脱敏抽查（供 preflight 与回归复用） |

基础包：

| 包 | 作用 |
|---|---|
| `internal/dnswire` | 自建 DNS 线格式编解码（A/AAAA/NS/CNAME/SOA/SVCB/HTTPS + EDNS0 + ECS），零第三方依赖 |
| `internal/resolve` | UDP/TCP 查询客户端与 CNAME 链展开 |
| `internal/authority` | 权威位置判定、落点观测、子域折叠 |
| `internal/domain` | 域名形态判据、PSL |
| `internal/ipset` | IPv4 CIDR 集合、区间覆盖、全局地址判据 |
| `internal/cidrutil` | v4/v6 通用的 CIDR 区间运算（`math/big`）：collapse、二分集合、合并扫描求首个重叠 |
| `internal/geoip` | MaxMind/DB-IP MMDB 与 qqwry IPDB 只读查询 |
| `internal/infra` | Unbound infra 快照解析 |
| `internal/ruleset` | 由 infra 快照生成直连路由集与 ECS 白名单 |
| `internal/resolvetest` | 只在测试里用的最小权威服务器，单独成包以免脚手架被链进生产二进制 |

| `internal/cdn` | CDN 后缀表与共享 DNS ASN 表的**唯一真相源**（geo-steering / 多租户两个标志） |
| `internal/pipeline` | 分流数据流水线：按依赖顺序串起 6 个步骤，各步自带周期与时间戳 |
| `internal/selfcheck` | 运行时回归判据（只观察在跑的系统，不 grep 源码） |
| `internal/logtrim` | 原地收缩过大的运行日志，保留 inode 与文件权限；HK 定时任务直接调用 Go 子命令 |

**shell 归零（2026-09-14 复核）**：整个仓库只剩 `install.sh` 与 `install-hk.sh` 两个安装脚本，
外加 `mosproxy.service` 里那一行必须保留 `-o pipefail` 的管道。曾经的 `scripts/`、`migration/`
两个目录连同其中每一个 `.sh` 都已并入 Go 子命令——
`collect-polluted-ip.sh`→`collect-polluted`、`sync-rules.sh`→`sync-rules`、
`setup-recursive-routing.sh`→`routing-setup`、`backup.sh`→`backup`、`doh-path.sh`→`doh-path`、
`preflight.sh`→`selfcheck`、`migration/wg-peer.sh`→`dns-stack wg-peer`、
`update-*.sh`→`routing-data|maintenance`、`regression-check.sh`→`selfcheck`。
**卸载故意留在 shell**：Go 二进制坏掉时最需要它。
HK 的日志收缩也已从安装脚本生成的 `trim-logs.sh` 收回 Go：`dns-stack trim-logs` 原地保留每份 `.log` 的末尾内容，安装脚本只负责写入 cron。仓库仍只有两个安装脚本。
⚠️ 在本文件里看到任何 `scripts/xxx.sh` 的引用都是历史章节的原文，不要照着去找文件。

⚠️ **把 shell 改写成 Go 时要逐条清点 curl 的保护参数**。`update-geoip.sh` 的
`--speed-limit 8192 --speed-time 20` 在第一版 Go 端口里丢了，只剩总超时；CN 直连 GitHub Release
正好是"连得上但不淌数据"，于是流水线整步挂死，`cn-authority` 的 15 分钟刷新停摆。
现在 `internal/pipeline/fetch.go` 有速度下限 + 步骤总预算，且 github.com 直接走隧道。

Go 模块：`go.mod` 声明 Go 1.26，**除 SQLite 驱动外不引入第三方依赖**。目标包括 Windows、
Linux amd64、Linux arm64。**Linux 产物是完全静态的 ELF**（CI 用 `file` + `readelf -l` 断言
没有 PT_INTERP），所以 HK 是 Alpine/musl 不构成任何障碍。

RDATA 里的域名可以用压缩指针指回报文头部，解析它必须带 `RR.RDataAt`（绝对偏移）。曾用"指针身份反查偏移"，报文被拷贝一次就永远找不到，而表现只是"目标名取不到"。

## 5. 验证入口

### 本机代码级验证

```bash
go build ./... && go vet ./... && go test ./... && gofmt -l cmd internal web
bash -n install.sh && sh -n install-hk.sh
node --check web/assets/panel.js && node --check web/mock-api.js
```

**每个 `internal/` 包都必须有测试**（`resolvetest` 是脚手架除外）。这条由 regression 断言守着——
Python 参照实现已于 2026-09-10 全部删除，测试是唯一的正确性证据，一个包没有测试就等于没有判据。

写测试的三条纪律（都是踩过的）：

- **必须做阴性对照**。把判据改错，测试要当场变红。"全绿"本身不是证据——
  2026-09-10 拆掉 cnauth 第 1 层扣除时测试没红，查下去才发现拆的是只用于打日志的死代码。
- **不要只比聚合计数**。两处互相抵消的错误在计数上完全一致。
- **先自证判据本身能跑**。两侧都是 0 条时也"一致"，那是最坏的一种绿。

### CN/Debian 实机验证

```bash
dns-stack health
dns-stack routing-status
dns-stack ecs-orphans --max-foreign 9
dns-stack ecs-audit --quick
dns-stack ecs-forward
dns-stack direct4-audit --dry-run
unbound-checkconf /etc/unbound/unbound.conf
```

ECS 就近测试使用真实中国 `/24`，不能用任意境外示例网段推断 CDN 是否正确。

长任务在 CN 上要用 **transient service** 而不是 `&` 后台或 `--scope`：
`systemd-run --unit=X --collect --property=MemoryMax=768M --property=CPUQuota=70% --setenv=HOME=/root --working-directory=DIR /usr/bin/bash 脚本`。
`&` 会让 SSH 通道挂住不返回；`--scope` 会随 SSH 断开一起死。

远程工具：`.deploy/remote.py`（gitignore，是主人本机的运维工具，不属于产品）。
PowerShell 传 shell 变量时使用 `runb64`；禁止读取、打印 `.deploy/creds.json`。

### 前端开发

```bash
go run ./web/devserver --root ./web    # 注入 mock-api.js 与 layout-scan.js，不需要后端
```

`index.html` 对 `mock-api.js` 与 `devserver/layout-scan.js` **必须零引用**，
两者都只能由开发服务器注入。

⚠️ **改动前端后必须跑跨视口扫描，只看一两个视口必然漏**。开发服务器注入了
`__layoutSweep()`，它遍历全部页面与标签页，报出页面横向溢出、单元格内容溢出、
同一筛选行里的字号不一致、提示块溢出：

```js
await window.__layoutSweep()   // 在每个视口各跑一次
```

**必须覆盖的视口**：320 / 393 / 641 / 768 / 861 / 1024 / 1920。
641 与 861 是断点边界，最容易出问题；320 是最窄真实设备。
2026-09-19 起 **7 个视口全部零 issue**，任何新增的非零都是本次改动引入的。

⚠️ 2026-09-19 清掉的 5 条存量「控件过小」里，4 条的根因是
`@media (max-width: 860px)` 里的 `.card h3 .xsel-btn, .card h3 button { min-height: 0 }`——
它**故意**把卡片标题里的控件压扁到 22~27px，正好卡在扫描阈值（32×28）下面。
一条 CSS 和一条判据长期互相打架而谁都没赢：改成 `28px` 后视觉几乎无变化。
这类「规则与判据对着干」的地方，先问哪一个是对的，别直接调阈值。
2026-09-14 只测了 1024 和 768 就提交，结果手机上 CDN 就近表格的域名列
只剩 5px 宽，内容整个溢出——而同一份判据早已在诊断弹窗里，只是没在别的视口跑过。

## 6. 部署铁律

1. 先比对源码树、安装入口、运行时目录的逐文件 SHA-256；`git status` 不能证明已部署。
2. 只同步明确变更的文件，先到暂存文件，做 LF/语法/权限校验，再原子 `mv`。
3. 任何会被 mosproxy/Unbound 加载的文件，写盘后必须真实 reload/checkconf；失败要回滚并返回非零。
4. 规则和 ECS 更新必须有空集/骤降/版本一致性护栏。
5. 不用裸 `cp` 覆盖运行文件，不在生产执行未知 shell 字符串。
6. helper 只接受固定操作、枚举 server、规范域名和规范全局 IPv4 `/24`；面板和 helper 的校验必须一致。
7. 前端 `web/` 靠 ETag/no-cache，不能恢复旧的服务端 `?v=` 指纹机制。
8. **Go 二进制只由 CI 构建**。生产机规格与依赖都不受控，且"在生产机跑没做过规模测试的代码"
   正是 2026-09-07 OOM 掀翻整机的起点。`install.sh` 里没有也不该有 `go build`。
9. **国内节点不向 GitHub 推任何东西**。构建/发布类命令在 CLI（`opsctl.requireRole`）
   与 helper（`RoleOps`）**两侧**都按 `ROLE` 拒绝，角色读不出来按拒绝处理。
   只在一侧加闸门是 2026-09-14 到 09-19 之间实际存在过的漏洞：
   面板拦住了，SSH 上去跑 `dns-stack publish` 照样能推。

## 7. 当前已知状态与下一步

### 7.11 2026-09-19：把「判不出」变成可判 + 递归管控进面板 + CLI 侧角色闸门补齐

再看一遍 antsxdp 的侧边栏，对照下来本项目唯一真缺的是「域名黑名单 / ACL 有 CLI、无面板」。
其余（递归日志、统计分析、缓存清理、节点监控）早已有；「转发源」与完整递归根本冲突，见 §7.10。

**1. `cdn-hit --fresh`：ECS 判据的死角被消掉了。** 详见 §3.3。
这是一条「判据问对了问题，但被环境骗过」的案例——逻辑一直是对的，
错的是它读到的那个答案来自缓存。**CNAME 链必须一起清**，否则等于没清。

**2. 递归管控进面板**（`/api/access`，`internal/panel/access.go`）。
⚠️ 三个设计约束，改动时别退回去：

- 列表**由面板直接读文件**，不走 helper。helper 的 `Sanitize` 会把 IPv4 打码成
  `1.2.x.x`，ACL 网段经 helper stdout 返回就全废了。写入仍然走 helper。
- ACL 的**防自锁闸门只能在面板做**——只有面板知道是谁在改。改完之后请求方
  自己不在授权网段里就拒绝、不写文件；回环（SSH 隧道）豁免；空白名单拒绝下发。
- 这几个操作**故意不进 `operationSpecs`**。进了就等于同时挂在 `/api/action/` 上，
  通用路径会把防自锁闸门整个绕过。`dedicatedOpRoles` 是它们的注册表，
  `TestDedicatedOperationsStayOutOfTheGenericActionPath` 盯着这一点。

**3. 审出一个真漏洞：`dns-stack publish` 在 CLI 侧从来没有角色闸门。**
2026-09-14 修的是 helper 侧（面板绕不过去），但 SSH 上 CN 机直接跑
`dns-stack publish` 照样能推 GitHub。同类的还有 `pull` / `classify` /
`update-cn-ip`——helper 都按 `RoleGlobalBuilder` 拦，`opsctl` 四个方法全漏。
已补齐，并加 `internal/opsctl/role_test.go`：
从 `helper.RoleOps` 反查，helper 有闸门而 CLI 没覆盖就红。
**已验证这道护栏本身是有效的**（拿掉 `Publish` 的闸门跑一遍，测试确实变红）。

**4. 死代码清理**（全库零引用，含测试）：`helper.DefaultStackRoot`、
`domain.DefectLabels`、`ruleset.LoadManual/LoadShared/OpenOptional`、
`pipeline.LoadNFTSetStrings`、`geoip.MergeRecords`、`collect.WriteAudit`、
`cdnhit.Answer.Steered`、`cdnhit.BeijingUnicom4/BeijingMobile4`，
以及两处 `var _ = xxx` 占位。删完编译器自己报出三个随之失效的 import，
反过来确认了它们确实只有死代码在用。

⚠️ 还有 4 个「只有测试在用」的导出符号**故意保留**：
`classify.ClearTrafficRuleClass`、`cdn.GeoSteeringRoots`、`cdn.OperatorFor`、
`dnswire.TypeByName`。它们的测试在记录行为契约，删了连测试一起没。

`nftables` 的表名/链名移到 `internal/stack`（`DefaultNFTTable` / `ACLChain`），
`pipeline` 与 `helper` 两侧引用同一处，避免各写一份字符串慢慢走散。

### 7.10 2026-09-14：规则集接进判据 + 护栏对齐 + 触摸端字号

参照 antsxdp 的递归系统做了一轮打磨。**它的「转发来源」（按线路转发到上游）与本项目
根本冲突**——本项目是完整递归，公共 DNS 进任何路径都是 §8 的回归。真正可借鉴的只有四项：
强制最小 TTL、一键清缓存、域名黑名单、ACL 可视化；后两项本来就有。

**`cdn-direct.txt` 从「只做答案侧检测」升级为「参与 ECS 白名单决策」**（详见 §3.3）。
它此前是一个典型的「判据从未被接上」：Action 每天生成、CN 每天拉取、
`selfcheck` 也在读，但**没有任何决策依赖它**。

⚠️ **接上判据之后才发现真正的缺口在数据侧**。规则集 20 个 provider，当时只有 6 个有前缀：

```
amazon 35/6034   cloudflare 1/434   microsoft 5/1010   （大陆段/境外段）
akamai 0/405     fastly 0/90        imperva 0/380
阿里 腾讯 华为 百度 七牛 网宿 Apple —— 一条都没有
```

根因：`officialFeeds` 只覆盖 cloudflare/fastly/amazon，其余靠 `Operator.ASNs`，
而**国产 CDN 与 Apple 一个 ASN 都没填**。后果是
`cdn-hit` 对淘宝/腾讯/百度/华为/Apple 一律判 `unknown`——判据接上了，数据侧却是空的。
（也因此，`MainlandCDN` 这条新判据在补数据之前**增量为零**：
规则集的 provider 就是从 `cdn.Operators()` 生成的，它们的根域必然已在 `geoSteeringRoots` 里。）

已按 RIPEstat 逐个核实 holder 后补齐 `PrefixASNs`：阿里 24429/37963/45102、
腾讯 45090/132203/132591、华为 55990/136907、百度 38365/55967、Apple 714/6185。
**网宿与七牛查不到可靠 ASN，弃权不填**——核实时发现常被当成网宿的 AS4808 其实是中国联通、
AS137702 是中国电信江苏 IDC，填进去等于把两家运营商的整片地址算给一家 CDN。

⚠️ **`ASNs` 与 `PrefixASNs` 是两个字段，不要合并**。`ASNs` 回答「这个 ASN 上的权威是不是
多租户共享、因而境外权威不得直连」（`SharedDNSProvider` → `shared-anycast.txt`），
`PrefixASNs` 只回答「这些地址是谁的节点」。国产云的 ASN 上主要是云主机而不是共享权威，
喂给前者语义就是错的。`cdnrules.Build` 用 `AllASNs()` 取两者之和，
`buildSharedDNSAS` 只用 `ASNs`；两条判据由 `TestPrefixASNsStayOutOfTheSharedDNSJudgement`
和 `TestPrefixASNsActuallyReachThePrefixBuilder` 分别钉住（「填了却拉不到」是最难发现的失效）。
`cdn-rules.yml` 新增 `MIN_MAINLAND_PROVIDERS=5` 门禁：全都没有大陆段时判据只会一路弃权，
**而弃权在报表上看起来和通过一模一样**。

⚠️⚠️ **国产 CDN 把节点放在运营商机房、用运营商的 IP**（2026-09-14 生产实测）：

```
img.alicdn.com   → 220.181.10.93     assets.alicdn.com → 211.100.8.69
res.hc-cdn.com   → 220.181.181.55    ss0.bdstatic.com  → 10 个省份的 IP
```

这些段**不由该 CDN 的 ASN 宣告**，所以按 ASN 拉前缀永远拿不到它们。
补 ASN 之后 `PrefixCount() > 0`，于是原来那条「provider 没有前缀就弃权」的保护失效，
`img.alicdn.com` 这种**完全正常的大陆节点**被判成了 `mismatch`（污染嫌疑）。

**根治办法是换判据维度**：要回答的是「用户拿到的是不是大陆节点」，不是
「这个 IP 属不属于该 CDN 的 ASN」。`direct4`（4256 段）本来就能回答前者，
现在它是 `cdnhit` 的**主判据**，规则集只负责归属标注与「这家 CDN 是否服务大陆」。
没有 direct4 时 `mismatch` 弃权——排除不掉「其实在大陆」就不该报可疑。
接上后默认清单从 0/0 变成 **5/5 命中**，国产 CDN 静态域名 5/7，
余下 2 个（`d1.awsstatic.com`、`www.office.com`）是真实的 ECS 未送达。

⚠️⚠️ **「没有 ECS 回显」不等于「ECS 没送达」，也可能是命中了缓存**（2026-09-14 生产复现）。
`scope=0` 的含义是「这个答案与位置无关」，**unbound 按 ECS 标准把它缓存成全局条目**，
后续任何子网的查询都命中它且不回显。实测：清缓存后第一轮（北京电信）三个域名都拿到
`scope=0`，第二三轮（联通、移动）全部无回显——权威分不出这三个子网，差异在我们这侧。

因此 `cdn-hit` **不回答「ECS 有没有送达」**，那是 `ecs-audit` 的职责。它只回答
「用户拿到的是不是大陆节点」，判定按每种观测**实际能支撑的结论**分档：

| 观测 | 判定 | 是否缺陷 |
|---|---|---|
| 落点在 `direct4` 内 | `mainland` | — |
| `scope > 0` 且落点境外 | `no_node`（挑过了仍给境外＝该服务在大陆没节点） | 否 |
| `scope = 0` | `no_steering`（权威声明不按位置调度） | 否 |
| 无回显 | `no_echo`（本轮判不出，**不进分母**） | 否 |

唯一的失败条件是**所有可判定域名都没拿到大陆节点**——那说明 ECS 链路整条失效，
而不是某家 CDN 的行为规则集看不见。

⚠️ **不要用「这家 CDN 有没有大陆段」当闸门**。`www.huawei.com` 曾被判成
「Akamai 没有大陆段」——那陈述的是规则集而不是世界：Akamai 的中国节点由网宿代运营、
用运营商 IP，AS20940 一条都不宣告，和国产 CDN 是同一个问题。用它当闸门会把真问题吞掉。

**新增 `internal/cdnhit`**：CLI `dns-stack cdn-hit`、面板 `/api/cdn-hit`（90 秒缓存）、
selfcheck 的「CDN 就近命中」组三方共用一份实现。当前判据不再使用 `stranded`：
落点在 `direct4` 就是大陆命中；`scope>0` 但落在境外表示权威按子网挑过后仍给境外；
`scope=0` 表示权威声明不按位置调度；没有 ECS 回显则本轮弃权，不得反推 ECS 没送达。
只有所有可判定样本都没有大陆命中时，才把它视作整条 ECS 链路可能失效。
`internal/selfcheck/query.go` 整个删掉——它的两个函数已并入 cdnhit，留着就是第二份实现。

**审查断言时抓到两个真缺口**，两个都是「同一份清单存在两处」：

1. **`set_arch_epoch` 面板标危险、helper 不拦**。绕开面板直接调 socket 就没有二次确认。
2. **`publish_github` 在 helper 侧没有角色闸门**。面板按 `Role` 只对 global-builder 显示，
   但 helper 是独立入口——**CN 机器绕过面板照样能往 GitHub 推**，
   而「CN 不上传 GitHub」正是主人明确定过的边界。
   根因：角色清单在 panel 的 `operationSpecs.Role`（8 条）和 helper 里散落的
   `requireRole` 调用（4 处）各存一份。已收敛成 `helper.RoleOps` 一处，
   闸门统一在 `Dispatch` 执行，`requireRole` 连同 4 处调用一起删除。

删掉的断言：`helper_test` 里的 `len(h.ops) == 44`。硬编码计数没有任何行为含义，
每加一个操作都要改数字，改完还会让人以为「审过了」。换成三条有行为含义的：
危险标记两侧一致、角色闸门两侧一致、`operationOrder` 与 `operationSpecs` 互相覆盖。
**新判据第一次运行就抓到了上面那两个缺口**——这就是它们与计数断言的区别。

**卸载清单改为扫描 `systemd/` 目录 + 一份显式的历史遗留名**（`install.sh`）。
手抄的现役清单每次新增单元都会漏；而已删除的旧单元不在目录里，必须显式列，
否则升级过的机器卸载后会残留启用中的 timer。两个来源都扫（源码树 + `/etc/systemd/system`）。

**缓存策略补齐 antsxdp 的两项**：`set_min_ttl`（强制最小 TTL）与 `flush_cache`
（可指定域名，走 `SafeDomain` 校验；全清列入 `DangerousOps`）。
`cache_info` 增加 `cache-min-ttl` 与命中率（`stats_noreset` 的 `cachehits/queries`）。
⚠️ **最小 TTL 上限刻意压到 300 秒**：它会一并抬高 CDN 那些几十秒的短 TTL，
而 CDN 正是靠短 TTL 做故障转移与就近调度的——**这一项与本轮的 CDN 就近目标直接冲突**，
所以默认仍是 0（不强制），代价写在 UI 上由主人自己权衡。

**前端触摸端字号体系**（主人实测反馈：移动端与 iPad mini 字体不协调）：

- **`enterkeyhint` 全站零使用**，iOS/iPadOS 软键盘右下角因此一律显示通用「换行」而不是「搜索」。
  已按语义补齐；同时给域名/IP 输入框补 `autocapitalize="none" autocorrect="off"`——
  否则 iOS 会把域名首字母自动大写。
- **控件字号分裂**：移动端 `--fs-field: 16px`（防 iOS 聚焦缩放）但 `--fs-control: 14px`，
  同一行里输入框与下拉框差 2px。已让 button / input / xsel 三者共用 `--fs-control`/`--fs-field`，
  并在 `@media (pointer: coarse)` 下统一为 16px（小号控件 14px）。
- **iPad mini 转屏换体系**：竖屏 768px 走移动档、横屏 1024px 直接掉回桌面档 13.5px。
  新增 861–1180px 平板档；xsel 的 bottom sheet 判定改为 `preferSheet()`
  （宽度 ≤860 或「coarse 指针且 ≤1180」），sheet 在宽屏收窄到 560px 居中。
- **`word-break: break-all` 用在中英混排上会把英文单词从中间劈开**。
  混排文本（表格、日志、toast、字段值）改 `overflow-wrap: anywhere`，
  只有纯 mono 内容（pre、哈希、主机名）保留 break-all；body 加 `line-break: strict` 做中文避头尾。
- 诊断面板新增**控件字号一致性实测**：取页面上可见的 input / xsel / button 各一个，
  比对 computed `fontSize`，多于一种就标红。把主人报的现象变成了能自己发现的判据。

### 7.9 2026-09-10：Python 归零 + 一体化 + 前端实测优化

**HK 的 `classifier/`（2800 行，最后一个运行时 Python）已重写为 `internal/classify`**——
一个包、一个 `Engine`，不是 Python 那 8 个模块的镜像。原来
`pull → classify → classify-authority → verify → build → publish` 是 6 个独立进程，
各自重开 SQLite、重载 direct4(6600 条)、重解析 PSL(8000+ 条)、`zone_cache` 每次退出就丢；
现在 `classify pipeline` 一个进程走完，权威扫描是否到期由引擎自己判断（`--authority-every`），
HK 的 cron 从 5 行降到 3 行。

**全仓库 Python 归零**：`classifier/`、`collector/`、`panel/`、`helper/`、`lib/`、
全部 `scripts/*.py`、全部 `scripts/tests/*.py` 与对应的 `*-parity.sh` 都已删除。
删之前每个包都补了 Go 测试（见 §5）。移植而非删除的三个诊断工具：
`diag-ecs-orphans.py` → `dns-stack ecs-orphans`、`diag-ecs-audit.py` → `dns-stack ecs-audit`、
`diag-ecs-forward.py` → `dns-stack ecs-forward`（为此给 `internal/dnswire` 补了 ECS 选项编解码）。
`DOMParser`、`serve-dev.py` 这类开发期工具改由 `web/devserver` 承担。

**`regression-check.sh` 从 1176 行降到 507 行**。删掉的是两类：指向已删除文件的僵尸断言，
和「某标识符存在于某 Go 文件」这类认实现的断言——后者已被 `go build/vet/test/gofmt` 严格覆盖，
而且新增了一条**「每个 internal 包都必须有测试」**。保留的是没有单元测试能覆盖的行为判据：
文件权限、CRLF、systemd 单元一致性、shell 编排护栏、模板配置、以及生产态的实测判据。

**前端优化，两处都做了实测**（不是凭感觉）：

- 渲染层 `DOMParser` → `<template>`。顺带删掉整张 `PARSE_CONTEXT` 包裹表——HTML 规范的
  "in template" 插入模式对 `tr`/`td`/`tbody`/`col` 会自动切到表格模式。
  **实测**：小片段 2.7×，20 行 1.37×，300 行只有 1.16×。
  ⚠️ 浮浮酱最初以为是 5-20×，实测推翻了这个假设——大片段的耗时被 DOM 构造主导。
- 静态资源改为**启动时预算一次**（ETag 哈希、gzip、字节拷贝）。
  **实测**：每请求 2,538,854 ns / 985,775 B → **10.4 ns / 0 B**；完整 handler 53,857 ns。
  资源实际传输 177KB → 48KB（gzip -9，现在零每请求开销）。

**CI 规模门禁抓到一个从未暴露过的隐患**（这是它第一次拦下真东西）：
`direct4-audit` 峰值 **1.5GB**，而生产机总共 1880MB。根因是
`IPDBReader.NetworksV4()` 把整棵前缀树物化——qqwry 有 **795,707 个叶子**，
每个叶子新建一个含 8 字段的 `map[string]string`，光记录就 1.26GB；
而 geoaudit 只用其中**一个字段**（`country_code`），其余全部丢弃。
这正是 §7.6 给 MMDB 打过的同一个补丁（`WalkV4` + 按偏移缓存记录），
IPDB 这条路径从来没做过。

实测（真实 qqwry，同一份数据）：

| | 累计分配 | 常驻 Sys |
|---|---|---|
| `NetworksV4`（旧） | 1,453,830 KB | 1,260,151 KB |
| `WalkV4`（新） | 141,485 KB | **147,962 KB** |

geoaudit / chnroute / ecszone 三个消费方全部改成流式，`NetworksV4` 与
`IPDBNetwork` 已删除——零调用方的物化 API 留着只是隐患。
顺带把 `geoaudit.intersect` 改成复用缓冲区（它在百万级叶子上被逐个调用）、
改为按 Hi 二分正向扫以保证升序输出，并新增 `subtractSorted` 取代逐叶子调用
会分配的 `ipset.Subtract`；相邻同国别片段就地合并，`mergeAgreement` 的
edge 数量随之大幅下降。**新旧产出逐字一致**（晋级 98 段 / 2,732,415 个地址、
ecs-zone 8326 段 / 201 zone / 跳过 13009 完全相同）。

⚠️ 这段代码是上一轮留在工作树里**从未提交、从未过 CI** 的改动。
最后一次绿色 CI 不含它，所以门禁一直没机会看到。生产上
`dns-stack-geo-cross.service` 有 `MemoryMax=1G`，而争议清单实测已经
**3.5 天没更新**（阈值 72 小时）——判据早就悄悄失效了，只是没人归因。
**没过 CI 的改动不要留在工作树里过夜。**

**迁移备份全流程打通**：`backup.sh` 此前另抄了一份状态清单，**漏掉整个 `chnroute/`**——
而 `ecs-accum-state.tsv` 是重跑也拿不回来的。现在备份、面板导出、恢复三条路径
共用 `migrationEntries` 这一份清单（`dns-stack migration-export/-restore`）。
端到端实测逐字节一致，阴性对照两条：改内容 → 该文件被 sha256 拦下且其余照常；
改 manifest kind → 整包拒收。

**新增 `dns-stack wg-peer`**（`migration/wg-peer.sh`）：CN ↔ HK WireGuard 一键对接。
换机时最容易漏的就是这一步——数据规则证书都迁好了，隧道没接上，境外权威全部走直连
拿到污染答案，而且不报任何错。默认只预演，`--apply` 才落盘；失败自动回滚本机配置。
最后一步验证的不是"隧道通不通"，而是"经隧道的境外递归能不能拿到答案"。

本轮清掉的死代码（都确认过全仓库无读取方）：`consec_*` 五个计数器（`classify.py` 恒写 0）、
`prev_result_signature`、`reachability`、`github_published`、`candidates.pulled_at`、
`field()` 的 `extra` 参数（走 `raw()` 绕过转义却无人传）。
`stable_domains` 整个删掉——只有测试在调，且比对的 `observed_status` 被写死成 `"unknown"`，
**结构上永远返回空集**。

### 7.8 2026-09-08：迁移导入（面板导出包的对偶）

`POST /api/migration-import`（multipart，支持 `dry_run`）、helper 操作 `migration_restore`、
CLI `dns-stack migration-restore`、前端「试算导入 / 导入并覆盖」。

**核心安全设计：导入与导出共用同一份 `migrationEntries(cfg)` 清单。** 导入只能写导出会写的
那些路径，白名单不会随时间漂移——这是单一事实来源，比另写一份白名单可靠。逐层校验：

| 层 | 判据 |
|---|---|
| 解包 | 拒绝绝对路径 / 含 `..` 的条目；单文件 32MB、整包 64MB 上限 |
| manifest | `kind` 必须是 `dns-stack-migration`；版本高于本机则整包拒绝 |
| 每个文件 | sha256 必须与 manifest 一致；不在清单里的**逐条报出**且不写 |
| 落盘 | 覆盖前备份到 `<state>/migration-restore-backup-<ts>/`；临时文件 + rename |
| 通道 | 面板只把上传落到 `<state>/migration-inbox/`，**真正的写入经 helper**；helper 用 `EvalSymlinks` 后做前缀检查 |
| 权限 | `migration_restore` 列入 `DangerousOps`，必须 `args.confirm=true` |

⚠️ **测路径限制时先确认 helper 能看见那个文件**。第一次用 `/tmp/xxx` 测，两条都"通过"了，
但错误消息是"迁移包不存在"而不是"必须位于…下"——`dns-stack-helper.service` 有 `PrivateTmp`。
那一轮测的是文件可见性，不是路径判据。

### 7.7 2026-09-07：CN 生产路径 Python 清零 + CI 规模门禁

`update-cn-authority.sh` 的 550 行内联 Python 搬进 `internal/cnauth`（脚本 761→226 行）；
`update-geoip.sh` 的库校验 → `dns-stack geoip-verify`；`update-chnroute.sh` → `internal/chnroute`；
`collect-polluted-ip.sh` → `internal/polluted`；`sync-rules.sh` 6 处 → `internal/rulesync`。

两处移植时容易错、已用测试钉死的地方：

- **Go 的 regexp 不支持 lookahead**。原域名正则 `^(?=.{1,253}$)(?!-)...(?<!-)...$` 改写成
  `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.…)*$` + 单独的长度检查。判据要**逐条**比多个域名
  （合法/前导连字符/尾随连字符/下划线/大写/连续点）——两边都拒但拒的不是同一条，整文件比法看不出来。
- **IPv6 的 CIDR 合并**。`internal/cidrutil` 用 `math/big` 做 128 位区间运算，v4/v6 共用一套 collapse。
  注意 `::1` 和 `::2` **跨 /127 边界本来就不该合并**，第一版自证断言就写错在这里。

⚠️ **`ipset.Subtract` 原来是 O(base × cuts × parts)**，chnroute 实测吃到 470MB。
已换成扫描线（O(n)，共享游标不重置，要求两侧输入都已 collapse）。
同轮还给 `Set` 加了零分配的 `Overlaps(lo,hi)`——`Ranges()` 每次返回**拷贝**，
在热循环里调它就是 OOM 的同一个错误，这是第二次犯。

**CI 规模门禁**（`build.yml` 的 `scale-gate`）：拉真实归属库 + 现拉 APNIC 生成真实量级 direct4，
用 `/usr/bin/time -v` 卡峰值 RSS ≤ 512MB、耗时 ≤ 300s，`release` 依赖它。
**拉不到库时明确报 skip 而不是静默通过**。

### 7.6 2026-09-07：把新归属库接进递归判据

**起点是一个"判据从未被接上"**：`geoip.yml` 每天把 5 个库发到 Release，但拉取端只拉前 3 个，
`dbip-*` 在 CN 机器上根本不存在；`direct4-audit` 能算出结果，而**全仓库没有任何代码读它**。
判据链两头都断，中间那段写得再好也没用。

💥 **本轮把生产 DNS 搞停过约 10 分钟**：在生产机**手工裸跑**了没做过规模测试的 `ecs-zone`，
`ipset.Subtract` 在几十万次热循环里每次都 `Collapse` 分配新 slice，吃到 1.7GB RSS（机器只有 1880MB）
→ 内存耗尽 → sshd 连 fork 都做不到 → DoT 握手超时 → **递归对外不可用**。
三层防御都已落地：`anyOverlap` 二分预判、cgroup 硬上限、CI 规模门禁。
**"只读"不等于"安全"——`--dry-run` 一个字节都没写，照样掀翻整机。**

### 7.1-7.5 更早的几轮

按时间倒序：助手 Go 化（7.5）、采集器 Go 化（7.4）、面板 Go 化的真实代价（7.3）、
递归严谨度与 ECS 收紧（7.1）。它们共同的教训已经提炼进 §5 与 §8，细节见 `.memory-archive/`。
其中反复出现、值得单独记住的几条：

- **「从未被调用 / 从未被填 / 只写不读」是独立的缺陷类型**，且不会有任何报错。
  `last_decisive_at` 全仓库只被写过 NULL；`is_cn_ip` 从没被生产代码传入；
  `consec_*` 恒写 0。它们都让某条判据结构上永远产不出结果。
- **判据的覆盖面本身就是判据**。面板 Go 化时 207 例对拍全绿，而 11 个端点压根不在用例里。
- **换实现时所有"认实现"的判据都要跟着换**，否则它们检查的是僵尸文件。这已经是第三次现场。
- **用"进程还在"回答"链路是否在工作"是错的**；健康检查不能写死某一种实现的进程名或 JSON 形态。

## 8. 绝对禁止回归

- 公共 DNS 进入任何正常或降级路径。
- 境外权威单独晋级 GFW/国内规则。
- 聚合后的路由前缀直接变成 ECS 授权。
- 非全局/保留地址进入 geographic evidence、ECS 或污染客户端规则。
- `client-subnet-always-forward: yes` 或不受控的 ECS 发送。
- 把 `cn.txt`、`gfw.txt`、历史 IP 观测作为递归输入。
- 单个 GeoIP 库直接决定权威落点，或在解析关键路径上做归属查询。
- 挡了权威 /32 却不从 direct4 冷启动段里扣掉争议网段（那条 /24 会原样覆盖回来）。
- 把 `geo-promoted.txt` 当 `geo-disputed.txt` 用（必须 fail-closed）。
- 可用归属库不足 2 个时仍然否决或晋级（护栏缺席要 fail-open）。
- 共享多租户 provider 根域成为整体 `cn` 规则。
- 权威位置判定不经国内视角落点复核就写入客户端流量规则。
- 双视角分类在拿不到 `direct4` 落点判据的状态下继续运行。
- 某一类规则本轮为空就把上一轮的整类抹掉；撤回只能走显式出口。
- 配了 `ecs.ip_zone` 之后凭"没打标"就不发 ECS。
- 出口 IP 出现在任何 API 响应里（面板已公网可访问，只给归属标签）。
- 迁移导出包含任何密钥，或省略排除项而不写理由。
- **备份与迁移导出各自维护一份状态清单**（必须共用 `migrationEntries`；
  分叉过一次，代价是 `chnroute/` 整个没进备份）。
- 判据依赖的字段没有任何代码会填；或字段只被写、从不被读。
- 解除 EXIT trap 后手写临时文件清单。
- mosproxy 的 `ExecStart` 管道少掉 `-o pipefail`。
- 健康检查/回归的判据写死某一种实现的进程名或 JSON 序列化形态。
- 用"进程还在"回答"链路是否在工作"。
- **在生产机手工裸跑没做过规模测试的代码**（一律套 `systemd-run -p MemoryMax=`）。
- **在生产机编译 Go**（`install.sh` 里出现 `go build` 即为回归）。
- 全表扫描类 systemd 单元没有 `MemoryMax` / `CPUQuota`。
- 热循环里调用会分配内存的辅助函数（`Collapse`/`Subtract`/`Ranges` 这类）。
- **`internal/` 下的包没有任何测试**（Python 参照已删，测试是唯一证据）。
- **改了判据却没做阴性对照**（把它改错，测试必须当场变红）。
- 只比聚合计数、或 Go 侧把空集合序列化成 `null`。
- **用硬编码的条目数当断言**（`len(ops) == 44` 这类）。它没有行为含义，
  每次改动只是改数字，还会伪装成「审过了」。要断言的是两侧一致、闸门可达这类性质。
- **面板与 helper 各存一份危险标记或角色清单**（必须共用 `helper.DangerousOps` /
  `helper.RoleOps`；分叉过一次，代价是 CN 能绕过面板往 GitHub 推）。
- **CDN 规则集只用于展示或检测，不接进任何决策**（那就退回「判据从未被接上」）。
- **接判据时不看数据侧是不是空的**。判据接通了、代码有测试、CI 全绿，
  而规则集里那家 CDN 一条前缀都没有——结果是永远弃权，且看起来和通过一样。
- 往 `Operator.ASNs` 里塞只为拉前缀的 ASN（那会让它们被当成共享 DNS 提供商，
  改用 `PrefixASNs`）。
- 凭记忆或搜索结果填 ASN。必须逐个查 RIPEstat 的 holder 核实；
  查不出归属就**弃权**，不要凑数（AS4808/AS137702 是运营商，不是网宿）。
- 拿「答案落在境外」本身当缺陷报警——先看 scope 才知道原因。
- 凭「有 ≥1 条大陆段」就断言某 CDN 该给大陆节点（Cloudflare 只有 1 条，
  实际大陆服务在另一张网上；门槛是 `cdnrules.MinMainlandPrefixes`）。
- **把「没有 ECS 回显」当成「ECS 没送达」**（`scope=0` 会被 unbound 缓存成全局条目，
  后续查询一律不回显；要判送达请用 `ecs-audit`）。
- 用「这家 CDN 在规则集里有没有大陆段」当闸门去决定报不报缺陷。
- **拿「这个 IP 属不属于该 CDN 的 ASN」回答「用户拿到的是不是大陆节点」**。
  国产 CDN 用运营商 IP，按 ASN 永远查不到；主判据必须是 `direct4`。
- 超时参数传 0 却不在被调方兜底（`timeout=0` → deadline 就是此刻 → 每次探测瞬间失败，
  而现象是「解析不出来」，看不出是调用方传错了）。
- 强制最小 TTL 开到能压住 CDN 短 TTL 的量级（上限 300 秒，且默认不强制）。
- 前端把 `word-break: break-all` 用在中英混排文本上（英文单词会被从中间劈开）。
- 交互式输入框缺 `enterkeyhint`，或域名/IP 输入框缺 `autocapitalize="none"`。
- 同一行里的 input / select / button 出现不同 computed 字号。
  ⚠️ **判据要限定在 `.filters` 这类真正并排的容器内**——拿标签页按钮（`--fs-sm`）
  去和表单下拉框比，报出来的是判据自己的缺陷，不是页面的。
- **只在一两个视口验证就提交前端改动**（必跑 320/393/641/768/861/1024/1920）。
- 给表格设了 `table-layout: fixed` 与固定列宽，却没为窄屏准备堆叠布局——
  固定列宽之和超过容器时，自动列会被压到几个 px，内容全部溢出。
- 面板处理器用裸 `time.Now()`（必须走可注入的 `s.now()`）。
- 面板可经 `update_panel_auth` 写入 password hash / salt / session_key。
- helper 的两条错误通道被合并（参数被拒会被面板当成"执行成功但无输出"）。
- 命令启动失败却不报出原因（`rc=-1 stderr=""` 是最难排查的一种失败）。
- 助手以非 root 运行，或 socket 属组不是 `dns-stack-panel`。
- 脱敏对拍只比"两边一致"，不断言机密串确实消失。
- 把"对不上就加进结构比白名单"当成解决办法（归一必须打印出来）。
- 前端渲染层出现 `esc()` 之外的转义旁路（`raw()` 只接受字面量或已 `esc()` 过的串）。
- 静态资源在请求路径上重新计算 ETag 或重新压缩（必须启动时预算一次）。
