# dns-stack

自建 DNS 解析栈：**本地完整递归 + 递归出口按权威 IP 分流**。

目标是把 DNS 污染从「需要检测再对抗的现象」变成「结构上不可能发生」。

后端与面板是**单个静态 Go 二进制**（前端 `go:embed` 在内），无运行时依赖。

---

## 工作剖析

### 核心思路

常见做法是「先解析，再判断答案可不可信」——需要双视角对比、启发式打分，
而判据本身就可能被污染。本项目把问题提前一步：**不让污染的查询发生**。

```
客户端 ──DoH/DoT/DoH3/DoQ──▶ mosproxy ──▶ 本机 Unbound（从根区完整递归）
                                              │
                              递归的每一跳都要问权威服务器，
                              出口按「这台权威在哪」分流：
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
              权威在大陆                                          权威在境外
         直连出网                                          经 WireGuard 隧道到境外节点
    （境内到境内，GFW 不介入）                              （GFW 看不见这个查询）
```

两条路径都拿不到污染答案，于是「猜谁可信」整套机制失去存在理由。

判据也从主观的「这个域名算不算国内的」（要人工维护、永远滞后）
变成客观的「这台权威服务器在哪」（可核验的网络事实）。

### 分流是怎么落地的

| 机制 | 作用 |
|---|---|
| `nft inet dns_route / chain output` | 正向匹配 Unbound 的 uid，目标不在 `@direct4`/`@cn_authority` 就打 fwmark |
| `ip rule fwmark 0x1d5 lookup 100` | 打了标的包走隧道 |
| `ip rule fwmark 0x1d5 prohibit` | 隧道断时境外查询**显性失败**，绝不回落直连 |
| `@direct4` | 大陆 IP 集合，源为 APNIC 一手委派记录 |
| `@cn_authority` | 「权威含大陆 IP」的区域；大陆权威可聚合，境外权威严格按 /32（避免共享 anycast 误伤） |

隧道断了宁可解析失败，也不回落直连——回落拿到的是污染答案，
**看着成功、实则更危险**。

### 客户端规则是怎么生成的

分流本身不需要域名规则；域名规则只用于**客户端侧**的代理分流。
规则由境外构建节点生成，经 GitHub 发布，国内节点拉取：

```
采集候选域名 ─▶ 双视角解析（境内视角 / 境外视角）
                      │
              权威位置判定 + 国内落点复核
                      │
        七道准入判据（共享 provider 根域拦截、境外落点剔除、
        人工规则优先、空类保护、发布新鲜度门禁…）
                      │
              四份规则文件 ─▶ GitHub ─▶ 国内节点 sync-rules
```

**判定结果绝不回流成判定输入**——那是自我强化的死循环。

### ECS 就近调度与 CDN 大陆节点

面板与递归都按客户端 /24 发送 EDNS Client Subnet，让 CDN 返回真正就近的节点；
白名单按「这台权威服务谁」收敛，而不是按「权威 IP 在不在大陆」。

**这一条对分流架构是必需品而不是优化项**。境外 CDN 的权威在境外，查询必然走隧道；
如果那台权威收不到中国 ECS，它只能按隧道出口（香港）判断你在哪，
于是把国内用户整体调度到香港节点——链路通、解析成功、但绕了一圈。

判据由两层组成：

| 层 | 来源 | 回答的问题 |
|---|---|---|
| `internal/cdn` 静态后缀表 | 人工维护 | 这个域名属于哪家 CDN、是不是 geo-steering |
| `cdn-direct.txt` 规则集 | `cdn-rules` Action 每日重建 | 这家 CDN **在大陆到底有没有节点段** |

第二层是可核验的网络事实：规则集从各家官方前缀源与 ASN 通告拉取，
按 APNIC 大陆基线切成大陆段与境外段。**只要规则集证明某家 CDN 有大陆节点，
它的境外权威就一律进 ECS 白名单**——不必等人工往静态表里补。
境外权威只进白名单、永不进直连集合（直连会吃 GFW 污染）。

`dns-stack cdn-hit` 是这条链路的验收判据：以真实中国 /24 的身份解析国内外大厂域名，
重点报出「该 CDN 在大陆有节点、答案却落在境外」——那不是分流出了问题，
是 ECS 没送达那台权威。

判据本身有一个**会被缓存骗过**的死角：`scope=0` 的答案会被 unbound 按 ECS 标准
缓存成全局条目，之后任何子网的查询都命中它且不回显，于是「无回显」既可能是
没送达、也可能只是命中了缓存——判不出。`--fresh` 消除这个死角：探测前先把这批域名
**连同它们的 CNAME 链**逐个 `flush_zone`（只清查询名不够，链末端的 A 记录还在缓存里），
强制走一次真实递归。此时仍然无回显就只剩一个解释：**你的子网没送到那台权威**，
它只能按隧道出口（香港）判断你在哪。面板上对应「清缓存重查」，
代价是这些热门域名下一次解析要走完整递归，因此 10 分钟内只允许一次。

判定「是不是大陆节点」用的是 `direct4` 而不是规则集里的归属，这一点很关键：
**国产 CDN 把节点放在运营商机房、用的是运营商的 IP**（`img.alicdn.com` 落在
`220.181.10.93`），那些段不由阿里的 ASN 宣告，按 ASN 去查永远查不到。
规则集在这里只负责回答「这是哪家 CDN」和「这家 CDN 是否在大陆有节点」。

### 递归管控

面板「设置 → 递归管控」与 CLI 共用同两个文件，改哪边都一样：

| | 文件 | 生效方式 |
|---|---|---|
| 域名黑名单 | `blocklist.txt` | mosproxy 的 `domain_set`，命中直接回 NXDOMAIN，连递归都不发生 |
| 访问控制 | `acl.txt` | 渲染成 nftables 链，只放行列出的网段访问 DoH/DoT 端口 |

两者都只在国内解析节点上存在，面板与助手按 `ROLE` 拒绝其它角色。
访问控制多一道**防自锁闸门**：如果改完之后请求方自己就不在授权网段里，
面板直接拒绝、不写文件——这个判断只有面板做得到，因为只有它知道是谁在改。
回环访问（SSH 隧道）不受此限，空白名单同样拒绝下发。

---

## 快速开始

### 一、拿到二进制

```bash
# 从 Release 下载（GitHub Actions 构建，带 sha256）
curl -fsSLO https://github.com/fa1nes/dns-stack/releases/latest/download/dns-stack-linux-amd64
curl -fsSLO https://github.com/fa1nes/dns-stack/releases/latest/download/dns-stack-linux-amd64.sha256
sha256sum -c dns-stack-linux-amd64.sha256
chmod +x dns-stack-linux-amd64
```

也可以自己编译（无 CGO，无第三方 DNS 库）：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o dns-stack ./cmd/dns-stack
```

### 二、部署

```bash
git clone https://github.com/fa1nes/dns-stack.git && cd dns-stack
cp config.example.env /etc/dns-stack/config.env   # 按注释填写
sudo ./install.sh
```

`install.sh` 会按 `ROLE` 部署对应角色，并用 systemd drop-in 把面板、采集器、
管理助手都指向同一个 Go 二进制。

### 三、访问面板

```bash
sudo dns-stack panel-password    # 设置访问密码
```

面板默认监听 `127.0.0.1:8080`；改成非回环地址时**必须**同时配好密码与
TLS 证书，否则拒绝启动（宁可起不来，也不裸奔）。

---

## 常用命令

```bash
dns-stack health            # 健康检查：递归、分流、采集链路、ECS 白名单、CDN 就近命中
dns-stack routing-status    # 当前分流集合与隧道状态
dns-stack cdn-hit           # 以真实中国 /24 验收 CDN 是否真的给了大陆节点
dns-stack cdn-hit --fresh   # 同上，但先清缓存，让「无 ECS 回显」变成可判定的结论
dns-stack blocklist list    # 域名黑名单（命中即回 NXDOMAIN，不出本机）
dns-stack acl status        # 访问控制：谁能查询 DoH/DoT/DoQ 入口
dns-stack version
```

单二进制的其余子命令：

| 子命令 | 用途 |
|---|---|
| `panel` | 启动管理面板（前端已内嵌） |
| `helper` | 以 root 运行受限管理助手，供面板经 unix socket 调用 |
| `collect consume-stdin` | 消费 mosproxy 查询日志（客户端地址即时丢弃，不落盘） |
| `geoip-check` | 查询 IP 归属 |
| `domain-check` / `ipset-check` / `infra-check` / `authority-check` | 各类判据的独立入口 |

---

## 自动化

| 工作流 | 作用 |
|---|---|
| `.github/workflows/build.yml` | `gofmt` + `go vet` + `go test`，再交叉编译 linux/amd64、linux/arm64、windows/amd64，打 tag 时附到 Release |
| `.github/workflows/geoip.yml` | 每日把四个上游归属库镜像到本仓库的 `geoip-latest` 滚动 Release，带体积门槛与**已知地址抽查**（只看文件大小不够，格式变了文件照样够大）。生产端由 `dns-stack routing-data --only geoip` 拉取，多出来的 DB-IP 是权威落点交叉验证的第三个源 |
| `.github/workflows/cdn-rules.yml` | 每日重建 `cdn-direct.txt`：从各家官方前缀源与 RIPEstat 的 ASN 通告拉取，按 APNIC 大陆基线切成大陆段/境外段。带**校验器自检**（拿一条明知错误的锚点去验，验不红就说明校验器自己失效了）与骤降拒绝。生产端由 `dns-stack sync-rules` 拉取 |

规则集全部由**本仓库的 Action 机器人生成并发布**，不引用任何第三方规则源——
第三方规则集的口径、更新节奏和存续都不受控，而这条判据直接决定 ECS 发给谁。

二进制同样只由 Actions 构建：**国内节点不编译、也不向 GitHub 推任何东西**，
只从 Release 下载并校验 sha256。这条不是约定而是闸门——
构建与发布类命令（`publish` / `build-rules` / `rebuild-rules` / `classify-*` /
`pull` / `update-cn-ip`）在 CLI 和受限助手**两侧**都按 `ROLE` 拒绝，
角色读不出来时按拒绝处理。`internal/opsctl/role_test.go` 与
`internal/panel/parity_test.go` 负责保证两侧不会走散：
helper 上有闸门而 CLI 漏了，测试直接红。

---

## 隐私与安全

- 客户端 IP **不落盘、不转发、不出现在任何 API 响应里**；查询日志在内存管道里就已脱敏
- 递归出口地址不出现在 API 响应里（面板可公网访问，只在前端不渲染是无效的）
- 面板自身只做只读访问，一切特权写入经受限助手；助手只接受白名单操作，
  命令是固定数组，绝不拼接用户输入
- 面板不能经助手改写密码哈希 / salt / 会话密钥
- 迁移导出包不含任何密钥，并**显式列出每个排除项及理由**

---

## 文档

| 文件 | 内容 |
|---|---|
| [`docs/使用指南.md`](docs/使用指南.md) | 日常运维操作 |
| [`docs/故障模式.md`](docs/故障模式.md) | **反复出现的故障模式**——每一条都是实际踩出来的，多数不止一次 |
| [`memory.md`](memory.md) | 架构、判定规则、验证入口、部署铁律 |
| [`fa1nes/mosproxy` 的 FORK-NOTES](https://github.com/fa1nes/mosproxy/blob/dev/FORK-NOTES.zh-CN.md) | mosproxy fork 改了什么、为什么 |

新接手先读 `docs/故障模式.md`：这个项目最贵的经验都在那里。
