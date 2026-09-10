# 本 Fork 的改动

上游：[IrineSistiana/mosproxy](https://github.com/IrineSistiana/mosproxy)，分叉基点 `80afb01`。
本仓库独立维护。改动仍然保持小而独立、每个缺陷一个提交，便于日后回溯与合并上游更新。

下面每条都经过实际验证，不是静态推断。

## 修复

**1. ECS 前缀没进缓存 key** — `app/router/router_utils.go`

```go
- q.ECS2Upstream.Masked().AppendTo(b)
+ b = q.ECS2Upstream.Masked().AppendTo(b)
```

`AppendTo` 遵循 append 惯例会返回新 slice，丢弃返回值等于没写入。结果 ECS 从未进入缓存 key，
所有客户端共享一条缓存、不分子网，随后的长度字节也写错。仅启用 `ecs` 时触发。

**2. 预取单飞标记从不释放** — `app/router/router_handle.go`

`prefetchCtl.Done` 有定义但零调用点。`Reserve` 把 key 放进 map 后再也不删，于是每个 key
一生只能预取一次，之后永远返回 false。启用乐观缓存时后果被放大：记录过期后无法后台刷新，
会持续返回陈旧结果直到乐观窗口耗尽。同时是无界 map，用随机子域可远程撑爆内存。
修法是在预取 goroutine 里 `defer r.prefetchSf.Done(sk)`。

**3. 域名匹配大小写敏感** — `app/router/server_utils.go`

规则加载时做了小写化，查询名却从未规范化，而匹配用 `bytes.Compare`。于是 `WWW.EXAMPLE.COM`
匹配不到任何规则，直接落到默认路由——基于域名的分流静默失效，reject 规则也能靠翻转一个字母绕过。
RFC 4343 要求大小写不敏感比较，且部分解析器会故意随机化大小写（DNS 0x20）防投毒。
在 `parseQuery` 里补 `q.Question.Name.ToLower()`，顺带修掉缓存 key 碎片化
（同一域名原本有 2^labels 个 key，可被用来冲刷缓存）。

**4. 并发限流计数器泄漏** — `app/router/middleware/limit/limit.go`

超限分支在 `defer h.concurrent.Add(-1)` 注册之前就 return，计数器只增不减。突发几次后
计数永久高于上限，之后所有查询被 REFUSED 直到重启。把 `defer` 提到自增之后即可。

**5. 截断没有置 TC 标志，段计数也不修正** — `pkg/dnsmsg/msg.go`

`Pack` 把 header 复制到 `msgHdr` 供截断逻辑设置 TC，但真正写入线缆的 bits 取自原始
`m.Header`，那个标志被丢弃了；各段计数同样是打包前算好、之后从不因跳过的记录而调整。
于是客户端拿到一个被削短的应答，却看到 TC=0 和一个与实际内容不符的 ANCOUNT——
它无从得知记录缺失，也就永远不会改用 TCP 重试，把残缺应答当成完整结果。
附带的回归测试 `pkg/dnsmsg/truncation_test.go` 会构造 80 条 A 记录压到 512 字节上限：
修复前是"裁到 17 条但 TC=false"，修复后为"裁到 17 条且 TC=true"。

**6. Commit/Discard 抹掉了已生效的校验和** — `app/router/data_loader.go`

`Commit` 把新校验和存进 `s.hash` 后立刻又将其清零（本意是清 staging 的那份），
`Discard` 同理清错了对象。结果文件**第一次真正变化之后**，记录的校验和恒为零、永不匹配，
此后每次 reload 都会重新读取并解析文件，哪怕内容一个字节都没变。
实测：连续两次 reload 相同内容，修复前两次都打印 `file loaded`，修复后第二次正确地
`skip loading file, same checksum`。

**7. 路径前缀匹配的长度判断写成了自比较** — `app/router/rule.go`

`len(q.Path) >= len(q.Path)` 恒为真，导致后面的切片在请求路径短于前缀时越界 panic，
直接带崩进程。只要配置了以 `/` 结尾的 `path:` 规则，再来一个更短的（或来自 UDP/TCP
服务器因而为空的）路径即可触发。

**8. base64 解码长度被丢弃，池内残留数据混入查询** — 两个 HTTP 服务端

`DecodedLen` 只是上界，解码器会跳过换行等字符，实际写入可能更短。原代码丢弃了返回值、
把整个缓冲区当作查询报文传下去，于是**上一个请求遗留在池化缓冲区里的字节**被拼到了
本次查询尾部；若报文中的压缩指针指向那段，这些残留会被当成域名解析，并原样回显在
应答的 question section 里。改为按实际解码长度切片。

**9. 配了 `ecs.ip_zone` 之后，分片表没覆盖到的客户端完全收不到 ECS** — `app/router/router_handle.go`、`app/router/ecs.go`

```go
- if len(q.ECSZone) == 0 {
+ if len(q.ECSZone) == 0 && !ecsAddrIsGlobal(q.ECS2Upstream.Addr()) {
      q.ECS2Upstream = netip.Prefix{}
  }
```

原判据把「分片表没给这个地址打标」当成「这是本地客户端」。分片表由归属库生成，只覆盖
归属库标注得出的那部分空间——本部署实测 `direct4` 里 **69.85% 的大陆 IPv4 地址空间没有标记**，
落在其中的客户端全都彻底收不到 ECS，权威只能按解析器位置作答，而这正是 ECS 要消除的问题。

同一份代码的两半互相拆台：`appendCacheKey` 本来就有「无 zone 就按真实前缀分片」这条分支
（`router_utils.go` 的 `case q.ECS2Upstream.IsValid()`），是 handler 提前把前缀清成零值让它走不到。

改成只对**确实不携带任何位置信息**的地址抑制：环回、私网、CGNAT、链路本地、benchmark、
文档示例与组播段。局域网与隧道客户端行为不变；公网客户端不再取决于归属库有没有收录它的网段。

## 新增

**剥离 SVCB/HTTPS 的 `ech` 参数** — `pkg/dnsmsg/svcb.go`、`app/router/router_handle.go`

Cloudflare 正在铺开 ECH。客户端一旦从 HTTPS 记录读到 ech 公钥，就会加密真实 SNI，
明文 ClientHello 里只剩幌子名 `cloudflare-ech.com`——**所有按域名分流的代理同时失明**，
规则匹配不上，流量静默落到默认出站。而 mosproxy 的 `RuleConfig` 只能按 domain/server/
path/client_ip 匹配，没有 qtype 维度，配置层根本挡不住，只能从报文层动手。

实现放在 `dnsmsg`，与 `RemoveEDNS0` 同层：HTTPS(65) 在 `unpackResource` 里落到
`RawResource`，wire-format RDATA 原样留在 `Data`，所以直接对字节做 TLV 手术，不必为
SVCB 单独实现一个 Resource 类型。SvcParams 是升序 TLV，删掉一项仍然有序，因此
**原地压缩**即可（写游标永不越过读游标），零分配；不含 ech 的记录一次扫描后原样返回。

三个容易漏的点：

- **不能整条丢弃 HTTPS 记录**。那会连 `alpn="h3"`（HTTP/3 没了）和 ipv4hint/ipv6hint
  （Happy Eyeballs 失效）一起赔进去，代价实打实而收益为零。只删 key 5。
- **必须同时删掉覆盖 SVCB/HTTPS 的 RRSIG 并清 AD 位**。留着签名比没有签名更糟：
  验证型客户端会拿改写后的记录去核对原签名，失败后把整个应答当成攻击丢弃——
  一个分流修复会变成一次故障。
- **配置项是 `*bool` 而不是 `bool`**。零值 false 意味着所有既有配置文件升级后会静默
  不启用，而唯一症状是分流悄悄失效。nil（未配置）按 true 处理。

指标 `ech_stripped_total` 用来防这类静默失败：解析成功率不受影响，剥离链路断掉时
没有任何报错，只能靠计数器是否在涨来判断它还活着。

验证用的是生产解析器上抓的真实 RDATA（`dig +unknownformat crypto.cloudflare.com HTTPS`，
含 71 字节 ech），不是手搓样本：单测覆盖剥离/无 ech 原样返回/七种畸形输入不 panic；
端到端起两个实例对照，默认实例 `ech=` 消失且 alpn 与两个 hint 完好，`strip_ech: false`
实例保留 ech。

**查询日志输出 `elapsed`** — `app/router/log.go`

`QueryCtx.Start` 早就在记录却从未出现在日志里，导致下游无法区分"缓存命中"和"一次慢速递归"。
加 `e.Dur("elapsed", time.Since(q.Start))` 后（单位毫秒）：缓存命中约 `0.09`，冷递归约 `800`，
一眼可辨。

**缓存按实际转发路径隔离** — `app/router/rule.go`、`router_handle.go`、`router_utils.go`

规则热更新可能把同一域名从动态/国外路径切到国内递归，旧缓存 key 却不含转发目标。
在开启乐观缓存时，规则虽然已 reload，旧路径答案仍可能继续命中数天。现在把匹配规则的
`forward` 标签写进 cache key，路径改变会自然使用新 key，不必清空其它无关缓存。

**`fall_through` 在同一次查询内真正回退** — `app/router/upstream_lb.go`

上游实现只按顺序选择第一个健康后端；该后端本次网络失败或返回 SERVFAIL 时不会尝试
后续后端，要等健康检查累计失败并把它标为离线后，下一次查询才可能切换。这会让动态
分类服务刚宕机时的前几次 DNS 请求直接失败。现在 `fall_through` 会在共享的查询超时内，
按配置顺序重试传输错误和 SERVFAIL，国内 Unbound 与动态服务的降级均即时生效。

**证书随文件变化热重载** — `app/router/tls.go`

`makeTlsConfig` 用 `tls.LoadX509KeyPair` 把证书**一次性**读进 `tls.Config.Certificates`，
之后再不看磁盘；换证书的唯一办法是重启进程。而 `signal_linux.go` 把 SIGHUP 归入
`exitSig`，连"发个信号重载"的口子都没有。

对 DNS 服务器，这个代价比看上去大得多。重启会同时做三件事：断开全部在途
DoH/DoT/DoH3 连接、丢掉整个内存缓存、**重置 TLS session ticket 密钥**——
最后一项意味着所有客户端的 session resumption 状态一起作废，重连时全部退化成
完整握手。用短效证书时这笔账每几天付一次（Let's Encrypt 的 IP 证书只有约 6 天
有效期，实际是每 3 天重启一次）。

改为 `GetCertificate` 回调 + 按 mtime 惰性重载：

- 握手是热路径，不能每次都 `stat`。用 `certReloadInterval = 10s` 配 CAS 限流，
  并发握手中只有一个会真正去看文件。ACME 续签以天计，10 秒的发现延迟无关紧要。
- **重载失败保留旧证书**。ACME 客户端写 cert 与 key 不是原子的，重载完全可能撞上
  截断的文件、或 cert 与 key 尚未配对的瞬间。为这个短暂窗口让握手失败，比继续用
  一张仍然有效的旧证书糟得多；下一次尝试自然会取到新的。
- 多证书时用 `ClientHelloInfo.SupportsCertificate` 按 SNI 选，全不匹配则回落到第一张
  ——与 `crypto/tls` 对静态 `Certificates` 切片的行为一致。

**CI 构建静态二进制** — `.github/workflows/release-binaries.yml`

上游只发 Docker 镜像。打 tag 即产出 linux/amd64 与 arm64 静态二进制 + SHA256，
裸机部署不必装 Docker 或 Go。

## 合并上游更新

```bash
git remote add upstream https://github.com/IrineSistiana/mosproxy.git
git fetch upstream && git rebase upstream/dev
```

上游是 alpha 阶段、无 tag/release 的项目，更新节奏不稳定。合并后请至少重跑
`go test ./...` 与 `go test -race ./app/router/... ./pkg/dnsmsg/...`，
其中 `truncation_test.go` 能直接兜住第 5 条被上游改动覆盖的情况。
