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

### ECS 就近调度

面板与递归都按客户端 /24 发送 EDNS Client Subnet，让 CDN 返回真正就近的节点；
白名单按「这台权威服务谁」收敛，而不是按「权威 IP 在不在大陆」。

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
dns-stack health            # 健康检查：递归、分流、采集链路、ECS 白名单
dns-stack routing-status    # 当前分流集合与隧道状态
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
| `.github/workflows/geoip.yml` | 每日把四个上游归属库镜像到本仓库的 `geoip-latest` 滚动 Release，带体积门槛与**已知地址抽查**（只看文件大小不够，格式变了文件照样够大）。生产端由 `scripts/update-geoip.sh` 拉取，多出来的 DB-IP 是权威落点交叉验证的第三个源 |

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
