# 系统概述

## 它是什么

一个**自己从根区完整递归**的 DNS 解析器，对外只提供加密入口（DoH / DoH3 / DoT / DoQ）。它不转发给任何公共 DNS，降级路径里也没有。

一句话概括它的设计：**递归的每一跳都要问某台权威服务器，出口按「这台权威在哪」分流。**

| 权威在哪 | 怎么问 | 为什么拿不到污染答案 |
|---|---|---|
| 大陆 | 直连 | 境内到境内，墙不介入 |
| 境外 | 经 WireGuard 隧道从香港出网 | 墙看不见这个查询 |

## 两台机器

| | 角色 | 职责 |
|---|---|---|
| 国内 | `cn-resolver` | 加密入口、递归、出口分流、数据流水线、采集、面板、告警。整套系统的全部功能都在这里 |
| 香港 | `offshore` | 一台 Unbound + WireGuard 出口。国内节点经隧道过来的递归从这里出网，它同时是 mosproxy 的降级上游 |

香港节点上**没有任何需要维护的业务逻辑**：它不生成数据、不写数据库、不对外发布任何东西。同一个 dns-stack 二进制在那里只做一件事——每天给日志瘦身。详见 [两台节点](/ops/nodes)。

## 模块一览

国内节点（`ROLE=cn-resolver`）：

| 模块 | 类型 | 周期 |
|---|---|---|
| mosproxy（DNS 入口，同时承载采集器） | 常驻 | — |
| Unbound（递归解析器） | 常驻 | — |
| dns-stack-recursive-routing（出口分流） | 常驻 | — |
| wg-quick@wg0（香港隧道） | 常驻 | — |
| dns-stack-panel / dns-stack-helper（面板与特权助手） | 常驻 | — |
| dns-stack-routing-watchdog（分流看门狗 + 告警） | 定时 | 1 分钟 |
| dns-stack-routing-data（分流数据流水线） | 定时 | 15 分钟 |
| dns-stack-collect-polluted（污染 IP 采集） | 定时 | 6 小时 |
| dns-stack-maintenance（例行维护） | 定时 | 6 小时 |

香港节点（`ROLE=offshore`）只有 Unbound、wg-quick@wg0 和一条每日的日志瘦身 cron。

模块清单的唯一来源是代码里的 `internal/stack`：面板、助手、自检、开发用 mock 都从它派生，不会出现「面板认识、助手不认识」的模块。

## 软件构成

- **单个 Go 静态二进制**：CLI、面板、特权助手、采集器、分流流水线都在里面，前端经 `go:embed` 嵌入。无 CGO、无第三方 DNS 库。
- **mosproxy**：用的是自己维护的 fork（[fa1nes/mosproxy](https://github.com/fa1nes/mosproxy)），修了上游的若干缺陷并加了按分片缓存、乐观缓存等功能。本仓库只按 tag 下载并校验。
- **Unbound**：发行版自带的包。配置模板在仓库的 `unbound/unbound.template.conf`。
- **WireGuard + nftables + 策略路由**：出口分流的落地方式。

二进制只由 GitHub Actions 构建并附 sha256，**生产机不编译**。

## 它不做什么

参考过的托管型权威 DNS 平台有套餐计费、NS 托管、DDoS 清洗、HTTPDNS SDK、全局流量调度等能力。它们解决的是「服务外部客户」的问题，这套家用系统都不需要：

| 平台能力 | 这里的对应 |
|---|---|
| 智能线路解析 | 不做权威，不需要。就近调度交给 CDN 自己，这边负责把 ECS 送到 |
| HTTPDNS（绕过运营商劫持） | 加密入口本身就绕过了运营商的 Local DNS |
| DDoS 防护 | 入口限流 + 访问控制 + 随机 DoH 路径，足够一个家庭网络 |
| 多节点容灾 | 只有一台香港机做降级上游；是否加第二台见 [设计取舍](/intro/tradeoffs) |
