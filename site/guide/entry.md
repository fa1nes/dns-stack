# 加密入口

设备只通过加密协议访问 dns-stack。入口是国内节点上的 mosproxy（自维护的 fork），配置由 `install.sh` 从仓库的 `mosproxy/config.template.yaml` 渲染到 `/etc/dns-stack/mosproxy/config.yaml`。

## 监听

| 协议 | 端口 | 传输 |
|---|---|---|
| DoH（HTTP/2） | `DOH_PORT`，默认 443 | TCP |
| DoH3（HTTP/3） | `DOH_PORT`，默认 443 | UDP（QUIC） |
| DoT | `DOT_PORT`，默认 853 | TCP |
| DoQ | `DOT_PORT`，默认 853 | UDP（QUIC） |

没有明文 53 端口。四个入口共用同一张 TLS 证书（见 [证书](/ops/certificates)）。

## 私密 DoH 路径

DoH 的路径不是默认的 `/dns-query`，而是安装时随机生成的 128 位路径，例如 `/<32 位十六进制>/dns-query`。

原因：IP 证书会进入证书透明度（CT）公开日志，「这个 IP 上有 TLS 服务」是公开可查的。扫描器拿到 IP 后固定去探 `/dns-query`，探到就能把你的服务器当免费公共 DNS 用。换成随机路径后，任何人探到的都是 404，和一个空的 web 服务器没有区别。路径在 TLS 内部传输，中间人也看不到。

```bash
sudo dns-stack doh-path            # 打印完整接入地址
sudo dns-stack doh-path --rotate   # 换一个新的随机路径
```

轮换会先改配置、重启 mosproxy，再用新路径真实查询一次；自验失败就回滚到原配置。换完之后**所有客户端都要同步更新**，旧地址立即失效。面板里也有「轮换私密路径」按钮，效果相同。

自检会检查路径是否还是默认的 `/dns-query`：那等于对外开放一个公共解析器。

## 请求怎么被处理

mosproxy 对每个查询按顺序匹配规则：

| 顺序 | 条件 | 动作 |
|---|---|---|
| 1 | 命中 `blocklist.txt` | 直接回 NXDOMAIN，不发起递归 |
| 2 | 命中 `manual-exclude.txt` | 交给递归负载均衡（本机 Unbound 优先） |
| 3 | 命中 `manual-gfw.txt` | 只交给香港 Unbound |
| 4 | 其余全部 | 交给递归负载均衡 |

递归负载均衡是 `fall_through`：先问本机 Unbound，超时或故障就落到香港 Unbound。两个上游都有健康检查（`ping_interval: 30`、`max_fails: 5`），离线的上游会被跳过，并在面板、自检和告警里出现。

三份清单都在 `/var/lib/dns-stack/` 下，按域匹配：写 `example.com` 就覆盖它的全部子域。

## 限流

入口带一个限流中间件：并发上限和每秒查询上限按 CPU 核数计算（每核 250 并发、1000 QPS），用来挡住单个失控客户端，不是为了防御攻击。被限流的请求会计入 mosproxy 指标，自检把非 0 的拒绝计数当成异常——它意味着正在拒绝服务。

## 去掉 ECH

mosproxy 会从 HTTPS 记录里去掉 ECH 配置。带 ECH 时，代理软件看不到真实的 SNI，按域名的分流规则一条都匹配不上，流量会静默落到默认出站——而解析成功、握手成功、网页打得开，很难发现。

## 指标

mosproxy 在 `127.0.0.1:8888/metrics` 暴露 Prometheus 格式的指标：各上游的成功率、延迟直方图、在线状态、限流拒绝计数。面板、自检和看门狗都从这里读。
