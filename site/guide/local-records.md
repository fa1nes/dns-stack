# 本地记录

给内网设备或测试环境写死地址：查询 `nas.home.arpa` 时由国内节点的 Unbound 直接回答你填的 IP，不发起递归。

## 规则

- 只有 **A / AAAA** 两种类型。面板按地址自动判断：带 `:` 的是 AAAA。
- **只管这个名字本身**：写了 `nas.home.arpa`，`a.nas.home.arpa` 照常解析。
- 名字下没写的类型回「无记录」（NOERROR/NODATA）：只写了 A，AAAA 查询就是空答案，不会再去公网解析出别的地址。
- TTL 固定 300 秒。
- 被拦截名单或香港解析名单截走的名字到不了本机 Unbound，添加时会直接拒绝，提示先把它移出那份名单。

## 文件

- 名单：`/var/lib/dns-stack/local-records.txt`，每行「域名 类型 值」。
- Unbound 配置：`/etc/unbound/unbound.conf.d/dns-stack-local.conf`，由命令根据名单生成，手改会被覆盖。

## 命令

```bash
sudo dns-stack local-record                                   # 列出（等同 list）
sudo dns-stack local-record add nas.home.arpa A 192.168.1.2
sudo dns-stack local-record add nas.home.arpa AAAA fd00::2
sudo dns-stack local-record remove nas.home.arpa AAAA         # 只删 AAAA
sudo dns-stack local-record remove nas.home.arpa              # 删这个名字的全部记录
sudo dns-stack local-record sync                              # 按名单重写配置并推给 Unbound（迁移恢复后用）
```

每次改动先写出新配置并跑 `unbound-checkconf`，不过就换回旧文件、撤回名单。通过后用 `unbound-control local_data` 把这个名字的记录推进运行中的 Unbound，**不重载**——重载会清掉 ECS 子网缓存。最后清掉 mosproxy 里这个名字的缓存，改动即刻生效。

## 面板

「设置 → 域名规则 → 本地记录」里可以添加、删除。和其它域名规则一样只在国内节点上存在。

## 怎么确认生效

```bash
dig @127.0.0.1 -p 5335 nas.home.arpa A +short
sudo dns-stack test nas.home.arpa        # 规则判定下面会列出本地记录
```
