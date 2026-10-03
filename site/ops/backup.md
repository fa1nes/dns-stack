# 备份与迁移

## 自动备份

例行维护默认每天做一次备份，写到 `/var/backups/dns-stack/`：

- 间隔由 `BACKUP_INTERVAL_HOURS` 决定（默认 24，`0` 关闭）；
- 距上一份周备份满 6.5 天的那次自动备份存成 `weekly-<时间>.tar.zst`，其余是 `daily-<时间>.tar.zst`。不再看是不是周日——每 3 天或每周备份一次时，可能永远碰不上周日；
- 默认保留最近 3 份日备份、2 份周备份（`BACKUP_RETENTION_DAILY`、`BACKUP_RETENTION_WEEKLY`），超出的在每次备份之后删掉；手动备份算日备份；
- 剩余空间不足 500MB 时不备份。

这三项都能在面板「设置 → 维护 → 备份」里直接改，写回 `config.env`，下一轮例行维护生效。

内容：`config.env`、Unbound 与 mosproxy 的配置、systemd 单元、版本锁；国内节点还包括查询数据库（用 `VACUUM INTO` 做一致性快照）和迁移数据。每个包带清单与 SHA256 校验。**自动备份不含任何密钥**。

```bash
sudo dns-stack backup                    # 立即备份
sudo dns-stack backup --include-secrets  # 连密钥一起，强制 age 加密
sudo dns-stack list-packages             # 列出所有备份与导出包
sudo dns-stack verify [包]               # 只读校验：解密、解包、核对 SHA256、读清单
```

## 迁移包

```bash
sudo dns-stack export --mode full        # config / state / full，full 含密钥
sudo dns-stack import <包>               # 导入到本机（会覆盖数据，高危）
```

导出包一律用 age 加密，放在 `/srv/dns-stack/export/`，旁边带一个 `.sha256`。加密身份文件在 `/etc/dns-stack/secrets/backup-age-identity.txt`，第一次导出时自动生成——**换机器时要一起带走，否则解不开**。

导入时：

- 角色必须一致；架构不一致只警告；
- 先给本机做一份导入前备份，失败可以回滚；
- `config.env` 是**合并**而不是覆盖：新机器的 `PUBLIC_IPV4` / `PUBLIC_IPV6` 保持不变，原文件另存为 `config.env.imported`。

面板「设置 → 维护 → 迁移」导出的是另一种迁移数据包：按清单白名单导出、**一条密钥都不含**，并且显式列出每个排除项和理由。用 `dns-stack migration-restore --bundle <包>` 恢复，支持 `--dry-run`。

## 一键迁移到新服务器

```bash
sudo dns-stack migrate root@<新服务器> --dry-run   # 先预演：只做检查
sudo dns-stack migrate root@<新服务器>
```

依次：检查 SSH → 检查新机系统（Debian / Ubuntu）与架构 → 检查空间（≥ 2GB）→ 确认新机还没装过 → 本机带密钥备份 → 把包、安装文件、二进制传过去 → 在新机上运行 `install.sh` → 校验并导入 → 在新机上跑健康检查。

**旧服务器全程保持运行。** 确认新机没问题之后，在旧服务器上执行：

```bash
sudo dns-stack migration-finish   # 停掉旧机上的服务并关掉例行维护，不删数据
```

迁移之后还要做两件事：确认 `config.env` 里的公网 IP，按新 IP 重新签发证书。

## 数据库结构升级

```bash
sudo dns-stack db-migrate
```

先停掉面板与 mosproxy，把所有数据库快照到 `/var/backups/dns-stack/schema-migration-<时间>/`，再按当前 schema 就地迁移、做完整性检查，最后把服务拉起来。迁移代码要用真实的旧库验证过才能上线——这里吃过「迁移脚本写死了旧库里不存在的列」的亏。
