# 域名黑名单

命中黑名单的查询由 mosproxy 直接回 **NXDOMAIN**，连递归都不发生，也不会离开本机。

## 文件

`/var/lib/dns-stack/blocklist.txt`

- 每行一个域名，**匹配它的全部子域**：写 `example.com` 就同时挡住 `www.example.com`、`a.b.example.com`。
- 写入时统一转小写、去掉末尾的点，去重并排序。
- 不接受裸顶级域（例如 `com`），格式非法的名字会被拒绝。
- `#` 开头的行是注释。文件由命令和面板维护，写入是原子的。

## 命令

```bash
sudo dns-stack blocklist                 # 列出（等同 list）
sudo dns-stack blocklist add ads.example.com tracker.example.net
sudo dns-stack blocklist remove ads.example.com
```

`add` / `remove` 之后会立即通知 mosproxy 重载域名表，改动即刻生效。加 `--no-reload` 只改文件，下次 `dns-stack reload` 时生效。

重载失败（例如 mosproxy 正在重启）只会打印警告，文件改动不会丢。

## 面板

「设置 → 域名规则 → 拦截」里可以加入、移出域名。黑名单只在国内节点上存在，面板和特权助手会拒绝其它角色的这类操作。

## 怎么确认生效

```bash
sudo dns-stack query-log --kind blocked --since 1h
```

被拦截的查询在查询日志里的递归类型是「域名黑名单」。

::: tip 与「分流规则」的区别
黑名单回答的是「这个名字要不要解析」，不改变解析走哪条路。想让某个域名换出口，见 [出口分流](/guide/routing#人工干预)。
:::
