# 快速开始

## 准备

| | 国内节点 | 香港节点 |
|---|---|---|
| 系统 | Debian / Ubuntu（systemd） | Alpine（OpenRC） |
| 内存 | 1GB 以上，推荐 2GB | 512MB 足够 |
| 软件 | `install.sh` 会装好 Unbound、mosproxy、nftables 规则与全部服务 | 自行装好 Unbound 与 WireGuard |
| 网络 | 公网 IPv4；放行 TCP+UDP 443、853 | 能与国内节点建立 WireGuard |

两台机器之间先用 WireGuard 连通：国内 `10.100.0.2`，香港 `10.100.0.3`。国内一侧 `wg0.conf` 里香港 peer 的 `AllowedIPs` 写 `10.100.0.3/32` 即可，分流服务启动时会在运行时把它放开成 `0.0.0.0/0`。如果你直接在文件里写 `0.0.0.0/0`，`[Interface]` 里就必须有 `Table = off`，否则 wg-quick 会把整机默认路由导进隧道——分流服务检测到这种配置会拒绝启动。

## 一、部署国内节点

一条命令：

```bash
curl -fsSL https://github.com/fa1nes/dns-stack/releases/download/binaries-latest/install.sh \
  | sudo PUBLIC_IPV4=203.0.113.10 bash
```

`PUBLIC_IPV4` 是客户端连接的公网地址；不写时安装脚本按出口探测填入并提示核对。其余配置项（`DOH_PATH`、`PANEL_LISTEN`、`ALERT_WEBHOOK`、`DNS_STACK_BINARY_REPO`）也可以这样在 `sudo` 后面给出，没给的保留 `/etc/dns-stack/config.env` 里已有的值，各项含义见 [配置项](/reference/config)。

这份 `install.sh` 发现身边没有安装包内容时，会从同一个 `binaries-latest` 下载 `dns-stack-bundle.tar.gz`（安装脚本、systemd 单元、Unbound 与 mosproxy 模板）和本机架构的二进制，**两者的 sha256 都对上才继续**，然后用解开的那份安装包执行安装。隧道（`10.100.0.2`）已在时先走隧道，再试直连和两个国内镜像；任何一条路连续 20 秒低于 100KB/s 就换下一条——国内直连 GitHub 常见的情形是能连上、但大文件只有几 KB/s。只想先看能不能下载下来：在 `sudo` 后面加 `DNS_STACK_FETCH_ONLY=1`，它校验完就停，不改动这台机器。

也可以照旧从仓库安装，适合要改模板或离线的场合：

```bash
git clone https://github.com/fa1nes/dns-stack.git && cd dns-stack
sudo PUBLIC_IPV4=203.0.113.10 ./install.sh
```

`install.sh` 按 `ROLE=cn-resolver` 部署全部模块，并把面板、采集器、助手都指向同一个 Go 二进制：

- 二进制从 `DNS_STACK_BINARY_REPO` 的 `binaries-latest` 滚动构建下载，核对 sha256（直连失败会经隧道重试）；也可以事先把 `dns-stack-linux-amd64` 放进仓库的 `bin/` 目录。
- mosproxy 从 `MOSPROXY_REPO` 的 Release 下载，版本号、二进制自带的 build-id 与 SHA256 三者互相印证。
- 重复运行是安全的：已有的配置项不会被覆盖，面板里调过的缓存时长也会保留。

::: warning 不要在生产机上编译
构建一律在 GitHub Actions 完成，生产机只下载、校验、替换。安装脚本里没有也不该有 `go build`。自己编译（`CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' ./cmd/dns-stack`）请在别的机器上做，再放进 `bin/`。
:::

安装结束时会打印 DoH 接入地址。`DOH_PATH` 留空时，安装脚本会生成一个随机私密路径。

### 证书

安装时如果还没有证书，会先放一张自签证书占位。要对外服务，需要用 acme.sh 为公网 IP 签发 Let's Encrypt 的 IP 证书，然后：

```bash
sudo dns-stack cert-renew
sudo dns-stack cert-check
```

此后续签由例行维护自动完成，见 [证书](/ops/certificates)。

## 二、部署香港节点

```bash
curl -fsSL https://github.com/fa1nes/dns-stack/releases/download/binaries-latest/install-hk.sh | sh
```

（Alpine 没装 curl 时用 `wget -qO- <同一地址> | sh`。）它先从 `binaries-latest` 取本机架构的二进制（静态链接，Alpine 上直接运行），sha256 对上才放到 `/opt/dns-stack/bin/dns-stack-go`，旧版留作 `dns-stack-go.prev`；下载失败而本机已有二进制时继续用旧的。然后只做三件事：写 `ROLE=offshore`、加一条每日日志瘦身的 cron、让 Unbound 不依赖开机顺序并由 supervise-daemon 守护。重复运行就是升级。香港 Unbound 需要监听 `10.100.0.3:5335` 并放行 `10.100.0.2`。见 [两台节点](/ops/nodes)。

## 三、登录管理面板

面板监听公网地址（`PANEL_LISTEN` 不是 `127.0.0.1`）且还没有设过密码时，`install.sh` 会生成一个随机的初始账号 `admin` 和 20 位密码，在安装结束时连同面板地址打印一次（只显示这一次）。登录后在「账号」页改掉，或者在服务器上：

```bash
sudo dns-stack panel-password
```

面板默认只监听 `127.0.0.1:8080`，这时不生成密码，经 SSH 隧道访问即可，见 [管理面板](/guide/panel)。

## 四、验收

```bash
sudo dns-stack preflight              # 完整体检，失败项会附排查命令
sudo dns-stack test www.qq.com        # 看一个国内域名怎么走
sudo dns-stack test www.wikipedia.org # 看一个境外域名怎么走
sudo dns-stack cdn-hit                # CDN 是否真的给了大陆节点
```

然后按 [客户端接入](/guide/clients) 配好设备。

## 升级

代码合进 `main`、CI 的 `build`（含 scale-gate）全绿后，`binaries-latest` 就是新版本。最省事的是在面板「系统」页点「检查更新」→「升级」，流程和下面的命令完全一样。也可以在国内节点上：

```bash
sudo dns-stack upgrade --check   # 只下载并报出新版本号，不替换
sudo dns-stack upgrade           # 替换并重启面板与管理助手
sudo dns-stack preflight
```

`upgrade` 先取 `.sha256`，二进制下载后校验和对不上就不替换（取不到校验和也不替换）；下载 GitHub 时先走隧道、失败再直连。替换前把当前二进制备份到 `/var/backups/dns-stack/dns-stack-go.pre-<时间>`，原子替换后重启 `--restart` 指定的服务（默认 `dns-stack-helper,dns-stack-panel`），3 秒后任何一个没在运行就自动换回旧二进制再重启一次。

mosproxy 用同一个命令升级：

```bash
sudo dns-stack upgrade --mosproxy --check
sudo dns-stack upgrade --mosproxy
```

它取 `versions.lock` 里那个 mosproxy fork 的最新 Release，sha256、`.build-id` 与二进制自报的版本三者对上才替换，旧版带着元数据备份成 `mosproxy-pre-<新版本>-<时间>`；重启后用 DoH 自检，不通就换回旧版。重启期间解析中断约 0.1 秒（2026-10-19 升级 v0.2.3 实测），内存缓存随之清空。

查询采集器跑在 `mosproxy.service` 里，默认不重启它——重启时解析中断约 0.1 秒，但内存缓存会清空，之后一段时间的查询都要重新递归。需要采集器立刻用上新代码时写 `--restart dns-stack-helper,dns-stack-panel,mosproxy`。改动涉及 `systemd/` 单元、Unbound / mosproxy 模板时，`upgrade` 不够，重新跑一遍上面那条安装命令（已有配置与面板调过的值都会保留）。香港节点不用 `upgrade`：重新跑一遍香港那条安装命令就是升级。
