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

```bash
git clone https://github.com/fa1nes/dns-stack.git && cd dns-stack
sudo mkdir -p /etc/dns-stack
sudo cp config.example.env /etc/dns-stack/config.env
sudo vi /etc/dns-stack/config.env     # 至少填 PUBLIC_IPV4 和 DNS_STACK_BINARY_REPO，各项含义见「配置项」
sudo ./install.sh
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

从 `binaries-latest` 下载同一个二进制（静态链接，Alpine 上可以直接运行），放到 `/opt/dns-stack/bin/dns-stack-go`，然后：

```bash
sudo sh install-hk.sh
```

它只做三件事：写 `ROLE=offshore`、加一条每日日志瘦身的 cron、让 Unbound 不依赖开机顺序并由 supervise-daemon 守护。香港 Unbound 需要监听 `10.100.0.3:5335` 并放行 `10.100.0.2`。见 [两台节点](/ops/nodes)。

## 三、设置面板密码

```bash
sudo dns-stack panel-password
```

面板默认只监听 `127.0.0.1:8080`，见 [管理面板](/guide/panel)。

## 四、验收

```bash
sudo dns-stack preflight              # 完整体检，失败项会附排查命令
sudo dns-stack test www.qq.com        # 看一个国内域名怎么走
sudo dns-stack test www.wikipedia.org # 看一个境外域名怎么走
sudo dns-stack cdn-hit                # CDN 是否真的给了大陆节点
```

然后按 [客户端接入](/guide/clients) 配好设备。
