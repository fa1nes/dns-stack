package opsctl

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

const (
	defaultWGPort   = 51820
	hkUnboundConf   = "/etc/unbound/unbound.conf.d/dns-stack.conf"
	handshakeRounds = 10
	handshakeWait   = 2 * time.Second
)

type WGPeerOptions struct {
	Target    string
	Port      int
	Identity  string
	Apply     bool
	CNAddr    string
	HKAddr    string
	Endpoint  string
	TunnelIf  string
	WGConfDir string
}

func (c *Ctl) WGPeer(ctx context.Context, opt WGPeerOptions) error {
	if opt.Target == "" {
		return fmt.Errorf("用法: dns-stack wg-peer root@<HK地址> [--port 22] [--identity 私钥] [--apply]")
	}
	if opt.Port == 0 {
		opt.Port = 22
	}
	if opt.TunnelIf == "" {
		opt.TunnelIf = "wg0"
	}
	if opt.WGConfDir == "" {
		opt.WGConfDir = "/etc/wireguard"
	}
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("缺少 wg 命令: apt-get install wireguard-tools")
	}
	keys := config.ReadKeys(c.ConfigFile, "CN_SERVER_WG_IP", "HK_DNS_WG_IP", "FOREIGN_DNS_WG_IP")
	cnAddr := firstNonEmpty(opt.CNAddr, keys["CN_SERVER_WG_IP"], "10.100.0.2")
	hkAddr := firstNonEmpty(opt.HKAddr, keys["HK_DNS_WG_IP"], keys["FOREIGN_DNS_WG_IP"], "10.100.0.3")
	if _, err := netip.ParseAddr(cnAddr); err != nil {
		return fmt.Errorf("CN 隧道地址无效 %q: %w", cnAddr, err)
	}
	if _, err := netip.ParseAddr(hkAddr); err != nil {
		return fmt.Errorf("HK 隧道地址无效 %q: %w", hkAddr, err)
	}
	wgConf := opt.WGConfDir + "/" + opt.TunnelIf + ".conf"
	ssh := MigrateOptions{Target: opt.Target, Port: opt.Port, Identity: opt.Identity}

	fmt.Fprintf(c.Out, "CN(本机) %s  ↔  HK %s (%s)\n", cnAddr, hkAddr, opt.Target)
	if !opt.Apply {
		c.Warnf("当前是预演模式，不会改动任何一端。确认无误后加 --apply")
	}

	c.Infof("[1/7] 检查 HK 可达与依赖...")
	if _, err := c.sshCapture(ctx, ssh, "command -v wg"); err != nil {
		return fmt.Errorf("HK 上没有 wg 命令，或 SSH 不通: %w", err)
	}
	c.Okf("HK SSH 与 wireguard-tools 就绪")

	c.Infof("[2/7] 取本机密钥...")
	privPath := opt.WGConfDir + "/cn-private.key"
	var private string
	if body, err := os.ReadFile(privPath); err == nil && strings.TrimSpace(string(body)) != "" {
		private = strings.TrimSpace(string(body))
		c.Okf("沿用已有私钥")
	} else {
		private, err = wgGenKey(ctx)
		if err != nil {
			return err
		}
		if opt.Apply {
			if err := os.MkdirAll(opt.WGConfDir, 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(privPath, []byte(private+"\n"), 0o600); err != nil {
				return err
			}
			c.Okf("已生成新私钥 %s", privPath)
		} else {
			c.Warnf("预演：生成的是临时密钥，不落盘")
		}
	}
	public, err := wgPubKey(ctx, private)
	if err != nil {
		return err
	}
	c.Infof("  本机公钥: %s", public)

	c.Infof("[3/7] 取 HK 的公钥与端点...")
	hkPub, _ := c.sshCapture(ctx, ssh, "wg show "+opt.TunnelIf+" public-key 2>/dev/null || true")
	if hkPub == "" {
		hkPub, _ = c.sshCapture(ctx, ssh,
			"test -s /etc/wireguard/hk-private.key && wg pubkey < /etc/wireguard/hk-private.key || true")
	}
	if hkPub == "" {
		return fmt.Errorf("取不到 HK 的 WireGuard 公钥——先确认 HK 上 %s 已配置", opt.TunnelIf)
	}
	endpoint := opt.Endpoint
	if endpoint == "" {
		host := opt.Target
		if at := strings.IndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		listen, _ := c.sshCapture(ctx, ssh, "wg show "+opt.TunnelIf+" listen-port 2>/dev/null || true")
		if listen == "" {
			listen = strconv.Itoa(defaultWGPort)
		}
		endpoint = host + ":" + listen
	}
	c.Okf("HK 公钥 %s  端点 %s", hkPub, endpoint)

	c.Infof("[4/7] 生成本机 %s ...", wgConf)
	conf := fmt.Sprintf(`[Interface]
Address = %s/24
PrivateKey = %s
Table = off

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, cnAddr, private, hkPub, endpoint)

	if !opt.Apply {
		fmt.Fprintf(c.Out, "--- 将写入 %s ---\n", wgConf)
		fmt.Fprint(c.Out, strings.Replace(conf, "PrivateKey = "+private,
			"PrivateKey = <本机私钥，不打印>", 1))
		fmt.Fprintln(c.Out, "--- 将在 HK 上追加的 peer ---")
		fmt.Fprintf(c.Out, "[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", public, cnAddr)
		fmt.Fprintln(c.Out, "--- 将在 HK 的 Unbound 放行 ---")
		fmt.Fprintf(c.Out, "access-control: %s/32 allow\n\n", cnAddr)
		c.Warnf("预演结束，未改动任何一端。确认无误后重跑并加 --apply")
		return nil
	}

	var backup string
	if original, err := os.ReadFile(wgConf); err == nil {
		backup = fmt.Sprintf("%s.bak.%d", wgConf, c.now().Unix())
		if err := os.WriteFile(backup, original, 0o600); err != nil {
			return err
		}
		c.Infof("  已备份原配置到 %s", backup)
	}
	if err := os.WriteFile(wgConf, []byte(conf), 0o600); err != nil {
		return err
	}
	c.Okf("已写入 %s", wgConf)

	rollback := func(reason error) error {
		c.Warnf("正在回滚本机配置...")
		exec.Command("wg-quick", "down", opt.TunnelIf).Run()
		if backup != "" {
			if body, err := os.ReadFile(backup); err == nil {
				os.WriteFile(wgConf, body, 0o600)
			}
			exec.Command("wg-quick", "up", opt.TunnelIf).Run()
			c.Warnf("已恢复到 %s", backup)
		} else {
			os.Remove(wgConf)
			c.Warnf("已移除本次写入的 %s", wgConf)
		}
		return reason
	}

	c.Infof("[5/7] 在 HK 注册本机为 peer ...")
	if err := c.sshRun(ctx, ssh, fmt.Sprintf("wg set %s peer '%s' allowed-ips '%s/32'",
		opt.TunnelIf, public, cnAddr)); err != nil {
		return rollback(fmt.Errorf("HK 上 wg set 失败: %w", err))
	}
	remoteConf := "/etc/wireguard/" + opt.TunnelIf + ".conf"
	c.sshRun(ctx, ssh, fmt.Sprintf(
		"test -f %s && cp -a %s %s.bak.$(date +%%s) || true", remoteConf, remoteConf, remoteConf))
	if err := c.sshRun(ctx, ssh, fmt.Sprintf(
		"grep -q '%s' %s 2>/dev/null || printf '\\n[Peer]\\nPublicKey = %%s\\nAllowedIPs = %%s/32\\n' '%s' '%s' >> %s",
		public, remoteConf, public, cnAddr, remoteConf)); err != nil {
		return rollback(fmt.Errorf("HK 上写入 peer 配置失败: %w", err))
	}
	c.Okf("HK 已接受本机 peer")

	c.Infof("[6/7] 在 HK 的 Unbound 放行本机 ...")
	if _, err := c.sshCapture(ctx, ssh, "test -f "+hkUnboundConf); err != nil {
		c.Warnf("HK 上找不到 %s，请手工确认 access-control 放行了 %s/32", hkUnboundConf, cnAddr)
	} else {
		c.sshRun(ctx, ssh, fmt.Sprintf(
			`grep -q 'access-control: %s/32 allow' %s || sed -i '0,/^\s*access-control:/s//    access-control: %s\/32 allow\n&/' %s`,
			cnAddr, hkUnboundConf, cnAddr, hkUnboundConf))
		if err := c.sshRun(ctx, ssh, "unbound-checkconf >/dev/null"); err != nil {
			return rollback(fmt.Errorf("HK Unbound 配置校验失败，未重载: %w", err))
		}
		c.sshRun(ctx, ssh, "systemctl reload unbound 2>/dev/null || rc-service unbound reload 2>/dev/null || true")
		c.Okf("HK Unbound 已放行 %s/32", cnAddr)
	}

	c.Infof("[7/7] 拉起隧道并验证 ...")
	exec.Command("wg-quick", "down", opt.TunnelIf).Run()
	if err := c.Run(ctx, "wg-quick", "up", opt.TunnelIf); err != nil {
		return rollback(fmt.Errorf("本机隧道启动失败: %w", err))
	}
	if !waitHandshake(ctx, opt.TunnelIf) {
		return rollback(fmt.Errorf(
			"20 秒内没有握手成功——检查 HK 的 %s 是否可达、云安全组是否放行 UDP", endpoint))
	}
	c.Okf("握手成功")

	client, err := resolve.NewClient(hkAddr, resolverPort, 5*time.Second)
	if err != nil {
		return rollback(err)
	}
	answer := client.Query(ctx, "www.wikipedia.org", dnswire.TypeA)
	v4, _ := resolve.Addresses(answer)
	if len(v4) == 0 {
		return rollback(fmt.Errorf(
			"经隧道查 HK 递归器(%s:%d)拿不到答案——检查 HK 的 Unbound access-control", hkAddr, resolverPort))
	}
	c.Okf("经隧道的境外递归正常: www.wikipedia.org -> %s", v4[0])

	for _, pair := range [][2]string{
		{"CN_SERVER_WG_IP", cnAddr}, {"HK_DNS_WG_IP", hkAddr}, {"FOREIGN_DNS_WG_IP", hkAddr},
	} {
		if err := upsertConfig(c.ConfigFile, pair[0], pair[1]); err != nil {
			c.Warnf("写回 %s 失败: %v", pair[0], err)
		}
	}
	c.Okf("config.env 已更新 CN_SERVER_WG_IP / HK_DNS_WG_IP / FOREIGN_DNS_WG_IP")
	fmt.Fprintln(c.Out)
	c.Okf("CN ↔ HK 隧道已对接完成")
	fmt.Fprintln(c.Out, "下一步（分流链路要重建，否则递归出口仍按旧表走）：")
	fmt.Fprintln(c.Out, "  sudo systemctl restart dns-stack-recursive-routing")
	fmt.Fprintln(c.Out, "  sudo dns-stack health")
	return nil
}

func waitHandshake(ctx context.Context, iface string) bool {
	for i := 0; i < handshakeRounds; i++ {
		out, err := exec.CommandContext(ctx, "wg", "show", iface, "latest-handshakes").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "0" {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(handshakeWait):
		}
	}
	return false
}

func wgGenKey(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("生成 WireGuard 私钥失败: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func wgPubKey(ctx context.Context, private string) (string, error) {
	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = strings.NewReader(private)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("推导 WireGuard 公钥失败: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func upsertConfig(path, key, value string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[i] = key + "=" + value
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, key+"="+value)
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0o640)
	if err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), mode)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
