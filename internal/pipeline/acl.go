package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

const (
	ACLChain   = "dns_acl"
	ACLSet4    = "acl_allowed4"
	ACLSet6    = "acl_allowed6"
	tunnelCIDR = "10.100.0.0/24"
)

type ACLConfig struct {
	Table    string
	DoHPort  int
	DoTPort  int
	Prefixes []netip.Prefix
}

func (c ACLConfig) ports() string {
	seen := map[int]struct{}{}
	var list []string
	for _, port := range []int{c.DoHPort, c.DoTPort} {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		list = append(list, fmt.Sprint(port))
	}
	return strings.Join(list, ", ")
}

func (c ACLConfig) split() (v4, v6 []string) {
	for _, prefix := range c.Prefixes {
		if !prefix.IsValid() {
			continue
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	return v4, v6
}

func (c ACLConfig) Render() (string, error) {
	ports := c.ports()
	if ports == "" {
		return "", fmt.Errorf("没有可保护的端口，检查 DOH_PORT / DOT_PORT")
	}
	v4, v6 := c.split()
	if len(v4) == 0 && len(v6) == 0 {
		return "", fmt.Errorf("授权网段为空——空的白名单会把所有客户端挡在外面，拒绝下发")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", c.Table)
	fmt.Fprintf(&b, "add set inet %s %s { type ipv4_addr; flags interval; auto-merge; }\n", c.Table, ACLSet4)
	fmt.Fprintf(&b, "flush set inet %s %s\n", c.Table, ACLSet4)
	for start := 0; start < len(v4); start += nftChunk {
		end := min(start+nftChunk, len(v4))
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", c.Table, ACLSet4, strings.Join(v4[start:end], ", "))
	}
	fmt.Fprintf(&b, "add set inet %s %s { type ipv6_addr; flags interval; auto-merge; }\n", c.Table, ACLSet6)
	fmt.Fprintf(&b, "flush set inet %s %s\n", c.Table, ACLSet6)
	for start := 0; start < len(v6); start += nftChunk {
		end := min(start+nftChunk, len(v6))
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", c.Table, ACLSet6, strings.Join(v6[start:end], ", "))
	}

	fmt.Fprintf(&b, "add chain inet %s %s { type filter hook input priority filter; policy accept; }\n", c.Table, ACLChain)
	fmt.Fprintf(&b, "flush chain inet %s %s\n", c.Table, ACLChain)
	fmt.Fprintf(&b, "add rule inet %s %s iif lo accept\n", c.Table, ACLChain)
	fmt.Fprintf(&b, "add rule inet %s %s ip saddr %s accept\n", c.Table, ACLChain, tunnelCIDR)
	fmt.Fprintf(&b, "add rule inet %s %s ct state established,related accept\n", c.Table, ACLChain)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add rule inet %s %s meta l4proto { tcp, udp } th dport { %s } ip saddr @%s accept\n",
			c.Table, ACLChain, ports, ACLSet4)
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add rule inet %s %s meta l4proto { tcp, udp } th dport { %s } ip6 saddr @%s accept\n",
			c.Table, ACLChain, ports, ACLSet6)
	}
	fmt.Fprintf(&b, "add rule inet %s %s meta l4proto { tcp, udp } th dport { %s } counter drop\n",
		c.Table, ACLChain, ports)
	return b.String(), nil
}

func (c ACLConfig) Apply(ctx context.Context) error {
	script, err := c.Render()
	if err != nil {
		return err
	}
	return nftRun(ctx, script)
}

func ACLDisable(ctx context.Context, table string) error {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "delete", "chain", "inet", table, ACLChain).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("删除访问控制链失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ACLInstalled(ctx context.Context, table string) bool {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "list", "chain", "inet", table, ACLChain).Run() == nil
}

func ACLStatus(ctx context.Context, table string) (string, error) {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", "inet", table, ACLChain).Output()
	return string(out), err
}
