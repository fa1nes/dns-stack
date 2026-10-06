package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/stack"
)

const (
	ACLTable   = stack.ACLTable
	aclChain   = "input"
	aclSet4    = "allowed4"
	aclSet6    = "allowed6"
	tunnelCIDR = stack.TunnelCIDR
)

type ACLConfig struct {
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
	fmt.Fprintf(&b, "add table inet %s\n", ACLTable)
	fmt.Fprintf(&b, "delete table inet %s\n", ACLTable)
	fmt.Fprintf(&b, "add table inet %s\n", ACLTable)
	for _, set := range []struct {
		name, family string
		prefixes     []string
	}{{aclSet4, "ipv4_addr", v4}, {aclSet6, "ipv6_addr", v6}} {
		fmt.Fprintf(&b, "add set inet %s %s { type %s; flags interval; auto-merge; }\n", ACLTable, set.name, set.family)
		for start := 0; start < len(set.prefixes); start += nftChunk {
			end := min(start+nftChunk, len(set.prefixes))
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", ACLTable, set.name, strings.Join(set.prefixes[start:end], ", "))
		}
	}
	fmt.Fprintf(&b, "add chain inet %s %s { type filter hook input priority filter; policy accept; }\n", ACLTable, aclChain)
	rule := func(format string, args ...any) {
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", ACLTable, aclChain, fmt.Sprintf(format, args...))
	}
	rule("iif lo accept")
	rule("ip saddr %s accept", tunnelCIDR)
	rule("ct state established,related accept")
	if len(v4) > 0 {
		rule("meta l4proto { tcp, udp } th dport { %s } ip saddr @%s accept", ports, aclSet4)
	}
	if len(v6) > 0 {
		rule("meta l4proto { tcp, udp } th dport { %s } ip6 saddr @%s accept", ports, aclSet6)
	}
	rule("meta l4proto { tcp, udp } th dport { %s } counter drop", ports)
	return b.String(), nil
}

func (c ACLConfig) Apply(ctx context.Context) error {
	script, err := c.Render()
	if err != nil {
		return err
	}
	return nftRun(ctx, script)
}

func ACLDisable(ctx context.Context) error {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", ACLTable).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("删除访问控制表失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ACLInstalled(ctx context.Context) bool {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "list", "chain", "inet", ACLTable, aclChain).Run() == nil
}

func ACLStatus(ctx context.Context) (string, error) {
	ctx, cancel := contextWithNFTTimeout(ctx)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", "inet", ACLTable, aclChain).Output()
	return string(out), err
}

func ACLFromConfig(cfg Config, prefixes []netip.Prefix) ACLConfig {
	return ACLConfig{DoHPort: cfg.Int("DOH_PORT", 443), DoTPort: cfg.Int("DOT_PORT", 853), Prefixes: prefixes}
}

func RestoreACL(ctx context.Context, cfg Config) (bool, error) {
	prefixes, err := access.Store{StateDir: cfg.StateDir}.EnforcedACL()
	if err != nil {
		return false, err
	}
	if len(prefixes) == 0 || ACLInstalled(ctx) {
		return false, nil
	}
	return true, ACLFromConfig(cfg, prefixes).Apply(ctx)
}
