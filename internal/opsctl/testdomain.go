package opsctl

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/resolve"
	"github.com/dns-stack/dns-stack/internal/stack"
)

const (
	localResolver    = "127.0.0.1"
	remoteResolver   = stack.HKTunnelIP
	resolverPort     = stack.UnboundPort
	queryTimeout     = 4 * time.Second
	maxAuthoritiesNS = 4
)

var domainRe = regexp.MustCompile(`^[a-z0-9.-]+$`)

type manualRule struct {
	file, label, route string
	local              bool
}

var (
	blockRule   = manualRule{"blocklist.txt", "拦截名单", "直接回答不存在，不发起任何查询", false}
	cnRule      = manualRule{"manual-cn-zones.txt", "国内解析名单", "本机递归，权威直连并带上客户端子网", true}
	excludeRule = manualRule{"manual-exclude.txt", "移出香港名单", "本机递归", true}
	hkRule      = manualRule{"manual-gfw.txt", "香港解析名单", "香港递归", false}
)

func (c *Ctl) TestDomain(ctx context.Context, domain, subnet string) error {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return fmt.Errorf("用法: dns-stack test <域名> [客户端子网]")
	}
	if !domainRe.MatchString(domain) {
		return fmt.Errorf("域名格式非法")
	}
	var ecs netip.Prefix
	note := ""
	if subnet != "" {
		parsed, err := netip.ParsePrefix(subnet)
		if err != nil {
			return fmt.Errorf("客户端子网格式应为 a.b.c.0/24: %w", err)
		}
		ecs = parsed
		note = fmt.Sprintf("（模拟客户端子网 %s）", ecs)
	}
	fmt.Fprintf(c.Out, "正在测试域名: %s%s\n", domain, note)

	rule, suffix := c.matchManualRule(domain)
	if rule.file != "" {
		fmt.Fprintf(c.Out, "  规则判定: %s (%s) -> %s\n", rule.label, suffix, rule.route)
	} else {
		fmt.Fprintln(c.Out, "  规则判定: 不在任何名单 -> 本机递归，每台权威按所在位置选直连或隧道")
	}
	if rule.file == "" || rule.local {
		c.explainRouting(ctx, domain, ecs)
	}

	cdnSet, _ := cdnrules.Load(cdnrules.Path(c.StateDir))
	localNote, remoteNote := "  ← 实际拿到的结果", "  ← 对比用"
	switch rule {
	case hkRule:
		localNote, remoteNote = "  ← 对比用", "  ← 实际拿到的结果"
	case blockRule:
		localNote, remoteNote = "  ← 对比用，实际被拦截", "  ← 对比用，实际被拦截"
	}
	fmt.Fprintln(c.Out, "  本机 Unbound 视角(A/AAAA/CNAME/HTTPS)"+localNote+":")
	c.dumpViews(ctx, localResolver, domain, ecs, cdnSet)
	fmt.Fprintln(c.Out, "  香港 Unbound 视角(A/AAAA/CNAME/HTTPS)"+remoteNote+":")
	c.dumpViews(ctx, remoteResolver, domain, netip.Prefix{}, cdnSet)

	if client, err := resolve.NewClient(localResolver, resolverPort, queryTimeout); err == nil {
		start := time.Now()
		client.Query(ctx, domain, dnswire.TypeA)
		fmt.Fprintf(c.Out, "  查询耗时: %dms\n", time.Since(start).Milliseconds())
	}
	return nil
}

func (c *Ctl) matchManualRule(domain string) (manualRule, string) {
	match := func(rule manualRule) string {
		for suffix := domain; suffix != ""; {
			if fileHasLine(c.state(rule.file), suffix) {
				return suffix
			}
			dot := strings.IndexByte(suffix, '.')
			if dot < 0 {
				break
			}
			suffix = suffix[dot+1:]
		}
		return ""
	}
	if hit := match(blockRule); hit != "" {
		return blockRule, hit
	}
	excluded := match(excludeRule)
	if excluded == "" {
		if hit := match(hkRule); hit != "" {
			return hkRule, hit
		}
	}
	if hit := match(cnRule); hit != "" {
		return cnRule, hit
	}
	if excluded != "" {
		return excludeRule, excluded
	}
	return manualRule{}, ""
}

func (c *Ctl) explainRouting(ctx context.Context, domain string, ecs netip.Prefix) {
	if c.Role() != stack.RoleCNResolver {
		return
	}
	client, err := resolve.NewClient(localResolver, resolverPort, queryTimeout)
	if err != nil {
		return
	}
	zone := registrableGuess(domain)
	fmt.Fprintf(c.Out, "    注册域: %s\n", zone)
	servesCN := false
	answer := client.Query(ctx, zone, dnswire.TypeNS)
	names := resolve.TargetNames(answer, dnswire.TypeNS)
	if len(names) > maxAuthoritiesNS {
		names = names[:maxAuthoritiesNS]
	}
	for _, ns := range names {
		v4, _ := resolve.Addresses(client.Query(ctx, ns, dnswire.TypeA))
		if len(v4) == 0 {
			continue
		}
		addr := v4[0]
		label := c.geoLabel(ctx, addr)
		switch {
		case c.inNFTSet(ctx, "direct4", addr):
			fmt.Fprintf(c.Out, "    权威 %s (%s)%s 在大陆 -> 直连\n", strings.TrimSuffix(ns, "."), addr, label)
			servesCN = true
		case c.inNFTSet(ctx, "cn_authority", addr):
			fmt.Fprintf(c.Out, "    权威 %s (%s)%s 在国内权威表 -> 直连\n", strings.TrimSuffix(ns, "."), addr, label)
			servesCN = true
		default:
			fmt.Fprintf(c.Out, "    权威 %s (%s)%s 在境外 -> 经隧道\n", strings.TrimSuffix(ns, "."), addr, label)
		}
	}
	final, _ := resolve.Addresses(c.queryMaybeECS(ctx, client, domain, dnswire.TypeA, ecs))
	if len(final) == 0 {
		return
	}
	addr := final[0]
	label := c.geoLabel(ctx, addr)
	if c.inNFTSet(ctx, "direct4", addr) {
		fmt.Fprintf(c.Out, "    解析结果 %s%s -> 大陆节点\n", addr, label)
		return
	}
	fmt.Fprintf(c.Out, "    解析结果 %s%s -> 境外节点\n", addr, label)
	if !ecs.IsValid() && servesCN {
		fmt.Fprintln(c.Out, "      ↑ 本机自查不带客户端子网(ECS)，按省调度的域名在这里会显示默认节点。")
		fmt.Fprintln(c.Out, "        要看主人实际会拿到什么，带上运营商网段再跑一次，例如：")
		fmt.Fprintf(c.Out, "        dns-stack test %s 219.141.136.0/24   # 电信\n", domain)
		fmt.Fprintf(c.Out, "        dns-stack test %s 123.125.0.0/24     # 联通\n", domain)
	}
}

func (c *Ctl) dumpViews(ctx context.Context, server, domain string, ecs netip.Prefix, cdnSet *cdnrules.Set) {
	client, err := resolve.NewClient(server, resolverPort, queryTimeout)
	if err != nil {
		fmt.Fprintf(c.Out, "    (解析器地址无效: %v)\n", err)
		return
	}
	for _, qtype := range []uint16{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCNAME, dnswire.TypeHTTPS} {
		fmt.Fprintf(c.Out, "    [%s]\n", dnswire.TypeName(qtype))
		answer := c.queryMaybeECS(ctx, client, domain, qtype, ecs)
		v4, v6 := resolve.Addresses(answer)
		printed := false
		for _, addr := range append(append([]netip.Addr(nil), v4...), v6...) {
			fmt.Fprintf(c.Out, "      %-40s%s%s\n", addr, c.geoLabel(ctx, addr), cdnNote(cdnSet, domain, addr))
			printed = true
		}
		for _, name := range resolve.TargetNames(answer, qtype) {
			fmt.Fprintf(c.Out, "      %s\n", name)
			printed = true
		}
		if !printed {
			fmt.Fprintln(c.Out, "      (无记录)")
		}
	}
}

func (c *Ctl) queryMaybeECS(ctx context.Context, client *resolve.Client, domain string, qtype uint16, ecs netip.Prefix) resolve.Answer {
	if !ecs.IsValid() {
		return client.Query(ctx, domain, qtype)
	}
	return client.QueryWithSubnet(ctx, domain, qtype, ecs)
}

func cdnNote(set *cdnrules.Set, domain string, addr netip.Addr) string {
	if set == nil {
		return ""
	}
	d := set.Classify(domain, addr)
	if d.Verdict == cdnrules.VerdictUnknown {
		if owner, _, mainland, ok := set.Owner(addr); ok {
			where := "境外"
			if mainland {
				where = "大陆"
			}
			return fmt.Sprintf(" [%s %s节点]", owner.Name, where)
		}
		return ""
	}
	return fmt.Sprintf(" [%s]", d.Verdict.Label())
}

func (c *Ctl) geoLabel(ctx context.Context, addr netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.GoBin, "geoip-check", addr.String()).Output()
	if err != nil {
		return ""
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "\t")
	if len(fields) < 2 || fields[1] == "" {
		return ""
	}
	return " [" + fields[1] + "]"
}

func (c *Ctl) inNFTSet(ctx context.Context, set string, addr netip.Addr) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "get", "element", "inet",
		"dns_route", set, "{ "+addr.String()+" }").Run() == nil
}

func registrableGuess(domain string) string {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return domain
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func fileHasLine(path, want string) bool {
	body, err := readLinesFile(path)
	if err != nil {
		return false
	}
	for _, line := range body {
		before, _, _ := strings.Cut(line, "#")
		if fields := strings.Fields(before); len(fields) > 0 && strings.EqualFold(strings.TrimSuffix(fields[0], "."), want) {
			return true
		}
	}
	return false
}

func readLinesFile(path string) ([]string, error) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, nil
}
