package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultRouteTable   = "100"
	DefaultUnboundUser  = "unbound"
	DefaultEndpointSet  = "tunnel_endpoints"
	DefaultFailMode     = "closed"
	tunnelSubnet        = "10.100.0.0/24"
	hkPeerAllowedIP     = "10.100.0.3/32"
	openAllowedIPs      = "0.0.0.0/0"
	rulePriorityFrom    = "100"
	rulePriorityFWMark  = "101"
	rulePriorityProhib  = "102"
	ruleDeleteMaxRounds = 10
)

type RoutingConfig struct {
	Config      Config
	RouteTable  string
	FWMark      string
	UnboundUser string
	WGConf      string
	FailMode    string
	MinEntries  int
	EndpointSet string
	CachedNFT   string
}

func LoadRoutingConfig(cfg Config) RoutingConfig {
	rc := RoutingConfig{
		Config:      cfg,
		RouteTable:  pick(cfg.Value("ROUTE_TABLE"), DefaultRouteTable),
		FWMark:      pick(cfg.Value("FWMARK"), DefaultFWMark),
		UnboundUser: pick(cfg.Value("UNBOUND_USER"), DefaultUnboundUser),
		FailMode:    pick(cfg.Value("TUNNEL_FAIL_MODE"), DefaultFailMode),
		MinEntries:  cfg.Int("MIN_SET_ENTRIES", DefaultMinSetEntries),
		EndpointSet: pick(cfg.Value("NFT_ENDPOINT_SET"), DefaultEndpointSet),
		CachedNFT:   cfg.Chnroute("direct4.nft"),
	}
	rc.WGConf = pick(cfg.Value("WG_CONF"), "/etc/wireguard/"+cfg.TunnelIf+".conf")
	return rc
}

func (rc RoutingConfig) ipRuleShow(ctx context.Context) string {
	out, _ := run(ctx, "ip", "rule", "show")
	return out
}

func (rc RoutingConfig) ruleExists(ctx context.Context, fragment string) bool {
	return strings.Contains(rc.ipRuleShow(ctx), fragment)
}

func (rc RoutingConfig) inSet(ctx context.Context, addr string) bool {
	_, err := run(ctx, "nft", "get", "element", "inet",
		rc.Config.NFTTable, rc.Config.DirectSet, "{ "+addr+" }")
	return err == nil
}

func (rc RoutingConfig) Apply(ctx context.Context, rt *Runtime) error {
	for _, tool := range []string{"nft", "wg", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("缺少 %s 命令", tool)
		}
	}
	if _, err := run(ctx, "ip", "link", "show", rc.Config.TunnelIf); err != nil {
		return fmt.Errorf("隧道接口 %s 不存在", rc.Config.TunnelIf)
	}
	account, err := user.Lookup(rc.UnboundUser)
	if err != nil {
		return fmt.Errorf("找不到用户 %s: %w", rc.UnboundUser, err)
	}
	rt.Infof("Unbound 运行用户 %s (uid=%s)", rc.UnboundUser, account.Uid)

	if err := rc.applyPolicyRoutes(ctx, rt); err != nil {
		return err
	}
	if err := rc.guardWireGuardConf(); err != nil {
		return err
	}
	if err := rc.openHKPeer(ctx, rt); err != nil {
		return err
	}

	rc.ensureSetLoaded(ctx, rt)
	entries := rt.NFTSetCount(ctx, rc.Config.DirectSet)
	if entries < rc.MinEntries {
		return fmt.Errorf("直连集合仅 %d 条（要求 ≥ %d），拒绝安装分流链。"+
			"集合过小会把国内递归查询也全导进隧道，请先执行 dns-stack routing-data --only chnroute --force",
			entries, rc.MinEntries)
	}
	rt.Infof("直连集合约 %d 条，校验语义", entries)
	if err := rc.verifySetSemantics(ctx, rt); err != nil {
		return fmt.Errorf("%w（请先执行 dns-stack routing-data --only chnroute --force）", err)
	}

	endpoints := rc.tunnelEndpoints(ctx)
	if len(endpoints) == 0 {
		rt.Warnf("未取到隧道端点地址，跳过端点保护")
	} else {
		rt.Infof("隧道端点保护：%s", strings.Join(endpoints, ", "))
	}
	authority := rc.cnAuthorityEntries()
	if len(authority) == 0 {
		rt.Infof("无历史墙内权威记录，集合留空（等 timer 生成）")
	}

	script := rc.renderChainScript(account.Uid, endpoints, authority)
	if rt.Preview {
		fmt.Fprint(rt.Out, script)
		return nil
	}
	if err := nftRun(ctx, script); err != nil {
		return err
	}
	if len(authority) > 0 {
		rt.Infof("墙内权威集合已从历史记录恢复（%d 条）", len(authority))
	}
	rt.Infof("分流链已安装（正向匹配 uid=%s）", account.Uid)
	rt.Infof("源地址改写已安装（出隧道包 → %s）", rc.Config.TunnelAddr)
	rt.Infof("递归出口分流已生效")
	rt.Infof("  大陆目标 → 直连出网")
	rt.Infof("  境外目标 → 隧道 %s 出网（经香港 NAT）", rc.Config.TunnelIf)
	rt.Infof("  作用范围 → 仅 %s 进程，其它流量不变", rc.UnboundUser)
	return nil
}

func (rc RoutingConfig) applyPolicyRoutes(ctx context.Context, rt *Runtime) error {
	rt.Infof("配置路由表 %s", rc.RouteTable)
	if _, err := run(ctx, "ip", "route", "replace", tunnelSubnet,
		"dev", rc.Config.TunnelIf, "scope", "link", "table", rc.RouteTable); err != nil {
		return fmt.Errorf("写入隧道网段路由失败: %w", err)
	}
	if _, err := run(ctx, "ip", "route", "replace", "default",
		"dev", rc.Config.TunnelIf, "table", rc.RouteTable); err != nil {
		return fmt.Errorf("写入默认路由失败: %w", err)
	}
	if !rc.ruleExists(ctx, "from "+rc.Config.TunnelAddr+" lookup "+rc.RouteTable) {
		if _, err := run(ctx, "ip", "rule", "add", "from", rc.Config.TunnelAddr,
			"lookup", rc.RouteTable, "priority", rulePriorityFrom); err != nil {
			return fmt.Errorf("添加隧道源地址策略失败: %w", err)
		}
	}
	if !rc.ruleExists(ctx, "fwmark "+rc.FWMark+" lookup "+rc.RouteTable) {
		if _, err := run(ctx, "ip", "rule", "add", "fwmark", rc.FWMark,
			"lookup", rc.RouteTable, "priority", rulePriorityFWMark); err != nil {
			return fmt.Errorf("添加 fwmark 策略失败: %w", err)
		}
	}
	prohibit := "fwmark " + rc.FWMark + " prohibit"
	if rc.FailMode == "closed" {
		if !rc.ruleExists(ctx, prohibit) {
			if _, err := run(ctx, "ip", "rule", "add", "fwmark", rc.FWMark,
				"prohibit", "priority", rulePriorityProhib); err != nil {
				return fmt.Errorf("添加隧道故障兜底规则失败: %w", err)
			}
		}
		rt.Infof("隧道故障策略：closed（境外查询失败，不回落直连）")
	} else {
		for i := 0; i < ruleDeleteMaxRounds && rc.ruleExists(ctx, prohibit); i++ {
			if _, err := run(ctx, "ip", "rule", "del", "fwmark", rc.FWMark, "prohibit"); err != nil {
				break
			}
		}
		rt.Warnf("隧道故障策略：open（境外查询回落直连，期间可能拿到污染答案）")
	}
	rt.Infof("策略路由已就位")
	return nil
}

var (
	allowedAllRe = regexp.MustCompile(`(?m)^\s*AllowedIPs\s*=\s*0\.0\.0\.0/0`)
	tableOffRe   = regexp.MustCompile(`(?m)^\s*Table\s*=\s*off`)
)

func (rc RoutingConfig) guardWireGuardConf() error {
	body, err := os.ReadFile(rc.WGConf)
	if err != nil {
		return nil
	}
	if allowedAllRe.Match(body) && !tableOffRe.Match(body) {
		return fmt.Errorf("%s 有 AllowedIPs = 0.0.0.0/0 但缺少 Table = off。"+
			"下次重启时 wg-quick 会装默认路由，把整机流量导进隧道。"+
			"请在 [Interface] 段加一行 Table = off；拒绝继续，以免留下开机即失控的配置", rc.WGConf)
	}
	return nil
}

func (rc RoutingConfig) peerAllowedIPs(ctx context.Context) map[string]string {
	out, _ := run(ctx, "wg", "show", rc.Config.TunnelIf, "allowed-ips")
	result := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result[fields[0]] = strings.Join(fields[1:], " ")
		}
	}
	return result
}

func (rc RoutingConfig) openHKPeer(ctx context.Context, rt *Runtime) error {
	peers := rc.peerAllowedIPs(ctx)
	var target, current string
	for key, value := range peers {
		if value == hkPeerAllowedIP || value == openAllowedIPs {
			target, current = key, value
			break
		}
	}
	if target == "" {
		rt.Warnf("未找到香港 peer（allowed-ips 既非 %s 也非 %s），跳过", hkPeerAllowedIP, openAllowedIPs)
		return nil
	}
	if current == openAllowedIPs {
		rt.Infof("香港 peer 的 allowed-ips 已是 %s", openAllowedIPs)
		return nil
	}
	if _, err := run(ctx, "wg", "set", rc.Config.TunnelIf, "peer", target,
		"allowed-ips", openAllowedIPs); err != nil {
		return fmt.Errorf("放开香港 peer 的 allowed-ips 失败: %w", err)
	}
	rt.Infof("香港 peer allowed-ips 放开至 %s", openAllowedIPs)
	return nil
}

func (rc RoutingConfig) ensureSetLoaded(ctx context.Context, rt *Runtime) {
	if rt.NFTSetCount(ctx, rc.Config.DirectSet) >= rc.MinEntries {
		return
	}
	if _, err := os.Stat(rc.CachedNFT); err != nil {
		return
	}
	rt.Infof("集合为空，从缓存恢复：%s", rc.CachedNFT)
	if _, err := run(ctx, "nft", "-f", rc.CachedNFT); err != nil {
		rt.Warnf("缓存恢复失败: %v", err)
		return
	}
	rt.Infof("已恢复 %d 条", rt.NFTSetCount(ctx, rc.Config.DirectSet))
}

func (rc RoutingConfig) verifySetSemantics(ctx context.Context, rt *Runtime) error {
	var bad []string
	if !rc.inSet(ctx, rc.Config.TunnelAddr) {
		bad = append(bad, fmt.Sprintf("集合未包含私有网段（%s），集合内容异常", rc.Config.TunnelAddr))
	}
	if sample := strings.TrimSpace(rc.Config.Value("PUBLIC_IPV4")); sample == "" {
		rt.Warnf("config.env 未配置 PUBLIC_IPV4，跳过大陆样本校验")
	} else if rc.inSet(ctx, sample) {
		rt.Infof("本机公网 %s 在直连集合内（符合预期：大陆）", sample)
	} else {
		bad = append(bad, fmt.Sprintf("本机公网 %s 不在直连集合内，大陆数据疑似残缺", sample))
	}
	endpoints := rc.tunnelEndpoints(ctx)
	if len(endpoints) == 0 {
		rt.Warnf("未取到隧道对端地址，跳过境外样本校验")
	} else if rc.inSet(ctx, endpoints[0]) {
		bad = append(bad, fmt.Sprintf("隧道对端 %s 竟在直连集合内，集合疑似被污染", endpoints[0]))
	} else {
		rt.Infof("隧道对端 %s 不在直连集合内（符合预期：境外）", endpoints[0])
	}
	if len(bad) > 0 {
		return fmt.Errorf("集合语义校验未通过: %s", strings.Join(bad, "; "))
	}
	return nil
}

func (rc RoutingConfig) tunnelEndpoints(ctx context.Context) []string {
	out, _ := run(ctx, "wg", "show", rc.Config.TunnelIf, "endpoints")
	seen := make(map[string]struct{})
	var result []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := fields[1]
		if cut := strings.LastIndexByte(host, ':'); cut >= 0 {
			host = host[:cut]
		}
		host = strings.Trim(host, "[]")
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is4() {
			continue
		}
		if _, dup := seen[addr.String()]; dup {
			continue
		}
		seen[addr.String()] = struct{}{}
		result = append(result, addr.String())
	}
	return result
}

func (rc RoutingConfig) cnAuthorityEntries() []string {
	file, err := os.Open(rc.Config.Chnroute("cn-authority.txt"))
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] < '0' || line[0] > '9' {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (rc RoutingConfig) renderChainScript(uid string, endpoints, authority []string) string {
	table := rc.Config.NFTTable
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)

	fmt.Fprintf(&b, "add set inet %s %s { type ipv4_addr; flags interval; auto-merge; }\n",
		table, rc.Config.AuthoritySet)
	fmt.Fprintf(&b, "flush set inet %s %s\n", table, rc.Config.AuthoritySet)
	for start := 0; start < len(authority); start += nftChunk {
		end := min(start+nftChunk, len(authority))
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n",
			table, rc.Config.AuthoritySet, strings.Join(authority[start:end], ", "))
	}

	fmt.Fprintf(&b, "add set inet %s %s { type ipv4_addr; }\n", table, rc.EndpointSet)
	fmt.Fprintf(&b, "flush set inet %s %s\n", table, rc.EndpointSet)
	if len(endpoints) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n",
			table, rc.EndpointSet, strings.Join(endpoints, ", "))
	}

	fmt.Fprintf(&b, "add chain inet %s output { type route hook output priority mangle; policy accept; }\n", table)
	fmt.Fprintf(&b, "flush chain inet %s output\n", table)
	fmt.Fprintf(&b, "add rule inet %s output meta skuid %s ip daddr != @%s ip daddr != @%s ip daddr != @%s counter meta mark set %s\n",
		table, uid, rc.Config.DirectSet, rc.Config.AuthoritySet, rc.EndpointSet, rc.FWMark)

	fmt.Fprintf(&b, "add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }\n", table)
	fmt.Fprintf(&b, "flush chain inet %s postrouting\n", table)
	fmt.Fprintf(&b, "add rule inet %s postrouting oifname \"%s\" meta mark %s counter masquerade\n",
		table, rc.Config.TunnelIf, rc.FWMark)
	return b.String()
}

func (rc RoutingConfig) Revert(ctx context.Context, rt *Runtime) error {
	rt.Infof("撤销递归分流配置")
	if _, err := run(ctx, "nft", "delete", "table", "inet", rc.Config.NFTTable); err == nil {
		rt.Infof("已删除 nft 表 %s", rc.Config.NFTTable)
	} else {
		rt.Infof("nft 表不存在，跳过")
	}
	lookup := "lookup " + rc.RouteTable
	prohibit := "fwmark " + rc.FWMark + " prohibit"
	for i := 0; i < ruleDeleteMaxRounds && rc.ruleExists(ctx, lookup); i++ {
		if _, err := run(ctx, "ip", "rule", "del", "lookup", rc.RouteTable); err != nil {
			break
		}
	}
	for i := 0; i < ruleDeleteMaxRounds && rc.ruleExists(ctx, prohibit); i++ {
		if _, err := run(ctx, "ip", "rule", "del", "fwmark", rc.FWMark, "prohibit"); err != nil {
			break
		}
	}
	if rc.ruleExists(ctx, lookup) || rc.ruleExists(ctx, prohibit) {
		rt.Warnf("仍有策略路由规则未能删除，请手工检查: ip rule show")
	} else {
		rt.Infof("已删除策略路由规则")
	}
	run(ctx, "ip", "route", "flush", "table", rc.RouteTable)
	rt.Infof("已清空路由表 %s", rc.RouteTable)
	rt.Warnf("WireGuard 的 allowed-ips 未改动（改回 /32 会切断隧道转发能力）")
	rt.Warnf("如需完全还原：wg set %s peer <香港公钥> allowed-ips %s", rc.Config.TunnelIf, hkPeerAllowedIP)
	return nil
}

func (rc RoutingConfig) Status(ctx context.Context, rt *Runtime) error {
	section := func(title string, out string, err error) {
		fmt.Fprintf(rt.Out, "=== %s ===\n", title)
		if err != nil && strings.TrimSpace(out) == "" {
			fmt.Fprintf(rt.Out, "（不可用: %v）\n\n", err)
			return
		}
		fmt.Fprintf(rt.Out, "%s\n", strings.TrimRight(out, "\n"))
		fmt.Fprintln(rt.Out)
	}
	out, err := run(ctx, "wg", "show", rc.Config.TunnelIf, "allowed-ips")
	section("WireGuard 加密路由", out, err)
	out, err = run(ctx, "ip", "rule", "show")
	section("策略路由规则", out, err)
	out, err = run(ctx, "ip", "route", "show", "table", rc.RouteTable)
	section("路由表 "+rc.RouteTable, out, err)
	section("直连集合规模", strconv.Itoa(rt.NFTSetCount(ctx, rc.Config.DirectSet))+" 条", nil)
	out, err = run(ctx, "nft", "list", "chain", "inet", rc.Config.NFTTable, "output")
	section("分流链", out, err)
	marked, _ := run(ctx, "ip", "route", "get", "198.41.0.4", "mark", rc.FWMark)
	direct, _ := run(ctx, "ip", "route", "get", "180.76.76.76")
	fmt.Fprintf(rt.Out, "=== 抽样路由决策 ===\n")
	fmt.Fprintf(rt.Out, "  根服务器 198.41.0.4  打标后: %s\n", firstLine(marked))
	fmt.Fprintf(rt.Out, "  国内 180.76.76.76    直连:   %s\n", firstLine(direct))
	return nil
}

func firstLine(text string) string {
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		text = text[:idx]
	}
	if text = strings.TrimSpace(text); text == "" {
		return "（无输出）"
	}
	return text
}
