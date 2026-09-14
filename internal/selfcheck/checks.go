package selfcheck

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/cdn"
	"github.com/dns-stack/dns-stack/internal/cdnhit"
	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/pipeline"
	"github.com/dns-stack/dns-stack/internal/rulesync"
	"github.com/dns-stack/dns-stack/internal/stack"
)

func checkModules(ctx context.Context, opt Options, report *Report) {
	c := &checker{report: report, group: "模块健康"}
	modules := stack.ForRole(opt.Role)
	if len(modules) == 0 {
		c.skip("模块登记表", "角色 %s 没有登记任何模块", opt.Role)
		return
	}
	now := opt.now()
	var troubled []string
	critical := 0
	for _, module := range modules {
		status := stack.UnitStatus(module.Unit)
		state, note := stack.Evaluate(module, status, now)
		switch state {
		case stack.StateOK:
		case stack.StateDown:
			troubled = append(troubled, module.Unit+"("+note+")")
			if module.Critical {
				critical++
			}
		default:
			troubled = append(troubled, module.Unit+"("+note+")")
		}
	}
	if len(troubled) == 0 {
		c.ok("全部模块正常", "%d 个模块", len(modules))
		return
	}
	detail := strings.Join(troubled, ", ")
	if critical > 0 {
		c.fail("关键模块异常", "%s", detail)
		return
	}
	c.warn("有模块需要关注", "%s", detail)
}

type freshness struct {
	name    string
	path    string
	budget  time.Duration
	minRows int
	must    bool
}

func countRows(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer file.Close()
	count := 0
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

func checkRoutingData(opt Options, report *Report, now time.Time) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "分流数据"}
	state := func(parts ...string) string {
		return filepath.Join(append([]string{opt.StateDir}, parts...)...)
	}
	items := []freshness{
		{"大陆网段 direct4", state("chnroute", "direct4.txt"), 72 * time.Hour, 3000, true},
		{"国内权威集合", state("chnroute", "cn-authority.txt"), 2 * time.Hour, 20, true},
		{"多源争议清单", state("chnroute", "geo-disputed.txt"), 72 * time.Hour, 0, false},
		{"共享 anycast 清单", state("chnroute", "shared-anycast.txt"), 6 * time.Hour, 0, false},
		{"ECS 分片表", state("ecs-ip-zone.txt"), 72 * time.Hour, 1000, true},
		{"规则包 cn.txt", state("cn.txt"), 24 * time.Hour, 50, false},
		{"规则包 gfw.txt", state("gfw.txt"), 24 * time.Hour, 50, false},
	}
	for _, item := range items {
		rows := countRows(item.path)
		if rows < 0 {
			if item.must {
				c.fail(item.name, "文件不存在: %s", item.path)
			} else {
				c.skip(item.name, "文件不存在")
			}
			continue
		}
		if rows < item.minRows {
			c.fail(item.name, "只有 %d 条，低于下限 %d", rows, item.minRows)
			continue
		}
		age, _ := fileAge(item.path, now)
		if age > item.budget {
			c.warn(item.name, "%d 条，但已 %s 未更新（预算 %s）",
				rows, humanAge(age), humanAge(item.budget))
			continue
		}
		c.ok(item.name, "%d 条，%s更新", rows, humanAge(age))
	}
}

func loadECSWhitelist(path string) ([]netip.Prefix, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, "send-client-subnet:")
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rest))
		if err != nil {
			continue
		}
		out = append(out, prefix)
	}
	return out, sc.Err()
}

func loadMatchedZones(path string) map[string]struct{} {
	out := map[string]struct{}{}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && !strings.HasPrefix(line, "#") {
			out[line] = struct{}{}
		}
	}
	return out
}

func checkECSWhitelist(opt Options, report *Report, now time.Time) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "ECS 就近调度"}
	conf := "/etc/unbound/unbound.conf.d/dns-stack-ecs.conf"
	prefixes, err := loadECSWhitelist(conf)
	if err != nil {
		c.fail("ECS 白名单可读", "读不到 %s: %v", conf, err)
		return
	}
	if len(prefixes) == 0 {
		c.fail("ECS 白名单非空",
			"一条 send-client-subnet 都没有——所有权威都收不到客户端子网，CDN 调度会静默退化")
		return
	}
	c.ok("ECS 白名单非空", "%d 条", len(prefixes))

	if age, ok := fileAge(conf, now); ok && age > 2*time.Hour {
		c.warn("ECS 白名单新鲜度", "已 %s 未更新", humanAge(age))
	}

	steeredPath := filepath.Join(opt.StateDir, "chnroute", "cdn-steered-zones.txt")
	var steered []string
	for zone := range loadMatchedZones(steeredPath) {
		steered = append(steered, zone)
	}
	if len(steered) == 0 {
		for zone := range loadMatchedZones(
			filepath.Join(opt.StateDir, "chnroute", "cn-zones-matched.txt")) {
			if cdn.IsGeoSteered(zone) {
				steered = append(steered, zone)
			}
		}
	}
	sort.Strings(steered)
	if len(steered) == 0 {
		c.warn("CDN 地理调度区域已识别",
			"一个 geo-steering 区域都没识别到——Akamai/Apple 一类 CDN 会只按隧道出口调度，"+
				"用户拿到境外节点。检查 dns-stack-routing-data 是否跑过")
		return
	}
	sample := steered
	if len(sample) > 6 {
		sample = sample[:6]
	}
	c.ok("CDN 地理调度区域已识别", "%d 个，如 %s", len(steered), strings.Join(sample, ", "))
}

func checkAccessFiles(opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "访问控制与黑名单"}
	store := access.Store{StateDir: opt.StateDir}
	if missing := store.MissingFiles(); len(missing) > 0 {
		c.fail("黑名单文件存在",
			"%s 不存在——mosproxy 的 domain_set 在启动时读不到文件会直接起不来。"+
				"现在服务还活着只是因为规则已在内存里，下次重启就会炸。修复: dns-stack blocklist list",
			strings.Join(missing, ", "))
		return
	}
	blocked, err := store.Blocklist()
	if err != nil {
		c.fail("黑名单文件可读", "%v", err)
		return
	}
	c.ok("黑名单文件存在", "%d 个域名被拦截", len(blocked))

	entries, err := store.ACL()
	if err != nil {
		c.fail("访问控制清单可解析", "%v", err)
		return
	}
	installed := pipeline.ACLInstalled(context.Background(), pipeline.LoadConfig(opt.StateDir, opt.ConfigFile).NFTTable)
	switch {
	case len(entries) == 0 && !installed:
		c.skip("访问控制", "未启用，入口对全网开放")
	case len(entries) == 0 && installed:
		c.fail("访问控制", "acl.txt 为空但内核里仍有访问控制链——执行 dns-stack acl disable 清理")
	case !installed:
		c.fail("访问控制", "acl.txt 有 %d 条授权网段，但内核里没有对应的链——改动从未下发，入口其实对全网开放",
			len(entries))
	default:
		c.ok("访问控制", "%d 个授权网段已下发到内核", len(entries))
	}
}

func checkCDNRuleset(opt Options, report *Report, now time.Time) *cdnrules.Set {
	if opt.Role != stack.RoleCNResolver {
		return nil
	}
	c := &checker{report: report, group: "CDN 直连规则集"}
	path := rulesync.CDNPath(opt.StateDir)
	set, err := cdnrules.Load(path)
	if err != nil {
		c.warn("规则集可用", "读不到 %s: %v（CDN 命中判据本轮整体弃权）", path, err)
		return nil
	}
	withNets := 0
	mainland := 0
	for _, p := range set.Providers() {
		if p.PrefixCount() > 0 {
			withNets++
		}
		if p.HasMainland() {
			mainland++
		}
	}
	if withNets == 0 {
		c.fail("规则集有前缀证据",
			"%d 个 provider 全都没有前缀，判据会对所有域名弃权——等于规则集从未接上",
			len(set.Providers()))
		return set
	}
	c.ok("规则集可用", "provider %d 个(%d 个有前缀证据，%d 个有大陆节点段)，前缀 %d 条",
		len(set.Providers()), withNets, mainland, set.PrefixCount())
	if age, ok := fileAge(path, now); ok && age > 72*time.Hour {
		c.warn("规则集新鲜度", "已 %s 未更新，检查 cdn-rules Action 与 dns-stack-sync-rules", humanAge(age))
	}
	return set
}

func checkResolution(ctx context.Context, opt Options, report *Report, cdnSet *cdnrules.Set) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "解析与就近"}
	resolver := cdnhit.DefaultResolver
	probes := []cdnhit.Probe{
		{Domain: "www.apple.com", Label: "Apple 主站"},
		{Domain: "www.microsoft.com", Label: "微软主站"},
		{Domain: "www.qq.com", Label: "腾讯"},
	}
	differentiated, comparable := 0, 0
	for _, probe := range probes {
		north, errN := cdnhit.Query(ctx, resolver, probe.Domain, cdnhit.BeijingTelecomPrefix, 0)
		south, errS := cdnhit.Query(ctx, resolver, probe.Domain, cdnhit.GuangdongUnicomPrefix, 0)
		if errN != nil || errS != nil || len(north) == 0 || len(south) == 0 {
			c.skip(probe.Label+" 按子网分化", "解析未成功，本轮取不到对照")
			continue
		}
		comparable++
		if cdnhit.JoinAddrs(north, ",") != cdnhit.JoinAddrs(south, ",") {
			differentiated++
			c.ok(probe.Label+" 按子网分化", "北京 %s / 广东 %s",
				cdnhit.JoinAddrs(north, " "), cdnhit.JoinAddrs(south, " "))
		} else {
			c.warn(probe.Label+" 按子网分化",
				"两地答案相同(%s)——该域名的权威没收到 ECS，或它本来就没有国内节点",
				cdnhit.JoinAddrs(north, " "))
		}
	}
	if comparable == 0 {
		c.skip("ECS 就近整体判据", "没有可比较的域名，本轮判据没有回答任何问题")
	} else {
		c.assert(differentiated > 0, "ECS 就近整体判据",
			fmt.Sprintf("%d/%d 个域名按客户端子网给出不同答案", differentiated, comparable),
			fmt.Sprintf("%d 个域名全都不按子网分化——ECS 链路可能整条失效", comparable))
	}
	checkCDNLanding(ctx, opt, report, cdnSet, resolver)
}

func checkCDNLanding(ctx context.Context, opt Options, report *Report, cdnSet *cdnrules.Set, resolver string) {
	c := &checker{report: report, group: "CDN 就近命中"}
	hit, err := cdnhit.Run(ctx, cdnhit.Options{Resolver: resolver, Set: cdnSet})
	if err != nil {
		c.skip("大陆节点命中", "%v", err)
		return
	}
	var stranded, mismatched []string
	for _, probe := range hit.Probes {
		switch probe.Verdict {
		case cdnhit.VerdictStranded:
			stranded = append(stranded, fmt.Sprintf("%s→%s(%s)",
				probe.Domain, strings.Join(probe.Addrs, "/"), probe.Provider))
		case cdnhit.VerdictMismatch:
			mismatched = append(mismatched, fmt.Sprintf("%s→%s",
				probe.Domain, strings.Join(probe.Addrs, "/")))
		}
	}
	if hit.Comparable == 0 {
		c.skip("大陆节点命中", "没有一个域名的落点能与规则集比对，本轮判据没有回答任何问题")
	} else {
		c.assert(hit.Stranded == 0, "大陆节点命中",
			fmt.Sprintf("%d/%d 个域名拿到了大陆 CDN 节点", hit.Mainland, hit.Comparable),
			fmt.Sprintf("%s——这些 CDN 在大陆有节点却给了境外地址，"+
				"多半是权威没收到 ECS；复核 dns-stack ecs-audit --quick", strings.Join(stranded, ", ")))
	}
	if len(mismatched) > 0 {
		c.warn("答案属于已知 CDN 段",
			"%s 不属于任何已知 CDN 段——可能是自建源站，也可能是投毒地址，"+
				"用 dns-stack cdn-rules lookup 复核", strings.Join(mismatched, ", "))
	}
}
