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

	"github.com/dns-stack/dns-stack/internal/cdn"
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

	zones := loadMatchedZones(filepath.Join(opt.StateDir, "chnroute", "cn-zones-matched.txt"))
	var steered []string
	for zone := range zones {
		if cdn.IsGeoSteered(zone) {
			steered = append(steered, zone)
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

func checkResolution(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "解析与就近"}
	probes := []struct {
		domain string
		label  string
	}{
		{"www.apple.com", "Apple 主站"},
		{"www.microsoft.com", "微软主站"},
		{"www.qq.com", "腾讯"},
	}
	const (
		beijing   = "219.141.136.0/24"
		guangdong = "113.108.10.0/24"
	)
	resolver := "127.0.0.1:5335"
	differentiated, comparable := 0, 0
	for _, probe := range probes {
		north, errN := queryWithSubnet(ctx, resolver, probe.domain, beijing)
		south, errS := queryWithSubnet(ctx, resolver, probe.domain, guangdong)
		if errN != nil || errS != nil || len(north) == 0 || len(south) == 0 {
			c.skip(probe.label+" 按子网分化", "解析未成功，本轮取不到对照")
			continue
		}
		comparable++
		if strings.Join(north, ",") != strings.Join(south, ",") {
			differentiated++
			c.ok(probe.label+" 按子网分化", "北京 %s / 广东 %s",
				strings.Join(north, " "), strings.Join(south, " "))
			continue
		}
		c.warn(probe.label+" 按子网分化",
			"两地答案相同(%s)——该域名的权威没收到 ECS，或它本来就没有国内节点",
			strings.Join(north, " "))
	}
	if comparable == 0 {
		c.skip("ECS 就近整体判据", "没有可比较的域名，本轮判据没有回答任何问题")
		return
	}
	c.assert(differentiated > 0, "ECS 就近整体判据",
		fmt.Sprintf("%d/%d 个域名按客户端子网给出不同答案", differentiated, comparable),
		fmt.Sprintf("%d 个域名全都不按子网分化——ECS 链路可能整条失效", comparable))
}
