package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnhit"
	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/rulesync"
)

func cmdCDNHit(args []string) error {
	fs := flag.NewFlagSet("cdn-hit", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	ruleset := fs.String("ruleset", "", "CDN 直连规则集(默认 <state>/cdn-direct.txt)")
	direct4 := fs.String("direct4", "", "大陆网段集合(默认 <state>/chnroute/direct4.txt)")
	resolver := fs.String("resolver", cdnhit.DefaultResolver, "递归解析器地址")
	subnet := fs.String("subnet", cdnhit.BeijingTelecom, "客户端子网，必须是真实中国 /24")
	domains := fs.String("domains", "", "自定义探测域名，逗号分隔(默认为内置的国内外大厂清单)")
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	minMainland := fs.Int("min-mainland", -1, "至少要有几个域名命中大陆节点，不足则退出码非零")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ruleset == "" {
		*ruleset = rulesync.CDNPath(*state)
	}
	if *direct4 == "" {
		*direct4 = filepath.Join(*state, "chnroute", "direct4.txt")
	}

	set, err := cdnrules.Load(*ruleset)
	if err != nil {
		return fmt.Errorf("读不到 CDN 直连规则集 %s: %w（先跑 dns-stack sync-rules）", *ruleset, err)
	}

	mainland, err := cdnhit.LoadMainland(*direct4)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"[警告] 读不到大陆网段 %s (%v)：只能靠规则集里的大陆段判定，"+
				"而国产 CDN 大多把节点放在运营商机房、用运营商的 IP，规则集按 ASN 拉不到那些段\n",
			*direct4, err)
	}

	var probes []cdnhit.Probe
	for _, item := range strings.Split(*domains, ",") {
		if name := strings.TrimSpace(item); name != "" {
			probes = append(probes, cdnhit.Probe{Domain: name, Label: name})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report, err := cdnhit.Run(ctx, cdnhit.Options{
		Resolver: *resolver, Subnet: *subnet, Probes: probes, Set: set, Mainland: mainland,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return err
		}
	} else {
		renderCDNHit(report)
	}
	if *minMainland >= 0 && report.Mainland < *minMainland {
		return fmt.Errorf("只有 %d 个域名命中大陆节点，低于下限 %d（可比对 %d 个，未判定 %d 个）",
			report.Mainland, *minMainland, report.Comparable, report.Undecided)
	}
	return nil
}

func renderCDNHit(report cdnhit.Report) {
	fmt.Printf("解析器 %s   客户端子网 %s   规则集 %s\n\n",
		report.Resolver, report.Subnet,
		time.Unix(report.RulesetAt, 0).Format("2006-01-02 15:04"))
	marks := map[cdnhit.Verdict]string{
		cdnhit.VerdictMainland:   "✓",
		cdnhit.VerdictNoSteering: "–",
		cdnhit.VerdictNoNode:     "–",
		cdnhit.VerdictNoEcho:     "?",
		cdnhit.VerdictUnresolved: "?",
	}
	for _, probe := range report.Probes {
		provider := probe.Provider
		if provider == "" {
			provider = "未识别"
		}
		ecs := "无回显"
		if probe.ECSEchoed {
			ecs = fmt.Sprintf("scope=%d", probe.Scope)
		}
		fmt.Printf("  %s %-24s %-12s %-10s %s\n",
			marks[probe.Verdict], probe.Domain, provider, ecs, probe.VerdictText)
		if len(probe.Addrs) > 0 {
			note := ""
			if probe.Mismatch {
				note = "   ← 不属于该 CDN 的任何段，可能是自建源站或投毒地址"
			}
			fmt.Printf("      %s%s\n", strings.Join(probe.Addrs, " "), note)
		}
		if probe.Error != "" {
			fmt.Printf("      %s\n", probe.Error)
		}
	}
	if report.Comparable == 0 {
		fmt.Printf("\n%d 个域名本轮都没有 ECS 回显，判不出\n", report.Undecided)
		return
	}
	fmt.Printf("\n就近命中 %d/%d", report.Mainland, report.Comparable)
	if report.NoNode+report.NoSteering > 0 {
		fmt.Printf("；另有 %d 个落在境外但已解释（权威挑过了或声明不按位置调度）",
			report.NoNode+report.NoSteering)
	}
	fmt.Println()
	if report.Undecided > 0 {
		fmt.Printf("%d 个域名没有 ECS 回显：scope=0 的答案会被 unbound 按 ECS 标准缓存成全局条目，\n"+
			"后续任何子网的查询都命中它且不回显。要确认 ECS 是否真的送达，用 dns-stack ecs-audit\n",
			report.Undecided)
	}
}
