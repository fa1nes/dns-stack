package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	resolver := fs.String("resolver", cdnhit.DefaultResolver, "递归解析器地址")
	subnet := fs.String("subnet", cdnhit.BeijingTelecom, "客户端子网，必须是真实中国 /24")
	domains := fs.String("domains", "", "自定义探测域名，逗号分隔(默认为内置的国内外大厂清单)")
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	maxStranded := fs.Int("max-stranded", -1, "允许的「有大陆节点却落到境外」条数上限，超过则退出码非零")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ruleset == "" {
		*ruleset = rulesync.CDNPath(*state)
	}

	set, err := cdnrules.Load(*ruleset)
	if err != nil {
		return fmt.Errorf("读不到 CDN 直连规则集 %s: %w（先跑 dns-stack sync-rules）", *ruleset, err)
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
		Resolver: *resolver, Subnet: *subnet, Probes: probes, Set: set,
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
	if *maxStranded >= 0 && report.Stranded > *maxStranded {
		return fmt.Errorf("%d 个域名的 CDN 在大陆有节点却返回了境外地址，超过上限 %d",
			report.Stranded, *maxStranded)
	}
	return nil
}

func renderCDNHit(report cdnhit.Report) {
	fmt.Printf("解析器 %s   客户端子网 %s   规则集 %s\n\n",
		report.Resolver, report.Subnet,
		time.Unix(report.RulesetAt, 0).Format("2006-01-02 15:04"))
	marks := map[cdnhit.Verdict]string{
		cdnhit.VerdictMainland: "✓", cdnhit.VerdictStranded: "✗",
		cdnhit.VerdictOffshore: "–", cdnhit.VerdictThin: "–",
		cdnhit.VerdictMismatch: "!",
		cdnhit.VerdictUnknown:  "?", cdnhit.VerdictUnresolved: "?",
	}
	for _, probe := range report.Probes {
		provider := probe.Provider
		if provider == "" {
			provider = "未识别"
		}
		fmt.Printf("  %s %-24s %-14s %s\n", marks[probe.Verdict], probe.Domain, provider, probe.VerdictText)
		if len(probe.Addrs) > 0 {
			fmt.Printf("      %s\n", strings.Join(probe.Addrs, " "))
		}
		if probe.Error != "" {
			fmt.Printf("      %s\n", probe.Error)
		}
	}
	if report.Comparable == 0 {
		fmt.Printf("\n没有一个域名的落点能与规则集比对，本轮判据没有回答任何问题\n")
		return
	}
	fmt.Printf("\n就近命中 %d/%d", report.Mainland, report.Comparable)
	if report.Stranded > 0 {
		fmt.Printf("；%d 个域名的 CDN 在大陆有节点却给了境外地址——先查这些权威有没有收到 ECS："+
			"dns-stack ecs-audit --quick", report.Stranded)
	}
	fmt.Println()
}
