package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/geoaudit"
)

func cmdDirect4Audit(args []string) error {
	fs := flag.NewFlagSet("direct4-audit", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	defaultAgreement, _ := strconv.Atoi(envOr("GEO_CROSS_AGREEMENT", "0"))
	agreement := fs.Int("agreement", defaultAgreement, "需要多少个归属库同时判为非大陆才算争议，0 表示用默认值 2")
	list := fs.Int("list", 20, "按地址量列出前 N 段")
	promoteLimit := fs.Uint64("promote-limit", 0, "晋级地址量上限，超过则本轮整体不晋级，0 表示用默认值")
	disputeLimit := fs.Uint64("dispute-limit", 0, "争议地址量上限，超过则本轮整体不否决，0 表示按 direct4 的 5%")
	dryRun := fs.Bool("dry-run", false, "只报告，不写出争议/晋级清单")
	disputedOut := fs.String("emit-disputed", "", "争议网段输出路径（默认 <state>/chnroute/geo-disputed.txt）")
	promotedOut := fs.String("emit-promoted", "", "晋级网段输出路径（默认 <state>/chnroute/geo-promoted.txt）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	geoDir := filepath.Join(*state, "geoip")
	if *disputedOut == "" {
		*disputedOut = filepath.Join(*state, "chnroute", "geo-disputed.txt")
	}
	if *promotedOut == "" {
		*promotedOut = filepath.Join(*state, "chnroute", "geo-promoted.txt")
	}
	report, err := geoaudit.Run(geoaudit.Config{
		Direct4Path:  filepath.Join(*state, "chnroute", "direct4.txt"),
		Sources:      geoaudit.DefaultSources(geoDir),
		DisputeNeed:  *agreement,
		PromoteLimit: *promoteLimit,
		DisputeLimit: *disputeLimit,
	})
	if err != nil {
		return err
	}
	percent := func(n uint64) float64 {
		return float64(n) * 100 / float64(report.TotalAddresses)
	}
	fmt.Printf("direct4: %d 段 / %d 个地址\n", report.Entries, report.TotalAddresses)
	fmt.Printf("可用归属库: %s\n", strings.Join(report.Sources, ", "))
	if len(report.Unavailable) > 0 {
		names := sortedKeys(report.Unavailable)
		for _, name := range names {
			fmt.Printf("  [警告] %-8s 不可用: %s\n", name, report.Unavailable[name])
		}
	}
	for _, name := range report.Sources {
		fmt.Printf("  %-8s direct4 内判为非大陆 %11d 个 (%.2f%%)，direct4 外判为大陆 %11d 个\n",
			name, report.OffshoreBySource[name], percent(report.OffshoreBySource[name]),
			report.MainlandBySource[name])
	}

	if report.FailOpen != "" {
		fmt.Printf("[警告] %s\n", report.FailOpen)
		if *dryRun {
			return nil
		}
		fmt.Println("[警告] 不写出清单文件；消费侧读到陈旧文件会按新鲜度判据告警")
		return nil
	}

	if report.DisputeRejected != "" {
		fmt.Printf("[警告] %s\n", report.DisputeRejected)
	} else {
		fmt.Printf("争议（≥%d 个源一致判为非大陆）: %d 段 / %d 个地址 (%.2f%%)\n",
			report.DisputeNeed, len(report.Disputed), report.DisputedTotal, percent(report.DisputedTotal))
		printSpans(report.Disputed, *list)
	}

	if report.PromoteRejected != "" {
		fmt.Printf("[警告] %s\n", report.PromoteRejected)
	} else {
		fmt.Printf("晋级（%d 个源全部判为大陆、且不在 direct4 内）: %d 段 / %d 个地址\n",
			report.PromoteNeed, len(report.Promoted), report.PromotedTotal)
		printSpans(report.Promoted, *list)
	}

	if *dryRun {
		return nil
	}
	if report.DisputeRejected != "" {
		fmt.Println("[警告] 争议清单本轮不更新，消费侧会按新鲜度判据告警")
	} else if err := geoaudit.Write(*disputedOut, geoaudit.KindDisputed,
		report.DisputeNeed, report.Sources, report.Disputed); err != nil {
		return err
	} else {
		fmt.Printf("已写出 %s\n", *disputedOut)
	}
	if report.PromoteRejected != "" {
		fmt.Println("[警告] 晋级清单本轮不更新，消费侧会按新鲜度判据告警")
		return nil
	}
	if err := geoaudit.Write(*promotedOut, geoaudit.KindPromoted,
		report.PromoteNeed, report.Sources, report.Promoted); err != nil {
		return err
	}
	fmt.Printf("已写出 %s\n", *promotedOut)
	return nil
}

func printSpans(spans []geoaudit.Span, limit int) {
	sorted := append([]geoaudit.Span(nil), spans...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Hi-sorted[i].Lo > sorted[j].Hi-sorted[j].Lo
	})
	for i, span := range sorted {
		if i >= limit {
			break
		}
		fmt.Printf("    %-16s - %-16s %9d 个  %s\n",
			geoaudit.FormatAddr(span.Lo), geoaudit.FormatAddr(span.Hi),
			span.Hi-span.Lo+1, span.Country)
	}
}

func sortedKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
