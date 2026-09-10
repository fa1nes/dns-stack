package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/ruleset"
)

func loadCrossSet(path, wantKind string) *ipset.Set {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	snapshot, err := geoaudit.LoadSnapshot(path)
	if err != nil {
		fail(fmt.Sprintf("读不到多源清单 %s: %v", path, err))
	}
	if snapshot.Kind != wantKind {
		fail(fmt.Sprintf("%s 声明的 kind 是 %q，期望 %q，拒绝按错误的方向使用", path, snapshot.Kind, wantKind))
	}
	fmt.Fprintf(os.Stderr, "[信息] %s: %s %d 条前缀，来源 %s，agreement=%d\n",
		path, snapshot.Kind, snapshot.Prefixes, strings.Join(snapshot.Sources, ","), snapshot.Agreement)
	return snapshot.Set
}

type output struct {
	RoutePrefixes    []string            `json:"route_prefixes"`
	ECSPrefixes      []string            `json:"ecs_prefixes"`
	MatchedZones     []string            `json:"matched_zones"`
	DeadZones        []string            `json:"dead_zones"`
	Defective        map[string][]string `json:"defective"`
	SharedExcluded   []string            `json:"shared_excluded"`
	DisputedExcluded []string            `json:"disputed_excluded"`
	PromotedUsed     []string            `json:"promoted_used"`
	RTOSeen          bool                `json:"rto_seen"`
}

func main() {
	fs := flag.NewFlagSet("ruleset-check", flag.ExitOnError)
	directPath := fs.String("direct4", "", "direct4 文件")
	pslPath := fs.String("psl", "", "PSL 文件")
	manualPath := fs.String("manual", "", "人工区域文件")
	sharedPath := fs.String("shared", "", "shared anycast 文件")
	disputedPath := fs.String("disputed", "", "多源争议网段文件")
	promotedPath := fs.String("promoted", "", "多源晋级网段文件")
	agg := fs.Int("aggregate", 24, "大陆权威聚合前缀")
	_ = fs.Parse(os.Args[1:])
	if strings.TrimSpace(*directPath) == "" || strings.TrimSpace(*pslPath) == "" {
		fail("必须指定 --direct4 与 --psl")
	}
	directFile, err := os.Open(*directPath)
	if err != nil {
		fail(err.Error())
	}
	direct, err := ipset.LoadReader(directFile, ipset.LoadOptions{GlobalOnly: true})
	_ = directFile.Close()
	if err != nil {
		fail(err.Error())
	}
	psl, note := domain.LoadPSL([]string{*pslPath})
	if psl == nil {
		fail("PSL 不可用")
	}
	manual := map[string]struct{}{}
	if *manualPath != "" {
		f, e := os.Open(*manualPath)
		if e != nil {
			fail(e.Error())
		}
		manual, err = ruleset.LoadManual(f)
		_ = f.Close()
		if err != nil {
			fail(err.Error())
		}
	}
	shared := map[netip.Addr]struct{}{}
	if *sharedPath != "" {
		f, e := os.Open(*sharedPath)
		if e != nil {
			fail(e.Error())
		}
		shared, err = ruleset.LoadShared(f)
		_ = f.Close()
		if err != nil {
			fail(err.Error())
		}
	}
	disputed := loadCrossSet(*disputedPath, geoaudit.KindDisputed)
	promoted := loadCrossSet(*promotedPath, geoaudit.KindPromoted)
	snapshot, err := infra.Parse(os.Stdin)
	if err != nil {
		fail(err.Error())
	}
	result, err := ruleset.Build(snapshot, ruleset.Config{Direct: direct.Set, Disputed: disputed, Promoted: promoted, PSL: psl, ManualZones: manual, SharedAnycast: shared, Aggregate: *agg})
	if err != nil {
		fail(err.Error())
	}
	toStrings := func(prefixes []netip.Prefix) []string {
		out := make([]string, len(prefixes))
		for i, p := range prefixes {
			out[i] = p.String()
		}
		return out
	}
	zones := make([]string, len(result.MatchedZones))
	for i, z := range result.MatchedZones {
		zones[i] = z.Name
	}

	emptyIfNil := func(values []string) []string {
		if values == nil {
			return []string{}
		}
		return values
	}
	defective := result.Defective
	if defective == nil {
		defective = map[string][]string{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(output{RoutePrefixes: toStrings(result.RoutePrefixes), ECSPrefixes: toStrings(result.ECSPrefixes), MatchedZones: zones, DeadZones: emptyIfNil(result.DeadZones), Defective: defective, SharedExcluded: emptyIfNil(result.SharedExcluded), DisputedExcluded: emptyIfNil(result.DisputedExcluded), PromotedUsed: emptyIfNil(result.PromotedUsed), RTOSeen: result.RTOSeen})
	fmt.Fprintf(os.Stderr, "[信息] %s\n[信息] 区域 %d，直连 %d，ECS %d，争议剔除 %d，晋级采信 %d\n",
		note, len(zones), len(result.RoutePrefixes), len(result.ECSPrefixes),
		len(result.DisputedExcluded), len(result.PromotedUsed))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
