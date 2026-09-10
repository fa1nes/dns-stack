package ruleset

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	set := ipset.New([]ipset.Range{{Lo: 0x01010100, Hi: 0x010101ff}, {Lo: 0x74747400, Hi: 0x747474ff}})
	psl := domain.ParsePSL("com\ntld.example\n", "test")
	return Config{Direct: set, PSL: psl, Aggregate: 24, ManualZones: map[string]struct{}{}, SharedAnycast: map[netip.Addr]struct{}{}}
}

func parseInfra(t *testing.T, text string) infra.Snapshot {
	t.Helper()
	s, err := infra.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildGuardsForeignAndPublicSuffix(t *testing.T) {
	cfg := testConfig(t)
	s := parseInfra(t, strings.Join([]string{
		"1.1.1.1 good.com. rto 10",
		"8.8.8.8 foreign.com. rto 10",
		"1.1.1.1 com. rto 10",
	}, "\n"))
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MatchedZones) != 1 || r.MatchedZones[0].Name != "good.com" {
		t.Fatalf("matched=%#v", r.MatchedZones)
	}
	if len(r.RoutePrefixes) != 1 || r.RoutePrefixes[0].String() != "1.1.1.0/24" {
		t.Fatalf("route=%v", r.RoutePrefixes)
	}
	if len(r.Defective[domain.DefectSingleLabel]) != 1 {
		t.Fatalf("defective=%#v", r.Defective)
	}
}

func TestECSDoesNotReuseAggregatedRoutePrefix(t *testing.T) {
	direct := ipset.New([]ipset.Range{{Lo: 0x01010101, Hi: 0x01010101}})
	cfg := Config{
		Direct: direct, PSL: domain.ParsePSL("com\n", "test"), Aggregate: 24,
		ManualZones: map[string]struct{}{}, SharedAnycast: map[netip.Addr]struct{}{},
	}
	r, err := Build(parseInfra(t, "1.1.1.1 good.com. rto 10"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.RoutePrefixes) != 1 || r.RoutePrefixes[0].String() != "1.1.1.0/24" {
		t.Fatalf("route aggregation changed: %v", r.RoutePrefixes)
	}
	for _, prefix := range r.ECSPrefixes {
		if prefix.Contains(netip.MustParseAddr("1.1.1.2")) {
			t.Fatalf("aggregated route prefix widened ECS whitelist: %v", prefix)
		}
	}
	if len(r.ECSPrefixes) != 1 || r.ECSPrefixes[0].String() != "1.1.1.1/32" {
		t.Fatalf("unexpected ECS prefixes: %v", r.ECSPrefixes)
	}
}

func TestECSRejectsNonGlobalAuthorityAddresses(t *testing.T) {
	cfg := testConfig(t)
	r, err := Build(parseInfra(t, strings.Join([]string{
		"1.1.1.1 mixed.com. rto 10",
		"10.0.0.1 mixed.com. rto 10",
	}, "\n")), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range r.ECSPrefixes {
		if prefix.Contains(netip.MustParseAddr("10.0.0.1")) {
			t.Fatalf("non-global authority leaked into ECS whitelist: %v", prefix)
		}
	}

	for _, prefix := range r.RoutePrefixes {
		if prefix.Contains(netip.MustParseAddr("10.0.0.1")) {
			t.Fatalf("non-global authority leaked into route set: %v", prefix)
		}
	}
	if len(r.MatchedZones) != 1 || r.MatchedZones[0].Name != "mixed.com" {
		t.Fatalf("zone with one CN authority must stay matched: %#v", r.MatchedZones)
	}
}

func TestBuildDeadZoneAndSharedExclusion(t *testing.T) {
	cfg := testConfig(t)
	shared := netip.MustParseAddr("9.9.9.9")
	cfg.SharedAnycast[shared] = struct{}{}
	s := parseInfra(t, strings.Join([]string{
		"1.1.1.1 dead.com. rto 120000",
		"1.1.1.1 live.com. rto 10",
		"9.9.9.9 live.com. rto 10",
		"9.9.9.9 live.com. rto 10",
	}, "\n"))
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.DeadZones) != 1 || r.DeadZones[0] != "dead.com" {
		t.Fatalf("dead=%v", r.DeadZones)
	}
	if len(r.SharedExcluded) != 1 || r.SharedExcluded[0] != shared.String() {
		t.Fatalf("shared=%v", r.SharedExcluded)
	}
	for _, p := range r.RoutePrefixes {
		if p.Contains(shared) {
			t.Fatalf("shared address leaked into route: %v", p)
		}
	}
	found := false
	for _, p := range r.ECSPrefixes {
		if p.Contains(shared) {
			found = true
		}
	}
	if !found {
		t.Fatal("shared address missing from ECS")
	}
}

func TestManualSuffixForcesForeignAuthority(t *testing.T) {
	cfg := testConfig(t)
	cfg.ManualZones["manual.testzone"] = struct{}{}
	s := parseInfra(t, "8.8.8.8 edge.manual.testzone. rto 20")
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MatchedZones) != 1 || !r.MatchedZones[0].Forced {
		t.Fatalf("matched=%#v", r.MatchedZones)
	}
}

func TestMissingRTODoesNotDropZone(t *testing.T) {
	cfg := testConfig(t)
	s := parseInfra(t, "1.1.1.1 live.com. ttl 10")
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MatchedZones) != 1 {
		t.Fatalf("matched=%#v", r.MatchedZones)
	}
}

func TestIPv6DoesNotKeepDeadIPv4ZoneAlive(t *testing.T) {
	cfg := testConfig(t)
	s := parseInfra(t, strings.Join([]string{
		"1.1.1.1 dead.com. rto 120000",
		"2a00:86c0:2009::1 dead.com. rto 10",
	}, "\n"))
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.DeadZones) != 1 || r.DeadZones[0] != "dead.com" {
		t.Fatalf("dead=%v matched=%v", r.DeadZones, r.MatchedZones)
	}
}

func TestDisputedAuthorityLosesECSButKeepsRoute(t *testing.T) {
	cfg := testConfig(t)
	cfg.Disputed = ipset.New([]ipset.Range{{Lo: 0x01010101, Hi: 0x01010101}})
	victim := netip.MustParseAddr("1.1.1.1")
	r, err := Build(parseInfra(t, strings.Join([]string{
		"1.1.1.1 yimg.com. rto 10",
		"116.116.116.1 mixed.com. rto 10",
		"1.1.1.1 mixed.com. rto 10",
	}, "\n")), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.ECSPrefixes {
		if p.Contains(victim) {
			t.Fatalf("争议地址仍被 ECS 白名单的 %v 覆盖（direct4 冷启动段没有扣掉）", p)
		}
	}
	if len(r.DisputedExcluded) != 1 || r.DisputedExcluded[0] != victim.String() {
		t.Fatalf("disputed=%v", r.DisputedExcluded)
	}
	routed := false
	for _, p := range r.RoutePrefixes {
		if p.Contains(victim) {
			routed = true
		}
	}
	if !routed {
		t.Fatal("争议地址被踢出了直连路由，主人选定的口径是只挡 ECS")
	}
	for _, zone := range r.MatchedZones {
		if zone.Name == "yimg.com" {
			t.Fatal("唯一的大陆证据是争议地址，该区域不得晋级")
		}
	}
	if len(r.MatchedZones) != 1 || r.MatchedZones[0].Name != "mixed.com" {
		t.Fatalf("还有非争议大陆权威的区域必须照常晋级: %#v", r.MatchedZones)
	}
}

func TestWithoutDisputedSetNothingChanges(t *testing.T) {
	cfg := testConfig(t)
	victim := netip.MustParseAddr("1.1.1.1")
	r, err := Build(parseInfra(t, "1.1.1.1 yimg.com. rto 10"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.DisputedExcluded) != 0 {
		t.Fatalf("没有争议清单时不得排除任何地址: %v", r.DisputedExcluded)
	}
	if len(r.MatchedZones) != 1 {
		t.Fatalf("matched=%#v", r.MatchedZones)
	}
	covered := false
	for _, p := range r.ECSPrefixes {
		if p.Contains(victim) {
			covered = true
		}
	}
	if !covered {
		t.Fatal("fail-open 失效：没有争议清单时判据必须与只信 APNIC 完全一致")
	}
}

func TestPromotedAddressCountsAsMainlandEvidence(t *testing.T) {
	cfg := testConfig(t)
	promoted := netip.MustParseAddr("203.0.200.1")
	cfg.Promoted = ipset.New([]ipset.Range{{Lo: 0xcb00c801, Hi: 0xcb00c801}})
	r, err := Build(parseInfra(t, "203.0.200.1 promoted.com. rto 10"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MatchedZones) != 1 || r.MatchedZones[0].Name != "promoted.com" {
		t.Fatalf("direct4 外但全源一致的大陆地址必须能让区域晋级: %#v", r.MatchedZones)
	}
	if len(r.PromotedUsed) != 1 || r.PromotedUsed[0] != promoted.String() {
		t.Fatalf("promoted=%v", r.PromotedUsed)
	}
	found := false
	for _, p := range r.ECSPrefixes {
		if p.Contains(promoted) {
			found = true
		}
	}
	if !found {
		t.Fatal("晋级地址应与 direct4 内地址同等对待，可以收 ECS")
	}
}

func TestDisputedWinsWhenBothListsClaimTheSameAddress(t *testing.T) {
	cfg := testConfig(t)
	addr := netip.MustParseAddr("1.1.1.1")
	cfg.Disputed = ipset.New([]ipset.Range{{Lo: 0x01010101, Hi: 0x01010101}})
	cfg.Promoted = ipset.New([]ipset.Range{{Lo: 0x01010101, Hi: 0x01010101}})
	r, err := Build(parseInfra(t, strings.Join([]string{
		"1.1.1.1 both.com. rto 10",
		"116.116.116.1 both.com. rto 10",
	}, "\n")), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.ECSPrefixes {
		if p.Contains(addr) {
			t.Fatalf("两份清单矛盾时必须取更保守的一侧，%v 不该收 ECS", p)
		}
	}
	if len(r.DisputedExcluded) != 1 || len(r.PromotedUsed) != 0 {
		t.Fatalf("disputed=%v promoted=%v", r.DisputedExcluded, r.PromotedUsed)
	}
}

func TestIPv6OnlyZoneIsSkipped(t *testing.T) {
	cfg := testConfig(t)
	cfg.ManualZones["ipv6.testzone"] = struct{}{}
	s := parseInfra(t, "2001:db8::1 ipv6.testzone. rto 10")
	r, err := Build(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MatchedZones) != 0 || len(r.RoutePrefixes) != 0 || len(r.ECSPrefixes) != len(cfg.Direct.Prefixes()) {
		t.Fatalf("ipv6-only zone leaked into result: matched=%v route=%v ecs=%v", r.MatchedZones, r.RoutePrefixes, r.ECSPrefixes)
	}
}
