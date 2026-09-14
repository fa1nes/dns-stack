package cdnhit

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func testSet(t *testing.T, withMainland bool) *cdnrules.Set {
	t.Helper()
	steered := cdnrules.Provider{
		ID: "steered", Name: "有大陆节点的 CDN",
		Domains:  []string{"steered.example"},
		Offshore: prefixes(t, "203.0.113.0/24"),
	}
	if withMainland {
		steered.Mainland = prefixes(t,
			"116.116.116.0/24", "116.116.117.0/24", "116.116.118.0/24", "116.116.119.0/24")
	}
	return cdnrules.New(time.Unix(1_700_000_000, 0), []cdnrules.Provider{
		steered,
		{
			ID: "offshoreonly", Name: "只有境外节点的 CDN",
			Domains:  []string{"offshore.example"},
			Offshore: prefixes(t, "198.51.100.0/24"),
		},
		{
			ID: "thin", Name: "只有一条大陆段的 CDN",
			Domains:  []string{"thin.example"},
			Mainland: prefixes(t, "116.116.200.0/24"),
			Offshore: prefixes(t, "198.51.101.0/24"),
		},
	})
}

func answers(m map[string][]string) Resolver {
	return func(_ context.Context, name string, _ netip.Prefix) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, value := range m[name] {
			out = append(out, netip.MustParseAddr(value))
		}
		return out, nil
	}
}

func run(t *testing.T, set *cdnrules.Set, resolve Resolver, probes ...Probe) Report {
	t.Helper()
	report, err := Run(context.Background(), Options{
		Set: set, Probes: probes, Resolve: resolve,
		Now: func() time.Time { return time.Unix(1_700_000_100, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestStrandedIsTheVerdictWhenTheCDNHasMainlandNodesButAnswersOffshore(t *testing.T) {
	set := testSet(t, true)
	resolve := answers(map[string][]string{
		"a.steered.example":  {"116.116.116.9"},
		"b.steered.example":  {"203.0.113.9"},
		"c.offshore.example": {"198.51.100.9"},
	})
	report := run(t, set, resolve,
		Probe{"a.steered.example", "命中"},
		Probe{"b.steered.example", "落空"},
		Probe{"c.offshore.example", "本来就没有大陆节点"},
	)

	want := []Verdict{VerdictMainland, VerdictStranded, VerdictOffshore}
	for i, expected := range want {
		if report.Probes[i].Verdict != expected {
			t.Errorf("%s: 判定为 %s，期望 %s",
				report.Probes[i].Domain, report.Probes[i].Verdict, expected)
		}
	}
	if report.Mainland != 1 || report.Stranded != 1 || report.Comparable != 2 {
		t.Fatalf("计数不对: mainland=%d stranded=%d comparable=%d",
			report.Mainland, report.Stranded, report.Comparable)
	}
	if report.Probes[2].Verdict.Bad() {
		t.Fatal("该 CDN 本来就没有大陆段，拿到境外节点不是缺陷，不能报警")
	}
}

func TestWithoutMainlandEvidenceTheSameAnswerCannotBeCalledAHit(t *testing.T) {
	resolve := answers(map[string][]string{"a.steered.example": {"116.116.116.9"}})
	probe := Probe{"a.steered.example", "命中"}

	hit := run(t, testSet(t, true), resolve, probe)
	if hit.Probes[0].Verdict != VerdictMainland {
		t.Fatalf("阳性方向失效: %s", hit.Probes[0].Verdict)
	}

	miss := run(t, testSet(t, false), resolve, probe)
	if miss.Probes[0].Verdict == VerdictMainland {
		t.Fatal("阴性对照失效：规则集里没有大陆段时，同一个地址不该被判成命中大陆节点")
	}
	if miss.Mainland != 0 {
		t.Fatalf("阴性对照下 mainland 计数应为 0，得到 %d", miss.Mainland)
	}
}

func mainlandSet(t *testing.T, prefixes ...string) *ipset.Set {
	t.Helper()
	ranges := make([]ipset.Range, 0, len(prefixes))
	for _, value := range prefixes {
		rg, ok := ipset.PrefixRange(netip.MustParsePrefix(value))
		if !ok {
			t.Fatalf("无法转换 %s", value)
		}
		ranges = append(ranges, rg)
	}
	return ipset.New(ranges)
}

func runWith(t *testing.T, set *cdnrules.Set, mainland *ipset.Set, resolve Resolver, probes ...Probe) Report {
	t.Helper()
	report, err := Run(context.Background(), Options{
		Set: set, Mainland: mainland, Probes: probes, Resolve: resolve,
		Now: func() time.Time { return time.Unix(1_700_000_100, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestCarrierHostedMainlandNodeCountsAsAHitNotAMismatch(t *testing.T) {
	const carrier = "220.181.10.93"
	resolve := answers(map[string][]string{"a.steered.example": {carrier}})
	probe := Probe{"a.steered.example", "节点在运营商机房"}

	direct4 := mainlandSet(t, "220.181.10.0/24")
	got := runWith(t, testSet(t, true), direct4, resolve, probe).Probes[0]
	if got.Verdict != VerdictMainland {
		t.Fatalf("国产 CDN 大多把节点放在运营商机房、用运营商的 IP，规则集按 ASN 拉不到那些段。"+
			"要回答的是「用户拿到的是不是大陆节点」，不是「这个 IP 属不属于该 CDN 的 ASN」: %s",
			got.Verdict)
	}

	without := runWith(t, testSet(t, true), nil, resolve, probe).Probes[0]
	if without.Verdict == VerdictMismatch {
		t.Fatal("没有 direct4 就排除不掉「其实在大陆」，此时必须弃权而不是报成可疑地址")
	}
	if without.Verdict != VerdictUnknown {
		t.Fatalf("缺少大陆网段时应弃权: %s", without.Verdict)
	}
}

func TestOffshoreAnswerOutsideTheProviderRangesIsFlaggedNotSilentlyPassed(t *testing.T) {
	resolve := answers(map[string][]string{"a.steered.example": {"8.8.8.8"}})
	direct4 := mainlandSet(t, "220.181.10.0/24")
	report := runWith(t, testSet(t, true), direct4, resolve,
		Probe{"a.steered.example", "投毒或自建源站"})
	if report.Probes[0].Verdict != VerdictMismatch {
		t.Fatalf("已确认不在大陆、又不属于该 CDN 的地址必须单列出来: %s", report.Probes[0].Verdict)
	}
	if report.Comparable != 0 {
		t.Fatal("判不出归属的样本不能计入就近率的分母，否则分母被稀释后比率会虚高")
	}
}

func TestUnresolvedProbeDoesNotCountAsEitherSide(t *testing.T) {
	resolve := answers(map[string][]string{})
	report := run(t, testSet(t, true), resolve, Probe{"a.steered.example", "解析失败"})
	if report.Probes[0].Verdict != VerdictUnresolved {
		t.Fatalf("verdict=%s", report.Probes[0].Verdict)
	}
	if report.Mainland+report.Stranded+report.Comparable != 0 {
		t.Fatal("解析失败是判据缺席，不是被检对象的失败，两侧都不能计数")
	}
}

func TestEmptyRulesetRefusesToReportInsteadOfPassingEverything(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Set:     cdnrules.New(time.Unix(0, 0), nil),
		Probes:  DefaultProbes,
		Resolve: answers(map[string][]string{}),
	})
	if err == nil {
		t.Fatal("规则集为空时必须报错；静默返回全绿的报告是最坏的一种通过")
	}
}

func TestASingleMainlandPrefixIsNotEvidenceThatTheCDNServesTheMainland(t *testing.T) {
	resolve := answers(map[string][]string{"a.thin.example": {"198.51.101.9"}})
	report := run(t, testSet(t, true), resolve, Probe{"a.thin.example", "只有一条大陆段"})
	got := report.Probes[0]
	if got.Verdict == VerdictStranded {
		t.Fatal("一条 /24 可能只是测试段或边缘案例，据此断言「本该给大陆节点」会把正常的全球 " +
			"anycast 答案报成缺陷；生产上 Cloudflare 正是这样被误报的")
	}
	if got.Verdict != VerdictThin {
		t.Fatalf("弃权要留下痕迹，让人看得出为什么不判: %s", got.Verdict)
	}
	if got.HasMainland {
		t.Fatal("展示用的「有大陆节点」也该按同一条线收敛，否则面板上的徽章与判定自相矛盾")
	}
	if got.MainlandNum != 1 {
		t.Fatalf("原始条数要如实报出，供人判断阈值是否合适: %d", got.MainlandNum)
	}
	if report.Comparable != 0 {
		t.Fatal("弃权的样本不能进就近率的分母")
	}
}

func TestZeroTimeoutFallsBackInsteadOfExpiringImmediately(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("拿不到本地 UDP 端口: %v", err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		time.Sleep(80 * time.Millisecond)
		server.WriteTo(buf[:n], addr)
	}()

	_, err = Query(context.Background(), server.LocalAddr().String(),
		"example.com", BeijingTelecomPrefix, 0)
	if err != nil && strings.Contains(err.Error(), "timeout") {
		t.Fatalf("timeout=0 被当成了「立刻过期」而不是「用默认值」，"+
			"调用方每一次探测都会瞬间失败并报成解析不出来: %v", err)
	}
}

func TestDefaultSubnetIsARealChinesePrefix(t *testing.T) {
	report := run(t, testSet(t, true), answers(map[string][]string{}), Probe{"x.steered.example", "x"})
	if report.Subnet != BeijingTelecom {
		t.Fatalf("默认子网必须是真实中国网段，得到 %s", report.Subnet)
	}
	if !netip.MustParsePrefix(BeijingTelecom).Addr().Is4() {
		t.Fatal("ECS 就近判据只在 IPv4 上成立")
	}
}
