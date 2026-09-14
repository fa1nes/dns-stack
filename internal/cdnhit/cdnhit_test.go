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

func testSet(t *testing.T) *cdnrules.Set {
	t.Helper()
	return cdnrules.New(time.Unix(1_700_000_000, 0), []cdnrules.Provider{
		{
			ID: "big", Name: "有大陆节点的 CDN",
			Domains: []string{"big.example"},
			Mainland: prefixes(t,
				"116.116.116.0/24", "116.116.117.0/24", "116.116.118.0/24", "116.116.119.0/24"),
			Offshore: prefixes(t, "203.0.113.0/24"),
		},
		{
			ID: "thin", Name: "只有一条大陆段的 CDN",
			Domains:  []string{"thin.example"},
			Mainland: prefixes(t, "116.116.200.0/24"),
			Offshore: prefixes(t, "198.51.101.0/24"),
		},
	})
}

func mainlandSet(t *testing.T, values ...string) *ipset.Set {
	t.Helper()
	ranges := make([]ipset.Range, 0, len(values))
	for _, value := range values {
		rg, ok := ipset.PrefixRange(netip.MustParsePrefix(value))
		if !ok {
			t.Fatalf("无法转换 %s", value)
		}
		ranges = append(ranges, rg)
	}
	return ipset.New(ranges)
}

func replies(m map[string][]string, scope int, echoed bool) Resolver {
	return func(_ context.Context, name string, _ netip.Prefix) (Answer, error) {
		out := Answer{Scope: scope, Echoed: echoed}
		for _, value := range m[name] {
			out.Addrs = append(out.Addrs, netip.MustParseAddr(value))
		}
		return out, nil
	}
}

func run(t *testing.T, mainland *ipset.Set, resolve Resolver, probes ...Probe) Report {
	t.Helper()
	report, err := Run(context.Background(), Options{
		Set: testSet(t), Mainland: mainland, Probes: probes, Resolve: resolve,
		Now: func() time.Time { return time.Unix(1_700_000_100, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestMainlandAnswerWinsRegardlessOfWhoAnnouncesIt(t *testing.T) {
	direct4 := mainlandSet(t, "220.181.10.0/24")

	byRuleset := run(t, direct4, replies(
		map[string][]string{"a.big.example": {"116.116.116.9"}}, 24, true),
		Probe{"a.big.example", "落在规则集的大陆段"}).Probes[0]
	if byRuleset.Verdict != VerdictMainland {
		t.Fatalf("规则集自己的大陆段应当命中: %s", byRuleset.Verdict)
	}

	byDirect4 := run(t, direct4, replies(
		map[string][]string{"a.big.example": {"220.181.10.93"}}, 24, true),
		Probe{"a.big.example", "节点在运营商机房"}).Probes[0]
	if byDirect4.Verdict != VerdictMainland {
		t.Fatalf("国产 CDN 与 Akamai 中国节点都用运营商 IP，按 ASN 永远拉不到。"+
			"要回答的是「用户拿到的是不是大陆节点」: %s", byDirect4.Verdict)
	}
	if byDirect4.Mismatch {
		t.Fatal("在大陆的地址不该被标成「不属于该 CDN」——那是给境外可疑地址用的")
	}
}

func TestScopeDecidesWhyAnOffshoreAnswerHappened(t *testing.T) {
	direct4 := mainlandSet(t, "220.181.10.0/24")
	body := map[string][]string{"a.big.example": {"203.0.113.9"}}
	probe := Probe{"a.big.example", "境外落点"}

	cases := []struct {
		scope  int
		echoed bool
		want   Verdict
		why    string
	}{
		{0, false, VerdictStranded,
			"权威没回显 ECS，说明它压根没收到子网，只能按隧道出口调度——这才是我们能修的缺陷"},
		{0, true, VerdictNoSteering,
			"scope=0 是权威收到了却声明不按位置调度（全球 anycast），不是缺陷"},
		{24, true, VerdictNoNode,
			"scope=24 说明权威按子网挑过了仍给境外，只能说明这个服务在大陆没有节点"},
	}
	for _, item := range cases {
		got := run(t, direct4, replies(body, item.scope, item.echoed), probe).Probes[0]
		if got.Verdict != item.want {
			t.Errorf("scope=%d echoed=%v: 判为 %s，期望 %s —— %s",
				item.scope, item.echoed, got.Verdict, item.want, item.why)
		}
	}
}

func TestOnlyTheUndeliveredCaseIsADefect(t *testing.T) {
	for verdict, bad := range map[Verdict]bool{
		VerdictStranded:   true,
		VerdictNoSteering: false,
		VerdictNoNode:     false,
		VerdictMainland:   false,
		VerdictUnresolved: false,
	} {
		if verdict.Bad() != bad {
			t.Errorf("%s.Bad() = %v，期望 %v", verdict, verdict.Bad(), bad)
		}
	}
}

func TestTheVerdictNeverBlamesTheCDNForHavingNoMainlandPrefixes(t *testing.T) {
	direct4 := mainlandSet(t, "220.181.10.0/24")
	got := run(t, direct4, replies(map[string][]string{"www.example.org": {"8.8.8.8"}}, 0, false),
		Probe{"www.example.org", "规则集里没有这家"}).Probes[0]
	if got.Verdict != VerdictStranded {
		t.Fatalf("规则集拉不到某家 CDN 的大陆段是规则集的局限，不是放过 ECS 缺陷的理由。"+
			"Akamai 的中国节点由网宿代运营，AS20940 一条都拉不到，"+
			"而 www.huawei.com 走的正是 Akamai: %s", got.Verdict)
	}
	if got.Mismatch {
		t.Fatal("这个域名本来就不属于任何已知 CDN，答案不在 CDN 段里是正常的（自建源站），" +
			"标成可疑会把判据变成噪音")
	}
}

func TestMismatchNeedsTheDomainToBelongToACDNInTheFirstPlace(t *testing.T) {
	direct4 := mainlandSet(t, "220.181.10.0/24")
	got := run(t, direct4, replies(map[string][]string{"a.big.example": {"8.8.8.8"}}, 24, true),
		Probe{"a.big.example", "域名属于该 CDN，落点却不属于它"}).Probes[0]
	if !got.Mismatch {
		t.Fatal("域名归某家 CDN、答案却不在那家 CDN 的任何段里——这才是值得看一眼的信号")
	}
	if got.Verdict != VerdictNoNode {
		t.Fatalf("归属可疑是副标注，不该改变就近判定本身: %s", got.Verdict)
	}
}

func TestOnlyMainlandAndStrandedCountTowardsTheRate(t *testing.T) {
	direct4 := mainlandSet(t, "220.181.10.0/24")
	report := run(t, direct4, func(_ context.Context, name string, _ netip.Prefix) (Answer, error) {
		switch name {
		case "hit.big.example":
			return Answer{Addrs: []netip.Addr{netip.MustParseAddr("116.116.116.9")}, Scope: 24, Echoed: true}, nil
		case "miss.big.example":
			return Answer{Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}, nil
		default:
			return Answer{Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}, Scope: 24, Echoed: true}, nil
		}
	},
		Probe{"hit.big.example", "命中"},
		Probe{"miss.big.example", "ECS 没送达"},
		Probe{"nonode.big.example", "大陆本来就没节点"},
	)
	if report.Mainland != 1 || report.Stranded != 1 || report.Comparable != 2 {
		t.Fatalf("大陆本来就没节点的样本不能进分母，否则就近率会被结构性地拉低: "+
			"mainland=%d stranded=%d comparable=%d",
			report.Mainland, report.Stranded, report.Comparable)
	}
}

func TestUnresolvedProbeCountsForNeitherSide(t *testing.T) {
	report := run(t, mainlandSet(t, "220.181.10.0/24"),
		replies(map[string][]string{}, 0, false), Probe{"a.big.example", "解析失败"})
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
		Resolve: replies(map[string][]string{}, 0, false),
	})
	if err == nil {
		t.Fatal("规则集为空时必须报错；静默返回全绿的报告是最坏的一种通过")
	}
}

func TestASingleMainlandPrefixDoesNotEarnTheMainlandBadge(t *testing.T) {
	got := run(t, mainlandSet(t, "220.181.10.0/24"),
		replies(map[string][]string{"a.thin.example": {"198.51.101.9"}}, 24, true),
		Probe{"a.thin.example", "只有一条大陆段"}).Probes[0]
	if got.HasMainland {
		t.Fatal("一条 /24 可能只是测试段，面板上标成「有大陆节点」会误导；" +
			"Cloudflare 正是这样：唯一那条大陆段与它的中国业务并不是一回事")
	}
	if got.MainlandNum != 1 {
		t.Fatalf("原始条数仍要如实报出，供人判断阈值是否合适: %d", got.MainlandNum)
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
		"example.com", BeijingTelecom4, 0)
	if err != nil && strings.Contains(err.Error(), "timeout") {
		t.Fatalf("timeout=0 被当成了「立刻过期」而不是「用默认值」，"+
			"调用方每一次探测都会瞬间失败并报成解析不出来: %v", err)
	}
}

func TestVantagesAreRealChineseIPv4Prefixes(t *testing.T) {
	if len(Vantages) != 3 {
		t.Fatalf("面板只提供北京三网这三个观测点，得到 %d 个", len(Vantages))
	}
	seen := map[string]struct{}{}
	for _, item := range Vantages {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			t.Fatalf("%s 不是合法前缀: %v", item.Prefix, err)
		}
		if !prefix.Addr().Is4() {
			t.Fatalf("%s 不是 IPv4——ECS 就近判据只在 IPv4 上成立", item.Prefix)
		}
		if prefix.Bits() != 24 {
			t.Fatalf("%s 必须是 /24，与真实客户端子网粒度一致", item.Prefix)
		}
		if !ipset.IsGlobalPrefix(prefix) {
			t.Fatalf("%s 不是全局可路由地址，拿它当客户端子网等于没测", item.Prefix)
		}
		if _, dup := seen[item.Prefix]; dup {
			t.Fatalf("%s 重复", item.Prefix)
		}
		seen[item.Prefix] = struct{}{}
		if item.Label == "" {
			t.Fatalf("%s 没有标签", item.Prefix)
		}
	}
	if Vantages[0].Prefix != BeijingTelecom {
		t.Fatalf("默认观测点应是北京电信，得到 %s", Vantages[0].Prefix)
	}
}
