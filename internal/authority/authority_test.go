package authority

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/resolvetest"
)

type prefixMainland []string

func (p prefixMainland) IsMainland(addr netip.Addr) bool {
	for _, prefix := range p {
		if strings.HasPrefix(addr.String(), prefix) {
			return true
		}
	}
	return false
}

func rec(rtype uint16, rdata func(*resolvetest.Builder)) []resolvetest.Record {
	return []resolvetest.Record{{Type: rtype, RData: rdata}}
}

func TestAnyMainlandAuthorityMakesZoneCN(t *testing.T) {

	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4")),
			dnswire.TypeNS: {
				{Type: dnswire.TypeNS, RData: resolvetest.Target("ns1.qq.com")},
				{Type: dnswire.TypeNS, RData: resolvetest.Target("ns2.qq.com")},
				{Type: dnswire.TypeNS, RData: resolvetest.Target("ns3.qq.com")},
				{Type: dnswire.TypeNS, RData: resolvetest.Target("ns4.qq.com")},
			},
		}},
		"ns1.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("43.166.55.2"))}},
		"ns2.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("43.129.131.210"))}},
		"ns3.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("43.134.249.22"))}},
		"ns4.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.169.38.235"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"116."},
		"qq.com", nil, map[string]Verdict{})
	if got.Verdict != VerdictCN {
		t.Fatalf("verdict = %q, 期望 cn（reason=%s）", got.Verdict, got.Reason)
	}
	if got.Reason != "authority_in_cn(1/4)" {
		t.Fatalf("reason = %q", got.Reason)
	}
	if len(got.CNAuthorityIPs) != 1 || got.CNAuthorityIPs[0].String() != "116.169.38.235" {
		t.Fatalf("大陆权威 = %v", got.CNAuthorityIPs)
	}
}

func TestAllOffshoreAuthorityStaysUnknown(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"github.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("140.82.112.3")),
			dnswire.TypeNS: {
				{Type: dnswire.TypeNS, RData: resolvetest.Target("ns1.github.com")},
			},
		}},
		"ns1.github.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"116."},
		"github.com", nil, map[string]Verdict{})
	if got.Verdict != VerdictUnknown {
		t.Fatalf("境外权威不得晋级：verdict = %q", got.Verdict)
	}
	if len(got.CNAuthorityIPs) != 0 {
		t.Fatalf("不该有大陆权威: %v", got.CNAuthorityIPs)
	}
}

func TestDeadDomainNeverGetsCNVerdict(t *testing.T) {

	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"dead.example": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeNS: rec(dnswire.TypeNS, resolvetest.Target("ns.example"))}},
		"ns.example": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.1.1.1"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"116."},
		"dead.example", nil, map[string]Verdict{})
	if got.Verdict != VerdictUnknown || got.Reason != ReasonNoFinalAnswer {
		t.Fatalf("verdict=%q reason=%q", got.Verdict, got.Reason)
	}
}

func TestHiddenMasterAddressIsNotGeographicEvidence(t *testing.T) {

	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"alikunlun.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA:   rec(dnswire.TypeA, resolvetest.A("1.2.3.4")),
			dnswire.TypeSOA: rec(dnswire.TypeSOA, resolvetest.Target("hidden-master.aliyun.com")),
		}},
		"hidden-master.aliyun.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("127.0.0.1"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"127."},
		"alikunlun.com", nil, map[string]Verdict{})
	if got.Verdict != VerdictUnknown {
		t.Fatalf("非全局地址不得成为地理证据: verdict=%q reason=%q", got.Verdict, got.Reason)
	}
}

func TestFallsBackToSOAWhenNSAbsent(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"tencent-cloud.net": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA:   rec(dnswire.TypeA, resolvetest.A("1.2.3.4")),
			dnswire.TypeSOA: rec(dnswire.TypeSOA, resolvetest.Target("ns-open1.qq.com")),
		}},
		"ns-open1.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("125.39.202.140"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"125."},
		"tencent-cloud.net", nil, map[string]Verdict{})
	if got.Verdict != VerdictCN {
		t.Fatalf("只返回 SOA 的区域必须能判定: verdict=%q reason=%q", got.Verdict, got.Reason)
	}
}

func TestPublicSuffixZoneNeverSuppliesCNVerdict(t *testing.T) {
	psl := domain.ParsePSL("cn\ncom.cn\ncom\n", "test")
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"foo.com.cn": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"com.cn": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeNS: rec(dnswire.TypeNS, resolvetest.Target("a.dns.cn"))}},
		"a.dns.cn": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.0.0.1"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"116."},
		"foo.com.cn", psl, map[string]Verdict{})
	if got.Verdict != VerdictUnknown {
		t.Fatalf("公共后缀的权威位置不是该域名的证据: verdict=%q zone=%q", got.Verdict, got.Zone)
	}
	if got.Zone == "com.cn" {
		t.Fatal("判定不得停在公共后缀上")
	}
}

func TestNeverJudgesByTLDAuthority(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"example.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeNS: rec(dnswire.TypeNS, resolvetest.Target("a.gtld-servers.net"))}},
		"a.gtld-servers.net": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.0.0.1"))}},
	})
	got := ClassifyOne(context.Background(), client, prefixMainland{"116."},
		"example.com", nil, map[string]Verdict{})
	if got.Verdict != VerdictUnknown || got.Zone == "com" {
		t.Fatalf("不得拿 TLD 权威判定: verdict=%q zone=%q", got.Verdict, got.Zone)
	}
}

func TestCollapseKeepsSingleLabelZonesWhenMultiLabelPresent(t *testing.T) {

	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.1.1.1"))}},
		"baidu.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("2.2.2.2"))}},
		"alipay.com.cn": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("3.3.3.3"))}},
	})
	got := CollapseByResolution(context.Background(), client,
		[]string{"qq.com", "baidu.com", "alipay.com.cn"}, 3)
	want := []string{"alipay.com.cn", "baidu.com", "qq.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("折叠结果 = %v, 期望 %v", got, want)
	}
}

func TestCollapseNeverMergesIntoAParentOutsideTheSet(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"a.example.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"example.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
	})
	alone := CollapseByResolution(context.Background(), client,
		[]string{"a.example.com"}, 2)
	if strings.Join(alone, ",") != "a.example.com" {
		t.Fatalf("父域不在集合里时不得折叠: %v", alone)
	}
	together := CollapseByResolution(context.Background(), client,
		[]string{"a.example.com", "example.com"}, 2)
	if strings.Join(together, ",") != "example.com" {
		t.Fatalf("父域在集合里且同 IP 时应折叠: %v", together)
	}
}

func TestCollapseDropsDomainsWithoutAnswers(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"live.example": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"dead.example": {},
	})
	got := CollapseByResolution(context.Background(), client,
		[]string{"dead.example", "live.example"}, 2)
	if strings.Join(got, ",") != "live.example" {
		t.Fatalf("无应答域名应被剔除: %v", got)
	}
}

func TestLandingIsMainlandHasThreeStates(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"cn.example": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.1.1.1"))}},
		"off.example": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"silent.example": {Silent: true},
	})
	ctx := context.Background()
	m := prefixMainland{"116."}
	if mainland, known := LandingIsMainland(ctx, client, m, "cn.example"); !mainland || !known {
		t.Fatalf("大陆落点判定错误: mainland=%v known=%v", mainland, known)
	}
	if mainland, known := LandingIsMainland(ctx, client, m, "off.example"); mainland || !known {
		t.Fatalf("境外落点判定错误: mainland=%v known=%v", mainland, known)
	}

	if mainland, known := LandingIsMainland(ctx, client, m, "silent.example"); mainland || known {
		t.Fatalf("取不到答案时必须报未知: mainland=%v known=%v", mainland, known)
	}
}

func TestClassifyManyReusesZoneVerdicts(t *testing.T) {
	client := resolvetest.Serve(t, map[string]resolvetest.Zone{
		"qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA:  rec(dnswire.TypeA, resolvetest.A("1.2.3.4")),
			dnswire.TypeNS: rec(dnswire.TypeNS, resolvetest.Target("ns4.qq.com")),
		}},
		"ns4.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("116.169.38.235"))}},
		"www.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
		"im.qq.com": {Records: map[uint16][]resolvetest.Record{
			dnswire.TypeA: rec(dnswire.TypeA, resolvetest.A("1.2.3.4"))}},
	})
	got := ClassifyMany(context.Background(), client, prefixMainland{"116."},
		[]string{"www.qq.com", "im.qq.com"}, nil, 2)
	for _, v := range got {
		if v.Verdict != VerdictCN {
			t.Fatalf("%s verdict=%q reason=%q", v.Domain, v.Verdict, v.Reason)
		}
		if v.Zone != "qq.com" {
			t.Fatalf("%s 应回退到父域判定，实际 zone=%q", v.Domain, v.Zone)
		}
	}
}
