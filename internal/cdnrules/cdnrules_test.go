package cdnrules

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", v, err)
		}
		out = append(out, p.Masked())
	}
	return out
}

func mustAddr(t *testing.T, v string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(v)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", v, err)
	}
	return a
}

func sampleSet(t *testing.T) *Set {
	t.Helper()
	return New(time.Unix(1757000000, 0), []Provider{
		{
			ID: "akamai", Name: "Akamai",
			Domains:  []string{"akamaiedge.net", "edgekey.net"},
			Mainland: mustPrefixes(t, "23.56.0.0/16"),
			Offshore: mustPrefixes(t, "2.16.0.0/13", "23.32.0.0/12"),
		},
		{
			ID: "alibaba", Name: "阿里云",
			Domains: []string{"alicdn.com", "alikunlun.com"},
		},
	})
}

func TestClassifyMainlandOffshoreAndMismatch(t *testing.T) {
	s := sampleSet(t)
	cases := []struct {
		name string
		addr string
		want Verdict
	}{
		{"e123.dscb.akamaiedge.net", "23.56.1.1", VerdictMainland},
		{"e123.dscb.akamaiedge.net", "23.33.0.1", VerdictOffshore},
		{"e123.dscb.akamaiedge.net", "8.8.8.8", VerdictMismatch},
		{"www.qq.com", "23.56.1.1", VerdictUnknown},
	}
	for _, c := range cases {
		got := s.Classify(c.name, mustAddr(t, c.addr))
		if got.Verdict != c.want {
			t.Errorf("Classify(%s, %s) = %s，期望 %s", c.name, c.addr, got.Verdict, c.want)
		}
	}
}

func TestProviderWithoutPrefixesAbstainsInsteadOfVotingMismatch(t *testing.T) {
	s := sampleSet(t)
	got := s.Classify("img.alicdn.com", mustAddr(t, "120.55.0.1"))
	if got.Verdict != VerdictUnknown {
		t.Fatalf("阿里云没有任何前缀证据时应弃权，却判成 %s——查不到不等于投反对票", got.Verdict)
	}
	if got.Provider != "alibaba" {
		t.Errorf("即便弃权也应记录域名归属，得到 %q", got.Provider)
	}
}

func TestOwnerPrefersTheMostSpecificPrefix(t *testing.T) {
	s := New(time.Unix(1757000000, 0), []Provider{
		{ID: "wide", Name: "Wide", Domains: []string{"wide.test"}, Offshore: mustPrefixes(t, "10.0.0.0/8")},
		{ID: "narrow", Name: "Narrow", Domains: []string{"narrow.test"}, Mainland: mustPrefixes(t, "10.1.2.0/24")},
	})
	owner, prefix, mainland, ok := s.Owner(mustAddr(t, "10.1.2.3"))
	if !ok || owner.ID != "narrow" {
		t.Fatalf("应命中更具体的 narrow，得到 %q/%v", owner.ID, ok)
	}
	if prefix.String() != "10.1.2.0/24" || !mainland {
		t.Fatalf("命中前缀 %s mainland=%v，期望 10.1.2.0/24 true", prefix, mainland)
	}
	if owner, _, _, ok := s.Owner(mustAddr(t, "10.9.9.9")); !ok || owner.ID != "wide" {
		t.Fatalf("落在宽段里应命中 wide，得到 %q/%v", owner.ID, ok)
	}
	if _, _, _, ok := s.Owner(mustAddr(t, "11.0.0.1")); ok {
		t.Error("段外地址不该命中任何 provider")
	}
}

func TestSuffixMatchRespectsLabelBoundaries(t *testing.T) {
	s := sampleSet(t)
	if _, ok := s.ProviderFor("notakamaiedge.net"); ok {
		t.Error("notakamaiedge.net 不该命中 akamaiedge.net")
	}
	if _, ok := s.ProviderFor("akamaiedge.net.evil.com"); ok {
		t.Error("后缀出现在中间不该命中")
	}
	if p, ok := s.ProviderFor("A28-192.AkamaiEdge.Net."); !ok || p.ID != "akamai" {
		t.Errorf("大小写与尾点应被规范化，得到 %q/%v", p.ID, ok)
	}
}

func TestRenderParseRoundTrip(t *testing.T) {
	s := sampleSet(t)
	var buf bytes.Buffer
	if err := Render(&buf, s.GeneratedAt(), s.Providers()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	back, err := Parse(&buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !back.GeneratedAt().Equal(s.GeneratedAt()) {
		t.Errorf("generated-at 往返后变成 %v", back.GeneratedAt())
	}
	if back.PrefixCount() != s.PrefixCount() || back.DomainCount() != s.DomainCount() {
		t.Errorf("往返后前缀 %d/%d 域名 %d/%d", back.PrefixCount(), s.PrefixCount(), back.DomainCount(), s.DomainCount())
	}
	for _, c := range []struct {
		name, addr string
	}{
		{"e1.akamaiedge.net", "23.56.1.1"},
		{"e1.akamaiedge.net", "23.33.0.1"},
		{"e1.akamaiedge.net", "8.8.8.8"},
	} {
		if a, b := s.Classify(c.name, mustAddr(t, c.addr)), back.Classify(c.name, mustAddr(t, c.addr)); a.Verdict != b.Verdict {
			t.Errorf("%s/%s 往返后判据从 %s 变成 %s", c.name, c.addr, a.Verdict, b.Verdict)
		}
	}
}

func TestParseRejectsCorruptInput(t *testing.T) {
	cases := map[string]string{
		"schema 不符":      "# schema: cdn-direct/9\n# generated-at: 1\n",
		"缺 schema":       "# generated-at: 1757000000\nP\ta\tA\n",
		"缺 generated-at": "# schema: " + Schema + "\nP\ta\tA\n",
		"未知标记":           "# schema: " + Schema + "\n# generated-at: 1757000000\nX\ta\tb\n",
		"引用未声明 provider": "# schema: " + Schema + "\n# generated-at: 1757000000\nD\tghost\tx.test\n",
		"归属标记非法":         "# schema: " + Schema + "\n# generated-at: 1757000000\nP\ta\tA\nN\ta\tmars\t1.0.0.0/8\n",
		"列数不对":           "# schema: " + Schema + "\n# generated-at: 1757000000\nP\ta\n",
	}
	for label, text := range cases {
		if _, err := Parse(strings.NewReader(text)); err == nil {
			t.Errorf("%s 应当被拒绝", label)
		}
	}
}

func TestBuildSplitsPrefixesAgainstMainlandBaseline(t *testing.T) {
	fetch := func(ctx context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "ips-v4"):
			return []byte("104.16.0.0/13\n1.2.0.0/16\n"), nil
		case strings.Contains(url, "ips-v6"):
			return []byte("2400:cb00::/32\n"), nil
		case strings.Contains(url, "public-ip-list"):
			return []byte(`{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e42::/32"]}`), nil
		case strings.Contains(url, "ip-ranges.amazonaws.com"):
			return []byte(`{"prefixes":[{"ip_prefix":"13.32.0.0/15","service":"CLOUDFRONT"},{"ip_prefix":"3.5.0.0/16","service":"S3"}],"ipv6_prefixes":[]}`), nil
		case strings.Contains(url, "AS20940"):
			return []byte(`{"status":"ok","data":{"prefixes":[{"prefix":"23.32.0.0/12"}]}}`), nil
		case strings.Contains(url, "stat.ripe.net"):
			return []byte(`{"status":"ok","data":{"prefixes":[]}}`), nil
		}
		return nil, context.Canceled
	}
	rep, err := Build(context.Background(), Options{
		Fetch:    fetch,
		Mainland: mustPrefixes(t, "1.2.0.0/16", "23.32.0.0/16"),
		Now:      time.Unix(1757000000, 0),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	byID := make(map[string]Provider)
	for _, p := range rep.Providers {
		byID[p.ID] = p
	}
	cf := byID["cloudflare"]
	if len(cf.Mainland) != 1 || cf.Mainland[0].String() != "1.2.0.0/16" {
		t.Errorf("Cloudflare 大陆段应为 1.2.0.0/16，得到 %v", cf.Mainland)
	}
	if !cf.HasMainland() {
		t.Error("Cloudflare 有大陆段却报告没有")
	}
	ak := byID["akamai"]
	if len(ak.Mainland) != 1 || ak.Mainland[0].String() != "23.32.0.0/16" {
		t.Errorf("AS 拉到的 /12 应被切出 /16 大陆部分，得到 %v", ak.Mainland)
	}
	if len(ak.Offshore) == 0 {
		t.Error("/12 减去 /16 之后应仍有境外部分")
	}
	aws := byID["amazon"]
	for _, p := range append(append([]netip.Prefix(nil), aws.Mainland...), aws.Offshore...) {
		if p.String() == "3.5.0.0/16" {
			t.Error("非 CLOUDFRONT 的 AWS 网段被混进了 CDN 规则集")
		}
	}
	if byID["apple"].PrefixCount() != 0 {
		t.Error("Apple 没有任何前缀来源，应保持为空而不是编造")
	}
}

func TestBuildRejectsOverWidePrefixFromAPoisonedSource(t *testing.T) {
	fetch := func(ctx context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "ips-v4") {
			return []byte("0.0.0.0/0\n"), nil
		}
		return nil, context.Canceled
	}
	rep, err := Build(context.Background(), Options{
		Fetch:    fetch,
		Mainland: mustPrefixes(t, "1.2.0.0/16"),
		Now:      time.Unix(1757000000, 0),
	})
	if err != nil {
		t.Fatalf("单个来源失败不该让整次构建报错: %v", err)
	}
	for _, p := range rep.Providers {
		if p.ID == "cloudflare" && p.PrefixCount() != 0 {
			t.Fatalf("0.0.0.0/0 应当让整条来源被拒绝，却收进了 %v", p)
		}
	}
	if len(rep.Warnings) == 0 {
		t.Error("拒绝一条来源必须留下告警，否则是静默失败")
	}
}

func TestBuildRefusesToPublishAVacuousRuleset(t *testing.T) {
	fetch := func(ctx context.Context, url string) ([]byte, error) { return nil, context.Canceled }
	_, err := Build(context.Background(), Options{
		Fetch:       fetch,
		Mainland:    mustPrefixes(t, "1.2.0.0/16"),
		MinPrefixes: 1,
	})
	if err == nil {
		t.Fatal("所有来源都失败时应当拒绝发布，否则会用空规则集覆盖掉好的")
	}
}

func TestBuildRequiresMainlandBaseline(t *testing.T) {
	if _, err := Build(context.Background(), Options{Fetch: func(context.Context, string) ([]byte, error) {
		return []byte("1.0.0.0/8\n"), nil
	}}); err == nil {
		t.Fatal("没有大陆网段基线时无法区分节点归属，必须拒绝构建")
	}
}
