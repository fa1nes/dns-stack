package ipset

import (
	"net/netip"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %s: %v", s, err)
	}
	return p.Masked()
}

func rangeOf(t *testing.T, s string) Range {
	t.Helper()
	r, ok := PrefixRange(mustPrefix(t, s))
	if !ok {
		t.Fatalf("PrefixRange failed: %s", s)
	}
	return r
}

func TestCollapseMergesAdjacent(t *testing.T) {
	s := New([]Range{rangeOf(t, "192.168.2.0/24"), rangeOf(t, "192.168.3.0/24")})
	if s.Len() != 1 {
		t.Fatalf("相邻 /24 应合并成 1 条，实际 %d 条", s.Len())
	}
	if got := s.AddressCount(); got != 512 {
		t.Errorf("覆盖地址总数应为 512，实际 %d", got)
	}
}

func TestCountShrinksButAddressesDoNot(t *testing.T) {
	in := []Range{
		rangeOf(t, "10.0.0.0/24"), rangeOf(t, "10.0.1.0/24"),
		rangeOf(t, "10.0.2.0/24"), rangeOf(t, "10.0.3.0/24"),
	}
	s := New(in)
	if s.Len() >= len(in) {
		t.Fatalf("测试前提失效：合并后条数应减少，%d -> %d", len(in), s.Len())
	}
	if got := s.AddressCount(); got != 1024 {
		t.Errorf("条数会因合并而减少，但地址总数不变：应 1024，实际 %d", got)
	}
}

func TestCoversRangeIsIntervalNotEquality(t *testing.T) {
	s := New([]Range{rangeOf(t, "192.168.2.0/24"), rangeOf(t, "192.168.3.0/24")})
	merged := mustPrefix(t, "192.168.2.0/23")
	if !s.CoversPrefix(merged) {
		t.Error("合并后的 /23 应被识别为已覆盖；用集合相等判据会把它当成假孤儿")
	}
	if s.CoversPrefix(mustPrefix(t, "192.168.2.0/22")) {
		t.Error("/22 超出覆盖范围，不应判为已覆盖")
	}
	if !s.CoversPrefix(mustPrefix(t, "192.168.2.128/25")) {
		t.Error("子网段应被覆盖")
	}
	if s.CoversPrefix(mustPrefix(t, "203.0.113.7/32")) {
		t.Error("不相关网段不应被覆盖")
	}
}

func TestContainsBoundaries(t *testing.T) {
	s := New([]Range{rangeOf(t, "1.2.3.0/24")})
	cases := map[string]bool{
		"1.2.2.255": false,
		"1.2.3.0":   true,
		"1.2.3.255": true,
		"1.2.4.0":   false,
	}
	for ip, want := range cases {
		a := netip.MustParseAddr(ip)
		if got := s.Contains(a); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestEmptySetNeverMatches(t *testing.T) {
	var s *Set
	if s.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Error("nil 集合不应匹配任何地址")
	}
	if s.CoversRange(0, 0) {
		t.Error("nil 集合不应覆盖任何区间")
	}
	empty := New(nil)
	if empty.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Error("空集合不应匹配")
	}
	if empty.AddressCount() != 0 {
		t.Error("空集合地址数应为 0")
	}
}

func TestGlobalOnlyFiltersRoutingSafeguards(t *testing.T) {
	input := `1.2.3.0/24
10.0.0.0/8
192.168.0.0/16
127.0.0.0/8
100.64.0.0/10
0.0.0.0/8
224.0.0.0/4
240.0.0.0/4
169.254.0.0/16
8.8.8.0/24
`
	res, err := LoadReader(strings.NewReader(input), LoadOptions{GlobalOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Errorf("只有 1.2.3.0/24 与 8.8.8.0/24 是全局地址，实际收下 %d 条", res.Total)
	}
	if res.Set.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("私有段绝不能当作大陆地理证据——direct4 里它们是路由护栏")
	}
	if !res.Set.Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Error("全局地址应保留")
	}
}

func TestGlobalOnlySplitsWideRangeAroundSpecialUse(t *testing.T) {
	res, err := LoadReader(strings.NewReader("100.0.0.0/8\n"), LoadOptions{GlobalOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Set.Prefixes()
	want := []netip.Prefix{
		netip.MustParsePrefix("100.0.0.0/10"),
		netip.MustParsePrefix("100.128.0.0/9"),
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("wide range was not split safely: got %v want %v", got, want)
	}
	if res.Set.Contains(netip.MustParseAddr("100.64.0.1")) {
		t.Fatal("CGNAT address leaked through GlobalOnly")
	}
}

func TestLoadKeepsNonGlobalWhenNotFiltering(t *testing.T) {
	res, err := LoadReader(strings.NewReader("10.0.0.0/8\n1.2.3.0/24\n"), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Errorf("不过滤时应收下 2 条，实际 %d", res.Total)
	}
}

func TestBareAddressTreatedAsHost(t *testing.T) {
	res, err := LoadReader(strings.NewReader("203.0.113.7\n"), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 {
		t.Fatalf("裸地址应按 /32 收下，实际 %d", res.Total)
	}
	if res.Set.AddressCount() != 1 {
		t.Errorf("裸地址应只覆盖 1 个地址，实际 %d", res.Set.AddressCount())
	}
}

func TestMalformedLinesSkipped(t *testing.T) {
	res, err := LoadReader(strings.NewReader("# comment\n\nnot-an-ip\n1.2.3.0/24\n2001:db8::/32\n"), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 {
		t.Errorf("只有 1 条合法 v4，实际 %d", res.Total)
	}
	if res.Skipped != 2 {
		t.Errorf("应跳过 2 条(非法 + v6)，实际 %d", res.Skipped)
	}
}

func TestPrefixesRoundTrip(t *testing.T) {
	s := New([]Range{rangeOf(t, "192.168.2.0/24"), rangeOf(t, "192.168.3.0/24")})
	ps := s.Prefixes()
	if len(ps) != 1 || ps[0].String() != "192.168.2.0/23" {
		t.Errorf("合并后应还原为单条 /23，实际 %v", ps)
	}
	total := uint64(0)
	for _, p := range ps {
		r, _ := PrefixRange(p)
		total += uint64(r.Hi-r.Lo) + 1
	}
	if total != s.AddressCount() {
		t.Errorf("还原出的前缀覆盖地址数应与集合一致：%d vs %d", total, s.AddressCount())
	}
}

func TestPrefixesCoverUnalignedRange(t *testing.T) {
	s := New([]Range{{Lo: 0x01020304, Hi: 0x0102030A}})
	ps := s.Prefixes()
	total := uint64(0)
	for _, p := range ps {
		r, ok := PrefixRange(p)
		if !ok {
			t.Fatalf("bad prefix %v", p)
		}
		total += uint64(r.Hi-r.Lo) + 1
	}
	if total != 7 {
		t.Errorf("非对齐区间 .4-.10 共 7 个地址，还原后覆盖 %d 个", total)
	}
}

func TestSubtractCarvesHoleInsideRange(t *testing.T) {
	base := []Range{rangeOf(t, "1.1.1.0/24")}
	remove := []Range{rangeOf(t, "1.1.1.128/25")}
	out := New(Subtract(base, remove))
	if out.AddressCount() != 128 {
		t.Fatalf("剩余应为 128 个地址，实际 %d", out.AddressCount())
	}
	if out.Contains(netip.MustParseAddr("1.1.1.200")) {
		t.Fatal("被扣掉的地址仍然命中")
	}
	if !out.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("未被扣的地址不该消失")
	}
}

func TestSubtractSingleAddressSplitsRange(t *testing.T) {
	base := []Range{rangeOf(t, "1.1.1.0/24")}
	remove := []Range{{Lo: 0x01010180, Hi: 0x01010180}}
	out := New(Subtract(base, remove))
	if out.AddressCount() != 255 {
		t.Fatalf("扣掉一个 /32 后应剩 255 个，实际 %d", out.AddressCount())
	}
	if out.Contains(netip.MustParseAddr("1.1.1.128")) {
		t.Fatal("被扣的 /32 仍然命中：ECS 白名单会把它原样覆盖回来")
	}
	if !out.Contains(netip.MustParseAddr("1.1.1.127")) ||
		!out.Contains(netip.MustParseAddr("1.1.1.129")) {
		t.Fatal("相邻地址被误伤")
	}
}

func TestSubtractHandlesEmptyAndDisjointInputs(t *testing.T) {
	base := []Range{rangeOf(t, "1.1.1.0/24")}
	if got := New(Subtract(base, nil)).AddressCount(); got != 256 {
		t.Fatalf("没有要扣的东西时必须原样返回，实际 %d", got)
	}
	if got := New(Subtract(base, []Range{rangeOf(t, "8.8.8.0/24")})).AddressCount(); got != 256 {
		t.Fatalf("不相交时不得误删，实际 %d", got)
	}
	if got := len(Subtract(nil, []Range{rangeOf(t, "1.1.1.0/24")})); got != 0 {
		t.Fatalf("空 base 应返回空，实际 %d 段", got)
	}
	if got := len(Subtract(base, []Range{rangeOf(t, "1.1.0.0/16")})); got != 0 {
		t.Fatalf("被完全覆盖时应剩 0 段，实际 %d 段", got)
	}
}

func TestSubtractAcrossMultipleBaseRanges(t *testing.T) {
	base := []Range{rangeOf(t, "1.1.1.0/24"), rangeOf(t, "8.8.8.0/24"), rangeOf(t, "9.9.9.0/24")}
	remove := []Range{rangeOf(t, "1.1.1.0/25"), rangeOf(t, "9.9.9.0/24")}
	out := New(Subtract(base, remove))
	if out.AddressCount() != 128+256 {
		t.Fatalf("应剩 384 个地址，实际 %d", out.AddressCount())
	}
	if out.Contains(netip.MustParseAddr("9.9.9.9")) {
		t.Fatal("整段被扣的范围仍然命中")
	}
	if !out.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("未涉及的段被误删")
	}
}
