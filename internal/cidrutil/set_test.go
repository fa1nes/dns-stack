package cidrutil

import (
	"net/netip"
	"testing"
)

func mustSet(t *testing.T, values ...string) *Set {
	t.Helper()
	set, rejected := ParseSet(values)
	if len(rejected) > 0 {
		t.Fatalf("非法条目: %v", rejected)
	}
	return set
}

func TestSetContainsAcrossFamilies(t *testing.T) {
	set := mustSet(t, "157.240.7.0/24", "1.1.1.1", "2001:db8::/32")
	hits := []string{"157.240.7.0", "157.240.7.255", "1.1.1.1", "2001:db8::1"}
	for _, value := range hits {
		if !set.Contains(netip.MustParseAddr(value)) {
			t.Errorf("%s 应当命中", value)
		}
	}
	misses := []string{"157.240.6.255", "157.240.8.0", "1.1.1.2", "2001:db9::1", "::1"}
	for _, value := range misses {
		if set.Contains(netip.MustParseAddr(value)) {
			t.Errorf("%s 不该命中", value)
		}
	}
	if !mustSet(t).Empty() {
		t.Error("空集合应当报告为空")
	}
	if (*Set)(nil).Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Error("nil 集合查询必须安全返回 false")
	}
}

func TestSetMergesAdjacentRanges(t *testing.T) {
	set := mustSet(t, "10.0.0.0/25", "10.0.0.128/25")
	if got := set.AddressCount().Int64(); got != 256 {
		t.Errorf("相邻网段应当合并成 256 个地址，得到 %d", got)
	}
	prefixes := set.Prefixes()
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/24" {
		t.Errorf("合并后应当输出单条 /24，得到 %v", prefixes)
	}
}

func TestFirstOverlapUsesMergeScanAndRespectsFamilies(t *testing.T) {
	left := []netip.Prefix{
		netip.MustParsePrefix("1.0.0.0/8"),
		netip.MustParsePrefix("223.0.0.0/8"),
	}
	if _, _, overlap := FirstOverlap(left, []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}); overlap {
		t.Error("不相交的集合不该报重叠")
	}
	a, b, overlap := FirstOverlap(left, []netip.Prefix{netip.MustParsePrefix("223.5.5.0/24")})
	if !overlap || a.String() != "223.0.0.0/8" || b.String() != "223.5.5.0/24" {
		t.Errorf("应当报出实际相交的那一对，得到 %s / %s (%v)", a, b, overlap)
	}
	if _, _, overlap := FirstOverlap(
		[]netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")},
		[]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}); overlap {
		t.Error("v4 与 v6 之间不存在重叠，整数区间恰好相同也不算")
	}
	if _, _, overlap := FirstOverlap(
		[]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		[]netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}); !overlap {
		t.Error("v6 包含关系必须判为重叠")
	}
}
