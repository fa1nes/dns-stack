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

func TestCollapsePrefixesMergesSiblingsAndAbsorbsContained(t *testing.T) {
	var input []netip.Prefix
	for _, value := range []string{
		"10.0.0.0/25", "10.0.0.128/25",
		"10.0.0.0/24",
		"10.0.1.0/24", "10.0.0.0/23",
		"192.168.1.0/24",
		"2001:db8::/33", "2001:db8:8000::/33",
		"2001:db8:1::/48",
	} {
		input = append(input, netip.MustParsePrefix(value))
	}
	input = append(input, netip.Prefix{})
	var got []string
	for _, prefix := range CollapsePrefixes(input) {
		got = append(got, prefix.String())
	}
	want := []string{"10.0.0.0/23", "192.168.1.0/24", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("CollapsePrefixes = %v, 期望 %v——ACL 锁门自检与 CDN 直连规则集都靠它算最终网段", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CollapsePrefixes = %v, 期望 %v——ACL 锁门自检与 CDN 直连规则集都靠它算最终网段", got, want)
		}
	}
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
	if (*Set)(nil).Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Error("nil 集合查询必须安全返回 false")
	}
}

func TestSetMergesAdjacentRanges(t *testing.T) {
	set := mustSet(t, "10.0.0.0/25", "10.0.0.128/25")
	if got := addressCount(set).Int64(); got != 256 {
		t.Errorf("相邻网段应当合并成 256 个地址，得到 %d", got)
	}
	prefixes := set.Prefixes()
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/24" {
		t.Errorf("合并后应当输出单条 /24，得到 %v", prefixes)
	}
}
