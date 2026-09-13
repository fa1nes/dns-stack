package cidrutil

import (
	"math/big"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		p, err := ParsePrefix(v)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", v, err)
		}
		out = append(out, p)
	}
	return out
}

func totalAddrs(list []netip.Prefix) *big.Int {
	return NewSet(list).AddressCount()
}

func TestIntersectKeepsOnlyTheOverlap(t *testing.T) {
	got := Intersect(
		prefixes(t, "23.32.0.0/12"),
		prefixes(t, "23.36.0.0/14", "1.0.0.0/8"),
	)
	if want := totalAddrs(prefixes(t, "23.36.0.0/14")); totalAddrs(got).Cmp(want) != 0 {
		t.Fatalf("交集地址数 %s，期望 %s（得到 %v）", totalAddrs(got), want, got)
	}
}

func TestIntersectAndSubtractPartitionTheBase(t *testing.T) {
	base := prefixes(t, "23.32.0.0/12", "2.16.0.0/13", "2400:cb00::/32")
	mask := prefixes(t, "23.36.0.0/14", "2.20.0.0/16", "9.9.9.9/32", "2400:cb00:1::/48")
	inside := Intersect(base, mask)
	outside := Subtract(base, mask)
	sum := new(big.Int).Add(totalAddrs(inside), totalAddrs(outside))
	if sum.Cmp(totalAddrs(base)) != 0 {
		t.Fatalf("交集 %s + 差集 %s = %s，不等于原集合 %s——切分丢了地址",
			totalAddrs(inside), totalAddrs(outside), sum, totalAddrs(base))
	}
	if overlap := Intersect(inside, outside); len(overlap) != 0 {
		t.Fatalf("交集与差集重叠了 %v，同一个地址会被同时判成大陆和境外", overlap)
	}
}

func TestSubtractCarvesHolesAndCrossesFamilies(t *testing.T) {
	got := Subtract(prefixes(t, "10.0.0.0/24"), prefixes(t, "10.0.0.128/25"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/25" {
		t.Fatalf("挖掉后半段应剩 10.0.0.0/25，得到 %v", got)
	}
	kept := Subtract(prefixes(t, "10.0.0.0/24"), prefixes(t, "2001:db8::/32"))
	if len(kept) != 1 || kept[0].String() != "10.0.0.0/24" {
		t.Fatalf("v6 掩码不该动 v4 网段，得到 %v", kept)
	}
}

func TestSubtractWholeBaseYieldsNothing(t *testing.T) {
	if got := Subtract(prefixes(t, "192.0.2.0/24"), prefixes(t, "192.0.0.0/16")); len(got) != 0 {
		t.Fatalf("被完全覆盖时应为空，得到 %v", got)
	}
	if got := Intersect(prefixes(t, "192.0.2.0/24"), nil); len(got) != 0 {
		t.Fatalf("与空集求交应为空，得到 %v", got)
	}
	if got := Subtract(prefixes(t, "192.0.2.0/24"), nil); len(got) != 1 {
		t.Fatalf("减空集应原样返回，得到 %v", got)
	}
}

func TestSubtractHandlesManyRemovalsInOneBase(t *testing.T) {
	base := prefixes(t, "10.0.0.0/16")
	var mask []netip.Prefix
	for i := 0; i < 64; i++ {
		mask = append(mask, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i * 2), 0}), 24))
	}
	out := Subtract(base, mask)
	sum := new(big.Int).Add(totalAddrs(out), totalAddrs(mask))
	if sum.Cmp(totalAddrs(base)) != 0 {
		t.Fatalf("多段挖洞后地址总数 %s，期望 %s", sum, totalAddrs(base))
	}
}
