package cidrutil

import (
	"math/big"
	"net/netip"
	"sort"
)

type Set struct {
	v4 []span
	v6 []span
}

func NewSet(prefixes []netip.Prefix) *Set {
	var v4, v6 []span
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		s := spansOfPrefix(p)
		if p.Addr().Is6() {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	return &Set{v4: mergeSpans(v4), v6: mergeSpans(v6)}
}

func ParseSet(values []string) (*Set, []string) {
	var prefixes []netip.Prefix
	var rejected []string
	for _, raw := range values {
		p, err := ParsePrefix(raw)
		if err != nil {
			rejected = append(rejected, raw)
			continue
		}
		prefixes = append(prefixes, p)
	}
	return NewSet(prefixes), rejected
}

func (s *Set) Contains(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	spans := s.v4
	if addr.Is6() {
		spans = s.v6
	}
	if len(spans) == 0 {
		return false
	}
	value := ToBig(addr)
	i := sort.Search(len(spans), func(i int) bool { return spans[i].hi.Cmp(value) >= 0 })
	return i < len(spans) && spans[i].lo.Cmp(value) <= 0
}

func (s *Set) Empty() bool {
	return s == nil || (len(s.v4) == 0 && len(s.v6) == 0)
}

func (s *Set) AddressCount() *big.Int {
	total := new(big.Int)
	if s == nil {
		return total
	}
	one := big.NewInt(1)
	for _, group := range [][]span{s.v4, s.v6} {
		for _, sp := range group {
			total.Add(total, new(big.Int).Add(new(big.Int).Sub(sp.hi, sp.lo), one))
		}
	}
	return total
}

func (s *Set) Prefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	var out []netip.Prefix
	for _, sp := range s.v4 {
		out = append(out, rangePrefixes(sp.lo, sp.hi, false)...)
	}
	for _, sp := range s.v6 {
		out = append(out, rangePrefixes(sp.lo, sp.hi, true)...)
	}
	return out
}

func FirstOverlap(left, right []netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for _, is6 := range []bool{false, true} {
		a := sortedSpansWithSource(left, is6)
		b := sortedSpansWithSource(right, is6)
		i, j := 0, 0
		for i < len(a) && j < len(b) {
			if a[i].lo.Cmp(b[j].hi) <= 0 && b[j].lo.Cmp(a[i].hi) <= 0 {
				return a[i].source, b[j].source, true
			}
			if a[i].hi.Cmp(b[j].lo) < 0 {
				i++
			} else {
				j++
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}

type sourcedSpan struct {
	lo, hi *big.Int
	source netip.Prefix
}

func sortedSpansWithSource(prefixes []netip.Prefix, is6 bool) []sourcedSpan {
	out := make([]sourcedSpan, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() || p.Addr().Is6() != is6 {
			continue
		}
		s := spansOfPrefix(p)
		out = append(out, sourcedSpan{lo: s.lo, hi: s.hi, source: p.Masked()})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].lo.Cmp(out[j].lo); c != 0 {
			return c < 0
		}
		return out[i].hi.Cmp(out[j].hi) < 0
	})
	return out
}
