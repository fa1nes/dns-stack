package cidrutil

import (
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
