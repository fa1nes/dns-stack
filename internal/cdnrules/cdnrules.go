package cdnrules

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictMainland
	VerdictOffshore
	VerdictMismatch
)

func (v Verdict) String() string {
	switch v {
	case VerdictMainland:
		return "mainland"
	case VerdictOffshore:
		return "offshore"
	case VerdictMismatch:
		return "mismatch"
	default:
		return "unknown"
	}
}

func (v Verdict) Label() string {
	switch v {
	case VerdictMainland:
		return "大陆节点"
	case VerdictOffshore:
		return "境外节点"
	case VerdictMismatch:
		return "地址不属于该 CDN"
	default:
		return "不在规则集内"
	}
}

type Provider struct {
	ID       string
	Name     string
	Domains  []string
	Mainland []netip.Prefix
	Offshore []netip.Prefix
}

func (p Provider) HasMainland() bool { return len(p.Mainland) > 0 }

func (p Provider) PrefixCount() int { return len(p.Mainland) + len(p.Offshore) }

type Decision struct {
	Verdict  Verdict
	Provider string
	Name     string
	Owner    string
	Prefix   netip.Prefix
}

type Set struct {
	generatedAt time.Time
	providers   []Provider
	suffix      map[string]int
	spans       []span
	maxHi       []netip.Addr
}

type span struct {
	lo, hi   netip.Addr
	prefix   netip.Prefix
	provider int
	mainland bool
}

func New(generatedAt time.Time, providers []Provider) *Set {
	s := &Set{
		generatedAt: generatedAt,
		providers:   append([]Provider(nil), providers...),
		suffix:      make(map[string]int),
	}
	sort.SliceStable(s.providers, func(i, j int) bool { return s.providers[i].ID < s.providers[j].ID })
	for i := range s.providers {
		for _, d := range s.providers[i].Domains {
			key := normalize(d)
			if key == "" {
				continue
			}
			if _, taken := s.suffix[key]; !taken {
				s.suffix[key] = i
			}
		}
		s.collect(i, s.providers[i].Mainland, true)
		s.collect(i, s.providers[i].Offshore, false)
	}
	sort.Slice(s.spans, func(i, j int) bool {
		if c := s.spans[i].lo.Compare(s.spans[j].lo); c != 0 {
			return c < 0
		}
		return s.spans[i].hi.Compare(s.spans[j].hi) < 0
	})
	s.maxHi = make([]netip.Addr, len(s.spans))
	for i, sp := range s.spans {
		if i == 0 || sp.hi.Compare(s.maxHi[i-1]) > 0 {
			s.maxHi[i] = sp.hi
		} else {
			s.maxHi[i] = s.maxHi[i-1]
		}
	}
	return s
}

func (s *Set) collect(idx int, prefixes []netip.Prefix, mainland bool) {
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		lo, hi, ok := bounds(p)
		if !ok {
			continue
		}
		s.spans = append(s.spans, span{lo: lo, hi: hi, prefix: p, provider: idx, mainland: mainland})
	}
}

func (s *Set) GeneratedAt() time.Time { return s.generatedAt }

func (s *Set) Providers() []Provider { return s.providers }

func (s *Set) PrefixCount() int { return len(s.spans) }

func (s *Set) DomainCount() int { return len(s.suffix) }

func (s *Set) Empty() bool { return s == nil || len(s.providers) == 0 }

func (s *Set) ProviderFor(name string) (Provider, bool) {
	if s == nil {
		return Provider{}, false
	}
	for rest := normalize(name); rest != ""; {
		if idx, ok := s.suffix[rest]; ok {
			return s.providers[idx], true
		}
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	return Provider{}, false
}

func (s *Set) Owner(addr netip.Addr) (Provider, netip.Prefix, bool, bool) {
	if s == nil || !addr.IsValid() {
		return Provider{}, netip.Prefix{}, false, false
	}
	addr = addr.Unmap()
	idx := sort.Search(len(s.spans), func(i int) bool { return s.spans[i].lo.Compare(addr) > 0 })
	best := -1
	for i := idx - 1; i >= 0; i-- {
		if s.maxHi[i].Compare(addr) < 0 {
			break
		}
		sp := s.spans[i]
		if sp.lo.Compare(addr) <= 0 && sp.hi.Compare(addr) >= 0 {
			if best < 0 || sp.prefix.Bits() > s.spans[best].prefix.Bits() {
				best = i
			}
		}
	}
	if best < 0 {
		return Provider{}, netip.Prefix{}, false, false
	}
	sp := s.spans[best]
	return s.providers[sp.provider], sp.prefix, sp.mainland, true
}

func (s *Set) Classify(name string, addr netip.Addr) Decision {
	provider, known := s.ProviderFor(name)
	owner, prefix, mainland, found := s.Owner(addr)
	d := Decision{Name: name}
	if known {
		d.Provider = provider.ID
	}
	if found {
		d.Owner = owner.ID
		d.Prefix = prefix
	}
	switch {
	case !known:
		d.Verdict = VerdictUnknown
	case found && owner.ID == provider.ID && mainland:
		d.Verdict = VerdictMainland
	case found && owner.ID == provider.ID:
		d.Verdict = VerdictOffshore
	case provider.PrefixCount() == 0:
		d.Verdict = VerdictUnknown
	default:
		d.Verdict = VerdictMismatch
	}
	return d
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

func bounds(p netip.Prefix) (netip.Addr, netip.Addr, bool) {
	if !p.IsValid() {
		return netip.Addr{}, netip.Addr{}, false
	}
	lo := p.Masked().Addr()
	raw := lo.AsSlice()
	bits := p.Bits()
	for i := bits; i < len(raw)*8; i++ {
		raw[i/8] |= 1 << (7 - uint(i)%8)
	}
	hi, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	return lo, hi, true
}
