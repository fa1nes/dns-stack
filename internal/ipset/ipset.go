package ipset

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type Range struct {
	Lo uint32
	Hi uint32
}

type Set struct {
	ranges []Range
	starts []uint32
}

func New(ranges []Range) *Set {
	c := Collapse(ranges)
	s := &Set{ranges: c, starts: make([]uint32, len(c))}
	for i, r := range c {
		s.starts[i] = r.Lo
	}
	return s
}

func Collapse(in []Range) []Range {
	if len(in) == 0 {
		return nil
	}
	cp := make([]Range, len(in))
	copy(cp, in)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Lo != cp[j].Lo {
			return cp[i].Lo < cp[j].Lo
		}
		return cp[i].Hi < cp[j].Hi
	})
	out := []Range{cp[0]}
	for _, r := range cp[1:] {
		last := &out[len(out)-1]
		if r.Lo <= last.Hi || (last.Hi != ^uint32(0) && r.Lo == last.Hi+1) {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ranges)
}

func (s *Set) AddressCount() uint64 {
	if s == nil {
		return 0
	}
	var n uint64
	for _, r := range s.ranges {
		n += uint64(r.Hi-r.Lo) + 1
	}
	return n
}

func (s *Set) Ranges() []Range {
	if s == nil {
		return nil
	}
	out := make([]Range, len(s.ranges))
	copy(out, s.ranges)
	return out
}

func (s *Set) Overlaps(lo, hi uint32) bool {
	if s == nil || lo > hi {
		return false
	}
	i := sort.Search(len(s.ranges), func(k int) bool { return s.ranges[k].Hi >= lo })
	return i < len(s.ranges) && s.ranges[i].Lo <= hi
}

func (s *Set) locate(v uint32) int {
	i := sort.Search(len(s.starts), func(k int) bool { return s.starts[k] > v }) - 1
	return i
}

func (s *Set) Contains(addr netip.Addr) bool {
	if s == nil || !addr.Is4() {
		return false
	}
	return s.ContainsUint(toUint32(addr))
}

func (s *Set) ContainsUint(v uint32) bool {
	if s == nil || len(s.ranges) == 0 {
		return false
	}
	i := s.locate(v)
	return i >= 0 && s.ranges[i].Hi >= v
}

func (s *Set) CoversRange(lo, hi uint32) bool {
	if s == nil || len(s.ranges) == 0 || lo > hi {
		return false
	}
	i := s.locate(lo)
	return i >= 0 && s.ranges[i].Hi >= hi
}

func (s *Set) CoversPrefix(p netip.Prefix) bool {
	if s == nil || !p.Addr().Is4() {
		return false
	}
	lo, hi, ok := prefixBounds(p)
	if !ok {
		return false
	}
	return s.CoversRange(lo, hi)
}

func toUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromUint32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func prefixBounds(p netip.Prefix) (uint32, uint32, bool) {
	if !p.Addr().Is4() {
		return 0, 0, false
	}
	m := p.Masked()
	lo := toUint32(m.Addr())
	bits := m.Bits()
	if bits < 0 || bits > 32 {
		return 0, 0, false
	}
	size := uint32(1)<<(32-uint(bits)) - 1
	return lo, lo + size, true
}

func PrefixRange(p netip.Prefix) (Range, bool) {
	lo, hi, ok := prefixBounds(p)
	return Range{Lo: lo, Hi: hi}, ok
}

func IsGlobalPrefix(p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	m := p.Masked()
	lo, hi, ok := prefixBounds(m)
	if !ok {
		return false
	}
	parts := globalRangeParts(Range{Lo: lo, Hi: hi})
	return len(parts) == 1 && parts[0].Lo == lo && parts[0].Hi == hi
}

var nonGlobalPrefixes6 = []netip.Prefix{
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("3fff::/20"),
}

func IsGlobalAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return IsGlobalPrefix(netip.PrefixFrom(addr, 32))
	}
	if !addr.Is6() {
		return false
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsPrivate() {
		return false
	}
	if addr.As16()[0]&0xe0 != 0x20 {
		return false
	}
	for _, p := range nonGlobalPrefixes6 {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var nonGlobalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func GlobalParts(input Range) []Range {
	return globalRangeParts(input)
}

func isNormalized(values []Range) bool {
	for i := range values {
		if values[i].Lo > values[i].Hi {
			return false
		}
		if i > 0 && values[i].Lo <= values[i-1].Hi+1 {
			return false
		}
	}
	return true
}

func Subtract(base, remove []Range) []Range {
	if len(base) == 0 {
		return nil
	}
	if len(remove) == 0 {
		return Collapse(base)
	}
	cuts := remove
	if !isNormalized(cuts) {
		cuts = Collapse(remove)
	}
	spans := base
	if !isNormalized(spans) {
		spans = Collapse(base)
	}
	var out []Range
	j := 0
	for _, span := range spans {
		cur := span.Lo
		for {
			for j < len(cuts) && cuts[j].Hi < cur {
				j++
			}
			if j >= len(cuts) || cuts[j].Lo > span.Hi {
				out = append(out, Range{Lo: cur, Hi: span.Hi})
				break
			}
			if cuts[j].Lo > cur {
				out = append(out, Range{Lo: cur, Hi: cuts[j].Lo - 1})
			}
			if cuts[j].Hi >= span.Hi {
				break
			}
			cur = cuts[j].Hi + 1
			if cur > span.Hi {
				break
			}
		}
	}
	return out
}

func globalRangeParts(input Range) []Range {
	if input.Lo > input.Hi {
		return nil
	}
	parts := []Range{input}
	for _, excludedPrefix := range nonGlobalPrefixes {
		excluded, ok := PrefixRange(excludedPrefix)
		if !ok {
			continue
		}
		next := make([]Range, 0, len(parts)+1)
		for _, part := range parts {
			if excluded.Hi < part.Lo || excluded.Lo > part.Hi {
				next = append(next, part)
				continue
			}
			if excluded.Lo > part.Lo {
				next = append(next, Range{Lo: part.Lo, Hi: excluded.Lo - 1})
			}
			if excluded.Hi < part.Hi {
				next = append(next, Range{Lo: excluded.Hi + 1, Hi: part.Hi})
			}
		}
		parts = next
		if len(parts) == 0 {
			break
		}
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].Lo != parts[j].Lo {
			return parts[i].Lo < parts[j].Lo
		}
		return parts[i].Hi < parts[j].Hi
	})
	filtered := parts[:0]
	for _, part := range parts {
		if isGlobalAddr(fromUint32(part.Lo)) && isGlobalAddr(fromUint32(part.Hi)) {
			filtered = append(filtered, part)
		}
	}
	return filtered
}

func isGlobalAddr(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() ||
		a.IsInterfaceLocalMulticast() {
		return false
	}
	b := a.As4()
	switch {
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
		return false
	case b[0] == 192 && b[1] == 0 && b[2] == 0:
		return false
	case b[0] == 192 && b[1] == 0 && b[2] == 2:
		return false
	case b[0] == 192 && b[1] == 88 && b[2] == 99:
		return false
	case b[0] == 198 && (b[1] == 18 || b[1] == 19):
		return false
	case b[0] == 198 && b[1] == 51 && b[2] == 100:
		return false
	case b[0] == 203 && b[1] == 0 && b[2] == 113:
		return false
	case b[0] >= 240:
		return false
	}
	return true
}

type LoadOptions struct {
	GlobalOnly bool
}

type LoadResult struct {
	Set     *Set
	Total   int
	Skipped int
}

func LoadReader(r io.Reader, opt LoadOptions) (*LoadResult, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var ranges []Range
	res := &LoadResult{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Fields(line)[0]
		p, err := parsePrefix(line)
		if err != nil {
			res.Skipped++
			continue
		}
		if !p.Addr().Is4() {
			res.Skipped++
			continue
		}
		rg, ok := PrefixRange(p)
		if !ok {
			res.Skipped++
			continue
		}
		if opt.GlobalOnly {
			parts := globalRangeParts(rg)
			if len(parts) == 0 {
				res.Skipped++
				continue
			}
			ranges = append(ranges, parts...)
		} else {
			ranges = append(ranges, rg)
		}
		res.Total++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	res.Set = New(ranges)
	return res, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("not ipv4: %s", s)
	}
	return netip.PrefixFrom(a, 32), nil
}

func (s *Set) Prefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	var out []netip.Prefix
	for _, r := range s.ranges {
		out = append(out, rangeToPrefixes(r)...)
	}
	return out
}

func RangePrefixes(r Range) []netip.Prefix {
	return rangeToPrefixes(r)
}

func rangeToPrefixes(r Range) []netip.Prefix {
	var out []netip.Prefix
	lo, hi := r.Lo, r.Hi
	for {
		maxSize := uint(32)
		for maxSize > 0 {
			mask := uint32(1)<<(32-(maxSize-1)) - 1
			if lo&^mask != lo {
				break
			}
			if lo+mask > hi {
				break
			}
			maxSize--
		}
		out = append(out, netip.PrefixFrom(fromUint32(lo), int(maxSize)))
		size := uint32(1)<<(32-maxSize) - 1
		if lo+size >= hi || lo+size < lo {
			break
		}
		lo += size + 1
	}
	return out
}
