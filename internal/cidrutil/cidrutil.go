package cidrutil

import (
	"bufio"
	"io"
	"math/big"
	"net/netip"
	"os"
	"sort"
	"strings"
)

func ToBig(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func FromBig(v *big.Int, is6 bool) netip.Addr {
	size := 4
	if is6 {
		size = 16
	}
	raw := v.Bytes()
	buf := make([]byte, size)
	if len(raw) <= size {
		copy(buf[size-len(raw):], raw)
	} else {
		copy(buf, raw[len(raw)-size:])
	}
	addr, _ := netip.AddrFromSlice(buf)
	return addr
}

type span struct {
	lo, hi *big.Int
}

func rangePrefixes(lo, hi *big.Int, is6 bool) []netip.Prefix {
	bits := 32
	if is6 {
		bits = 128
	}
	one := big.NewInt(1)
	var out []netip.Prefix
	cur := new(big.Int).Set(lo)
	for cur.Cmp(hi) <= 0 {
		size := bits
		for size > 0 {
			mask := new(big.Int).Sub(new(big.Int).Lsh(one, uint(bits-size+1)), one)
			if new(big.Int).And(cur, mask).Sign() != 0 {
				break
			}
			if new(big.Int).Add(cur, mask).Cmp(hi) > 0 {
				break
			}
			size--
		}
		out = append(out, netip.PrefixFrom(FromBig(cur, is6), size))
		cur = new(big.Int).Add(cur, new(big.Int).Lsh(one, uint(bits-size)))
		if cur.BitLen() > bits {
			break
		}
	}
	return out
}

func mergeSpans(spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if c := spans[i].lo.Cmp(spans[j].lo); c != 0 {
			return c < 0
		}
		return spans[i].hi.Cmp(spans[j].hi) < 0
	})
	one := big.NewInt(1)
	out := []span{{lo: new(big.Int).Set(spans[0].lo), hi: new(big.Int).Set(spans[0].hi)}}
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s.lo.Cmp(new(big.Int).Add(last.hi, one)) <= 0 {
			if s.hi.Cmp(last.hi) > 0 {
				last.hi.Set(s.hi)
			}
			continue
		}
		out = append(out, span{lo: new(big.Int).Set(s.lo), hi: new(big.Int).Set(s.hi)})
	}
	return out
}

func collapseFamily(spans []span, is6 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range mergeSpans(spans) {
		out = append(out, rangePrefixes(s.lo, s.hi, is6)...)
	}
	return out
}

func spansOfPrefix(p netip.Prefix) span {
	p = p.Masked()
	lo := ToBig(p.Addr())
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
	hi := new(big.Int).Sub(new(big.Int).Add(lo, size), big.NewInt(1))
	return span{lo: lo, hi: hi}
}

func CollapseAddrs(addrs []netip.Addr) []netip.Prefix {
	var v4, v6 []span
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() {
			continue
		}
		value := ToBig(a)
		s := span{lo: value, hi: new(big.Int).Set(value)}
		if a.Is6() {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	return append(collapseFamily(v4, false), collapseFamily(v6, true)...)
}

func CollapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
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
	return append(collapseFamily(v4, false), collapseFamily(v6, true)...)
}

func Overlaps(a, b netip.Prefix) bool {
	if a.Addr().Is6() != b.Addr().Is6() {
		return false
	}
	sa, sb := spansOfPrefix(a), spansOfPrefix(b)
	return sa.lo.Cmp(sb.hi) <= 0 && sb.lo.Cmp(sa.hi) <= 0
}

func ReadPrefixes(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := ParsePrefix(line)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

func ReadPrefixFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadPrefixes(f)
}

func ParsePrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func Render(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return ""
	}
	var b strings.Builder
	for i, p := range prefixes {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(p.String())
	}
	b.WriteString("\n")
	return b.String()
}

func SortAddrs(addrs []netip.Addr) {
	sort.Slice(addrs, func(i, j int) bool {
		a, b := addrs[i], addrs[j]
		if a.Is6() != b.Is6() {
			return !a.Is6()
		}
		return ToBig(a).Cmp(ToBig(b)) < 0
	})
}
