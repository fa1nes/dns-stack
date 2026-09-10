package classify

import (
	"database/sql"
	"fmt"
	"net/netip"
	"sort"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

func parsePrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		if p, err := cidrutil.ParsePrefix(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Addr().Is6() != b.Addr().Is6() {
			return !a.Addr().Is6()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

func normalizePrefixStrings(values []string) []string {
	prefixes := parsePrefixes(values)
	sortPrefixes(prefixes)
	out := make([]string, 0, len(prefixes))
	for i, p := range prefixes {
		if i > 0 && p == prefixes[i-1] {
			continue
		}
		out = append(out, p.String())
	}
	return out
}

func collapsePrefixStrings(values []string) ([]string, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		p, err := cidrutil.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR: %s", raw)
		}
		prefixes = append(prefixes, p)
	}
	collapsed := cidrutil.CollapsePrefixes(prefixes)
	out := make([]string, len(collapsed))
	for i, p := range collapsed {
		out[i] = p.String()
	}
	return out, nil
}

func partitionPollutedCIDRs(values []string) (publishable, auditOnly []string) {
	for _, raw := range values {
		p, err := cidrutil.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if prefixHasGlobalEdge(p) {
			auditOnly = append(auditOnly, raw)
			continue
		}
		publishable = append(publishable, raw)
	}
	return publishable, auditOnly
}

func prefixHasGlobalEdge(p netip.Prefix) bool {
	p = p.Masked()
	if ipset.IsGlobalAddr(p.Addr()) {
		return true
	}
	return ipset.IsGlobalAddr(lastAddr(p))
}

func lastAddr(p netip.Prefix) netip.Addr {
	bits := p.Addr().BitLen()
	if p.Bits() == bits {
		return p.Addr()
	}
	if p.Addr().Is4() {
		raw := p.Addr().As4()
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		value |= ^uint32(0) >> uint(p.Bits())
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	raw := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		raw[i/8] |= 1 << uint(7-i%8)
	}
	return netip.AddrFrom16(raw)
}

func assertPollutedPublishable(values []string) error {
	for _, raw := range values {
		p, err := cidrutil.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("非法 CIDR: %s", raw)
		}
		if prefixHasGlobalEdge(p) {
			return fmt.Errorf("polluted-ip-cidr.txt 含全局可路由地址，拒绝发布: %s", p)
		}
	}
	return nil
}

func assertDisjoint(cnValues, pollutedValues []string) error {
	left, right, overlap := cidrutil.FirstOverlap(parsePrefixes(cnValues), parsePrefixes(pollutedValues))
	if overlap {
		return fmt.Errorf("CN CIDR 与污染 CIDR 存在重叠，禁止发布: %s <-> %s", left, right)
	}
	return nil
}

func assertCIDRClassesDisjoint(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT kind, cidr FROM ip_cidrs WHERE active=1 AND kind IN ('cn','polluted')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var cn, polluted []netip.Prefix
	for rows.Next() {
		var kind, cidr string
		if err := rows.Scan(&kind, &cidr); err != nil {
			return err
		}
		p, err := cidrutil.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if kind == "cn" {
			cn = append(cn, p)
		} else {
			polluted = append(polluted, p)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	left, right, overlap := cidrutil.FirstOverlap(cn, polluted)
	if overlap {
		return fmt.Errorf("CN CIDR 与污染 CIDR 存在重叠: %s <-> %s", left, right)
	}
	return nil
}
