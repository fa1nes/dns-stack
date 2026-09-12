package collect

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

const (
	minDirect4Entries = 3000
	minCNV6Entries    = 500
)

func LoadPollutedCIDRs(stateDir string) []string {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	seen := map[netip.Prefix]struct{}{}
	for _, name := range []string{"polluted-ip-cidr.txt", "polluted-ip.txt"} {
		for _, line := range dataLines(filepath.Join(stateDir, name)) {
			prefix, ok := parsePrefixOrAddr(line)
			if ok {
				seen[prefix] = struct{}{}
			}
		}
	}
	return formatPrefixes(keys(seen))
}

const maxGeoDisputedBytes = 4 << 20

func LoadGeoDisputed(stateDir string) string {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	info, err := os.Stat(filepath.Join(stateDir, "chnroute", "geo-disputed.txt"))
	if err != nil || info.Size() > maxGeoDisputedBytes {
		return ""
	}
	body, err := os.ReadFile(filepath.Join(stateDir, "chnroute", "geo-disputed.txt"))
	if err != nil {
		return ""
	}
	return string(body)
}

func LoadCNCIDRs(stateDir string) []string {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	v4 := loadDirect4(filepath.Join(stateDir, "chnroute", "direct4.txt"))
	if len(v4) == 0 {
		return []string{}
	}
	v6 := loadAPNICCNv6(filepath.Join(stateDir, "chnroute", "delegated-apnic-latest.txt"))
	merged := append(collapsePrefixes(v4), collapsePrefixes(v6)...)
	return formatPrefixes(merged)
}

func loadDirect4(path string) []netip.Prefix {
	var out []netip.Prefix
	for _, line := range dataLines(path) {
		prefix, err := netip.ParsePrefix(line)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if !ipset.IsGlobalPrefix(prefix) {
			continue
		}
		out = append(out, prefix.Masked())
	}
	if len(out) < minDirect4Entries {
		return nil
	}
	return out
}

func loadAPNICCNv6(path string) []netip.Prefix {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 7 || parts[1] != "CN" || parts[2] != "ipv6" {
			continue
		}
		if parts[6] != "allocated" && parts[6] != "assigned" {
			continue
		}
		bits, err := strconv.Atoi(strings.TrimSpace(parts[4]))
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[3]))
		if err != nil || !addr.Is6() || addr.Is4In6() {
			continue
		}
		prefix := netip.PrefixFrom(addr, bits)
		if !prefix.IsValid() || !ipset.IsGlobalAddr(addr) {
			continue
		}
		out = append(out, prefix.Masked())
	}
	if len(out) < minCNV6Entries {
		return nil
	}
	return out
}

func collapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	current := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			current = append(current, prefix.Masked())
		}
	}
	for {
		sort.Slice(current, func(i, j int) bool {
			if c := current[i].Addr().Compare(current[j].Addr()); c != 0 {
				return c < 0
			}
			return current[i].Bits() < current[j].Bits()
		})
		kept := make([]netip.Prefix, 0, len(current))
		for _, prefix := range current {
			if len(kept) > 0 && kept[len(kept)-1].Contains(prefix.Addr()) &&
				kept[len(kept)-1].Bits() <= prefix.Bits() {
				continue
			}
			kept = append(kept, prefix)
		}
		merged := make([]netip.Prefix, 0, len(kept))
		changed := false
		for index := 0; index < len(kept); index++ {
			if index+1 < len(kept) && siblings(kept[index], kept[index+1]) {
				parent := netip.PrefixFrom(kept[index].Addr(), kept[index].Bits()-1).Masked()
				merged = append(merged, parent)
				index++
				changed = true
				continue
			}
			merged = append(merged, kept[index])
		}
		current = merged
		if !changed {
			return current
		}
	}
}

func siblings(a, b netip.Prefix) bool {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	parentA := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	parentB := netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked()
	return parentA == parentB
}

func formatPrefixes(prefixes []netip.Prefix) []string {
	sort.Slice(prefixes, func(i, j int) bool {

		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func keys(set map[netip.Prefix]struct{}) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(set))
	for prefix := range set {
		out = append(out, prefix)
	}
	return out
}

func parsePrefixOrAddr(line string) (netip.Prefix, bool) {
	if strings.Contains(line, "/") {
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(line)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func dataLines(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		value := strings.TrimSpace(line)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		out = append(out, value)
	}
	return out
}
