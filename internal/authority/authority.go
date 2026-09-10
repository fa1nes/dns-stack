package authority

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

const MaxNSPerZone = 8

const (
	VerdictCN      = "cn"
	VerdictUnknown = "unknown"

	ReasonNoFinalAnswer       = "no_final_answer"
	ReasonNoAuthorityIP       = "no_authority_ip"
	ReasonNoZoneWithAuthority = "no_zone_with_authority"
)

type Mainland interface {
	IsMainland(addr netip.Addr) bool
}

type Verdict struct {
	Domain         string
	Zone           string
	Verdict        string
	Reason         string
	AuthorityIPs   []netip.Addr
	CNAuthorityIPs []netip.Addr
}

func isRoutable(addr netip.Addr) bool {
	return ipset.IsGlobalAddr(addr)
}

func nsNames(ctx context.Context, c *resolve.Client, zone string) []string {
	answer := c.Query(ctx, zone, dnswire.TypeNS)
	names := resolve.TargetNames(answer, dnswire.TypeNS)
	if len(names) > 0 {
		if len(names) > MaxNSPerZone {
			names = names[:MaxNSPerZone]
		}
		return names
	}
	soa := c.Query(ctx, zone, dnswire.TypeSOA)
	mnames := resolve.TargetNames(soa, dnswire.TypeSOA)
	if len(mnames) == 0 {
		return nil
	}
	return mnames[:1]
}

func authorityIPs(ctx context.Context, c *resolve.Client, zone string) []netip.Addr {
	names := nsNames(ctx, c, zone)
	if len(names) == 0 {
		return nil
	}
	type result struct {
		v4, v6 []netip.Addr
	}
	results := make([]result, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			a := c.Query(ctx, name, dnswire.TypeA)
			aaaa := c.Query(ctx, name, dnswire.TypeAAAA)
			v4, _ := resolve.Addresses(a)
			_, v6 := resolve.Addresses(aaaa)
			results[i] = result{v4: v4, v6: v6}
		}(i, name)
	}
	wg.Wait()
	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	for _, r := range results {
		for _, addr := range append(append([]netip.Addr{}, r.v4...), r.v6...) {
			addr = addr.Unmap()
			if !isRoutable(addr) {
				continue
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	sortAddrs(out)
	return out
}

func sortAddrs(values []netip.Addr) {
	sort.Slice(values, func(i, j int) bool { return values[i].Compare(values[j]) < 0 })
}

func FinalRecords(ctx context.Context, c *resolve.Client, name string) []netip.Addr {
	a := c.Query(ctx, name, dnswire.TypeA)
	aaaa := c.Query(ctx, name, dnswire.TypeAAAA)
	v4, _ := resolve.Addresses(a)
	_, v6 := resolve.Addresses(aaaa)
	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	for _, addr := range append(append([]netip.Addr{}, v4...), v6...) {
		addr = addr.Unmap()
		if !isRoutable(addr) {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	sortAddrs(out)
	return out
}

type ZoneAuthority struct {
	Zone   string
	ByName map[string][]netip.Addr
}

func Authorities(ctx context.Context, c *resolve.Client, name string) ZoneAuthority {
	labels := strings.Split(dnswire.NormalizeName(name), ".")
	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")
		names := nsNames(ctx, c, zone)
		if len(names) == 0 {
			continue
		}
		byName := make(map[string][]netip.Addr, len(names))
		for _, ns := range names {
			v4, _ := resolve.Addresses(c.Query(ctx, ns, dnswire.TypeA))
			for _, addr := range v4 {
				addr = addr.Unmap()
				if isRoutable(addr) {
					byName[ns] = append(byName[ns], addr)
				}
			}
		}
		if len(byName) > 0 {
			return ZoneAuthority{Zone: zone, ByName: byName}
		}
	}
	return ZoneAuthority{}
}

func ClassifyOne(
	ctx context.Context, c *resolve.Client, m Mainland, name string,
	psl *domain.PSL, zoneCache map[string]Verdict,
) Verdict {
	d := dnswire.NormalizeName(name)
	labels := strings.Split(d, ".")

	if len(FinalRecords(ctx, c, d)) == 0 {
		return Verdict{Domain: d, Zone: d, Verdict: VerdictUnknown, Reason: ReasonNoFinalAnswer}
	}

	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")

		if psl != nil && zone != d && psl.IsPublicSuffix(zone) {
			continue
		}
		if cached, ok := zoneCache[zone]; ok {
			if cached.Verdict != VerdictUnknown {
				return Verdict{
					Domain: d, Zone: zone, Verdict: cached.Verdict, Reason: cached.Reason,
					AuthorityIPs: cached.AuthorityIPs, CNAuthorityIPs: cached.CNAuthorityIPs,
				}
			}
			continue
		}
		ips := authorityIPs(ctx, c, zone)
		if len(ips) == 0 {
			if zoneCache != nil {
				zoneCache[zone] = Verdict{
					Domain: d, Zone: zone, Verdict: VerdictUnknown, Reason: ReasonNoAuthorityIP,
				}
			}
			continue
		}
		var cn []netip.Addr
		for _, addr := range ips {
			if m != nil && m.IsMainland(addr) {
				cn = append(cn, addr)
			}
		}
		verdict := VerdictUnknown
		reason := fmt.Sprintf("authority_all_offshore(0/%d)", len(ips))
		if len(cn) > 0 {
			verdict = VerdictCN
			reason = fmt.Sprintf("authority_in_cn(%d/%d)", len(cn), len(ips))
		}
		result := Verdict{
			Domain: d, Zone: zone, Verdict: verdict, Reason: reason,
			AuthorityIPs: ips, CNAuthorityIPs: cn,
		}
		if zoneCache != nil {
			zoneCache[zone] = result
		}
		return result
	}
	return Verdict{Domain: d, Zone: d, Verdict: VerdictUnknown, Reason: ReasonNoZoneWithAuthority}
}

func ClassifyMany(
	ctx context.Context, c *resolve.Client, m Mainland, names []string,
	psl *domain.PSL, concurrency int,
) []Verdict {
	if concurrency < 1 {
		concurrency = 1
	}
	out := make([]Verdict, len(names))
	cache := make(map[string]Verdict)
	var cacheMu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			local := make(map[string]Verdict)
			cacheMu.Lock()
			for k, v := range cache {
				local[k] = v
			}
			cacheMu.Unlock()
			verdict := ClassifyOne(ctx, c, m, name, psl, local)
			cacheMu.Lock()
			for k, v := range local {
				if _, ok := cache[k]; !ok {
					cache[k] = v
				}
			}
			cacheMu.Unlock()
			out[i] = verdict
		}(i, name)
	}
	wg.Wait()
	return out
}

func LandingIsMainland(
	ctx context.Context, c *resolve.Client, m Mainland, name string,
) (mainland bool, known bool) {
	routable := FinalRecords(ctx, c, name)
	if len(routable) == 0 {
		return false, false
	}
	for _, addr := range routable {
		if m != nil && m.IsMainland(addr) {
			return true, true
		}
	}
	return false, true
}

func CollapseByResolution(
	ctx context.Context, c *resolve.Client, names []string, concurrency int,
) []string {
	unique := dedupSorted(names)
	if len(unique) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	members := make(map[string]struct{}, len(unique))
	for _, n := range unique {
		members[n] = struct{}{}
	}
	type outcome struct {
		name      string
		parent    string
		hasAnswer bool
	}
	results := make([]outcome, len(unique))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, name := range unique {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			_, parent, found := strings.Cut(name, ".")
			if !found || !strings.Contains(parent, ".") {
				results[i] = outcome{name: name, hasAnswer: len(FinalRecords(ctx, c, name)) > 0}
				return
			}
			if _, ok := members[parent]; !ok {
				results[i] = outcome{name: name, hasAnswer: len(FinalRecords(ctx, c, name)) > 0}
				return
			}
			child := FinalRecords(ctx, c, name)
			if len(child) == 0 {
				results[i] = outcome{name: name}
				return
			}
			parentIPs := FinalRecords(ctx, c, parent)
			if len(parentIPs) == 0 {
				results[i] = outcome{name: name, hasAnswer: true}
				return
			}
			shared := false
			set := make(map[netip.Addr]struct{}, len(parentIPs))
			for _, addr := range parentIPs {
				set[addr] = struct{}{}
			}
			for _, addr := range child {
				if _, ok := set[addr]; ok {
					shared = true
					break
				}
			}
			if shared {
				results[i] = outcome{name: name, parent: parent, hasAnswer: true}
				return
			}
			results[i] = outcome{name: name, hasAnswer: true}
		}(i, name)
	}
	wg.Wait()

	kept := make(map[string]struct{})
	for _, r := range results {
		if !r.hasAnswer {
			continue
		}
		if r.parent != "" {
			kept[r.parent] = struct{}{}
			continue
		}
		kept[r.name] = struct{}{}
	}
	out := make([]string, 0, len(kept))
	for name := range kept {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func dedupSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = dnswire.NormalizeName(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
