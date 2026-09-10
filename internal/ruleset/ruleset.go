package ruleset

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

const DeadRTOMillis = 120000

type Config struct {
	Direct        *ipset.Set
	Disputed      *ipset.Set
	Promoted      *ipset.Set
	PSL           *domain.PSL
	ManualZones   map[string]struct{}
	SharedAnycast map[netip.Addr]struct{}
	Aggregate     int
}

func (cfg Config) routable(addr netip.Addr) bool {
	return addr.Is4() && ipset.IsGlobalPrefix(netip.PrefixFrom(addr, 32))
}

func (cfg Config) isDisputed(addr netip.Addr) bool {
	return cfg.Disputed != nil && cfg.routable(addr) && cfg.Disputed.Contains(addr)
}

func (cfg Config) isPromoted(addr netip.Addr) bool {
	return cfg.Promoted != nil && cfg.routable(addr) && cfg.Promoted.Contains(addr)
}

func (cfg Config) mainlandEvidence(addr netip.Addr) bool {
	if !cfg.routable(addr) {
		return false
	}
	if cfg.isDisputed(addr) {
		return false
	}
	if cfg.isPromoted(addr) {
		return true
	}
	return cfg.Direct.Contains(addr)
}

type Zone struct {
	Name   string
	Count  int
	Forced bool
}

type Result struct {
	RoutePrefixes    []netip.Prefix
	ECSPrefixes      []netip.Prefix
	MatchedZones     []Zone
	DeadZones        []string
	Defective        map[string][]string
	SharedExcluded   []string
	DisputedExcluded []string
	PromotedUsed     []string
	RTOSeen          bool

	DirectECSPrefixes int
	DirectECSCutAddrs uint64
}

func Build(s infra.Snapshot, cfg Config) (Result, error) {
	if cfg.Direct == nil || cfg.Direct.Len() == 0 {
		return Result{}, errors.New("direct4 为空")
	}
	if cfg.PSL == nil {
		return Result{}, errors.New("Public Suffix List 不可用")
	}
	agg := cfg.Aggregate
	if agg < 0 || agg > 32 {
		return Result{}, errors.New("聚合前缀必须在 0..32 之间")
	}
	allZones := s.Zones()
	zones := make(map[string][]infra.Entry, len(allZones))
	for zone, entries := range allZones {
		for _, e := range entries {
			if e.IP.Is4() {
				zones[zone] = append(zones[zone], e)
			}
		}
		if len(zones[zone]) == 0 {
			delete(zones, zone)
		}
	}
	rtos := make(map[string]map[string]infra.Entry)
	for _, e := range s.Entries {
		if !e.IP.Is4() {
			continue
		}
		if rtos[e.Zone] == nil {
			rtos[e.Zone] = make(map[string]infra.Entry)
		}
		key := e.IP.String()
		if old, ok := rtos[e.Zone][key]; !ok || (!old.HasRTO && e.HasRTO) || (e.HasRTO && old.HasRTO && e.RTO > old.RTO) {
			rtos[e.Zone][key] = e
		}
	}
	r := Result{Defective: make(map[string][]string)}
	r.RTOSeen = false
	for _, e := range s.Entries {
		if e.IP.Is4() && e.HasRTO && e.RTO >= 0 {
			r.RTOSeen = true
			break
		}
	}
	var routePrefixes []netip.Prefix
	var ecsExact []netip.Prefix
	var ecsExtra []netip.Prefix
	sharedExcluded := make(map[string]struct{})
	disputedExcluded := make(map[string]struct{})
	promotedUsed := make(map[string]struct{})
	for zone, entries := range zones {
		if defect := domain.ZoneDefect(zone, cfg.PSL); defect != "" {
			r.Defective[defect] = append(r.Defective[defect], zone)
			continue
		}
		forced := false
		for manual := range cfg.ManualZones {
			if zone == manual || strings.HasSuffix(zone, "."+manual) {
				forced = true
				break
			}
		}
		hasCN := false
		for _, e := range entries {
			if cfg.mainlandEvidence(e.IP) {
				hasCN = true
				break
			}
		}
		if !forced && !hasCN {
			continue
		}
		dead := false
		if !forced && r.RTOSeen {
			byIP := rtos[zone]
			dead = len(byIP) > 0 && len(byIP) == len(entries)
			if dead {
				for _, e := range entries {
					v, ok := byIP[e.IP.String()]
					if !ok || !v.HasRTO || v.RTO < DeadRTOMillis {
						dead = false
						break
					}
				}
			}
		}
		if dead {
			r.DeadZones = append(r.DeadZones, zone)
			continue
		}
		r.MatchedZones = append(r.MatchedZones, Zone{Name: zone, Count: len(entries), Forced: forced})
		for _, e := range entries {
			if !e.IP.Is4() {
				continue
			}
			global := ipset.IsGlobalPrefix(netip.PrefixFrom(e.IP, 32))

			if !global {
				continue
			}
			if cfg.isDisputed(e.IP) {
				p := netip.PrefixFrom(e.IP, 32)
				if agg > 0 && agg < 32 {
					p = netip.PrefixFrom(e.IP, agg).Masked()
				}
				routePrefixes = append(routePrefixes, p)
				disputedExcluded[e.IP.String()] = struct{}{}
				continue
			}
			if cfg.isPromoted(e.IP) {
				promotedUsed[e.IP.String()] = struct{}{}
			}
			if agg > 0 && agg < 32 && cfg.mainlandEvidence(e.IP) {
				p := netip.PrefixFrom(e.IP, agg).Masked()
				routePrefixes = append(routePrefixes, p)
				ecsExact = append(ecsExact, netip.PrefixFrom(e.IP, 32))
				continue
			}
			if _, shared := cfg.SharedAnycast[e.IP]; shared {
				ecsExtra = append(ecsExtra, netip.PrefixFrom(e.IP, 32))
				sharedExcluded[e.IP.String()] = struct{}{}
				continue
			}
			routePrefixes = append(routePrefixes, netip.PrefixFrom(e.IP, 32))
			ecsExact = append(ecsExact, netip.PrefixFrom(e.IP, 32))
		}
	}
	r.RoutePrefixes = collapse(routePrefixes)
	for ip := range sharedExcluded {
		r.SharedExcluded = append(r.SharedExcluded, ip)
	}
	for ip := range disputedExcluded {
		r.DisputedExcluded = append(r.DisputedExcluded, ip)
	}
	for ip := range promotedUsed {
		r.PromotedUsed = append(r.PromotedUsed, ip)
	}
	allECS := append(append([]netip.Prefix{}, ecsExact...), ecsExtra...)
	directECS := directECSPrefixes(cfg)
	r.DirectECSPrefixes = len(directECS)
	r.DirectECSCutAddrs = cfg.Direct.AddressCount() - directECSAddressCount(directECS)
	for _, p := range directECS {
		if ipset.IsGlobalPrefix(p) {
			allECS = append(allECS, p)
		}
	}
	r.ECSPrefixes = collapse(allECS)
	sort.Slice(r.MatchedZones, func(i, j int) bool { return r.MatchedZones[i].Name < r.MatchedZones[j].Name })
	sort.Strings(r.DeadZones)
	sort.Strings(r.SharedExcluded)
	sort.Strings(r.DisputedExcluded)
	sort.Strings(r.PromotedUsed)
	for key := range r.Defective {
		sort.Strings(r.Defective[key])
	}
	return r, nil
}

func directECSAddressCount(prefixes []netip.Prefix) uint64 {
	var total uint64
	for _, p := range prefixes {
		if rg, ok := ipset.PrefixRange(p); ok {
			total += uint64(rg.Hi-rg.Lo) + 1
		}
	}
	return total
}

func directECSPrefixes(cfg Config) []netip.Prefix {
	if cfg.Disputed == nil || cfg.Disputed.Len() == 0 {
		return cfg.Direct.Prefixes()
	}
	remaining := ipset.Subtract(cfg.Direct.Ranges(), cfg.Disputed.Ranges())
	return ipset.New(remaining).Prefixes()
}

func collapse(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	ranges := make([]ipset.Range, 0, len(prefixes))
	for _, p := range prefixes {
		if rg, ok := ipset.PrefixRange(p); ok {
			ranges = append(ranges, rg)
		}
	}
	return ipset.New(ranges).Prefixes()
}

func LoadManual(r io.Reader) (map[string]struct{}, error) {
	sc := bufio.NewScanner(r)
	out := make(map[string]struct{})
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(strings.TrimRight(line, "."))] = struct{}{}
	}
	return out, sc.Err()
}

func LoadShared(r io.Reader) (map[netip.Addr]struct{}, error) {
	sc := bufio.NewScanner(r)
	out := make(map[netip.Addr]struct{})
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) == 0 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		ip, err := netip.ParseAddr(parts[0])
		if err == nil {
			out[ip] = struct{}{}
		}
	}
	return out, sc.Err()
}

func OpenOptional(path string, loader func(io.Reader) error) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return loader(f)
}
