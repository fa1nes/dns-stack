package anycast

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

var sharedDNSAS = map[int]string{
	16509: "AWS", 14618: "AWS", 7224: "AWS",
	20940: "Akamai", 21342: "Akamai", 16625: "Akamai", 35994: "Akamai",
	32787: "Akamai", 12222: "Akamai",
	13335: "Cloudflare",
	26496: "GoDaddy", 398101: "GoDaddy",
	33517: "Dyn", 33070: "Dyn",
	30060: "Verisign",
	19551: "Incapsula",
}

type Config struct {
	StateDir   string
	OutPath    string
	UnboundCtl string
	GeoIP      *geoip.GeoDB
	DBIP       *geoip.DBIP
	DryRun     bool
}

type Finding struct {
	IP      string
	ASN     int
	Label   string
	Because string
	Outside []string
	Sources []string
}

type Report struct {
	InfraIPs   int
	Candidates int
	Kept       int
	Shared     []Finding
	ByOrg      map[string]int
	Note       string
	Wrote      bool
	BySource   map[string]int
}

func (c Config) path(rel string) string {
	base := c.StateDir
	if base == "" {
		base = "/var/lib/dns-stack"
	}
	return filepath.Join(base, filepath.FromSlash(rel))
}

func (c Config) outPath() string {
	if c.OutPath != "" {
		return c.OutPath
	}
	return c.path("chnroute/shared-anycast.txt")
}

func dataLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out
}

func loadDirect4(path string) *ipset.Set {
	var ranges []ipset.Range
	for _, value := range dataLines(path) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if r, ok := ipset.PrefixRange(prefix); ok {
			ranges = append(ranges, r)
		}
	}
	if len(ranges) == 0 {
		return nil
	}
	return ipset.New(ranges)
}

func loadCNZones(c Config) (map[string]bool, []string) {
	exact := map[string]bool{}
	for _, zone := range dataLines(c.path("chnroute/cn-zones-matched.txt")) {
		exact[strings.ToLower(zone)] = true
	}
	var suffixes []string
	for _, zone := range dataLines(c.path("manual-cn-zones.txt")) {
		suffixes = append(suffixes, strings.ToLower(zone))
	}
	return exact, suffixes
}

func servesCNZone(zones []string, exact map[string]bool, suffixes []string) string {
	for _, zone := range zones {
		if exact[zone] {
			return zone
		}
		for _, suffix := range suffixes {
			if zone == suffix || strings.HasSuffix(zone, "."+suffix) {
				return zone
			}
		}
	}
	return ""
}

func dumpInfra(ctx context.Context, ctl string) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ctl, "dump_infra").Output()
	if err != nil {
		return nil, err
	}
	snapshot, err := infra.Parse(strings.NewReader(string(out)))
	if err != nil {
		return nil, err
	}
	zones := map[string]map[string]bool{}
	for _, entry := range snapshot.Entries {
		if !entry.IP.Is4() {
			continue
		}
		zone := strings.ToLower(strings.TrimSuffix(entry.Zone, "."))
		if zone == "" {
			continue
		}
		key := entry.IP.String()
		if zones[key] == nil {
			zones[key] = map[string]bool{}
		}
		zones[key][zone] = true
	}
	flat := make(map[string][]string, len(zones))
	for ip, set := range zones {
		list := make([]string, 0, len(set))
		for zone := range set {
			list = append(list, zone)
		}
		sort.Strings(list)
		flat[ip] = list
	}
	return flat, nil
}

func Run(ctx context.Context, c Config) (Report, error) {
	report := Report{ByOrg: map[string]int{}, BySource: map[string]int{}}

	if c.GeoIP == nil || !c.GeoIP.HasASN() {
		report.Note = "geoip-unavailable"
		return report, c.finish(&report)
	}
	direct := loadDirect4(c.path("chnroute/direct4.txt"))
	if direct == nil {
		report.Note = "direct4-unavailable"
		return report, c.finish(&report)
	}
	keep := map[string]bool{}
	for _, ip := range dataLines(c.path("shared-anycast-keep.txt")) {
		keep[ip] = true
	}
	report.Kept = len(keep)

	ipZones, err := dumpInfra(ctx, c.UnboundCtl)
	if err != nil || len(ipZones) == 0 {
		report.Note = "infra-empty"
		return report, nil
	}
	report.InfraIPs = len(ipZones)

	exact, suffixes := loadCNZones(c)
	if len(exact) == 0 && len(suffixes) == 0 {
		report.Note = "cn-zones-unavailable"
		return report, c.finish(&report)
	}

	addresses := make([]string, 0, len(ipZones))
	for ip := range ipZones {
		addresses = append(addresses, ip)
	}
	sort.Strings(addresses)

	for _, ip := range addresses {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !ipset.IsGlobalAddr(addr) {
			continue
		}
		if direct.Contains(addr) {
			continue
		}
		zones := ipZones[ip]
		because := servesCNZone(zones, exact, suffixes)
		if because == "" {
			continue
		}
		report.Candidates++
		if keep[ip] {
			continue
		}
		asn, label, matched := c.sharedByAnySource(ip)
		if len(matched) == 0 {
			continue
		}
		var outside []string
		for _, zone := range zones {
			if servesCNZone([]string{zone}, exact, suffixes) == "" {
				outside = append(outside, zone)
			}
		}
		sort.Strings(outside)
		if len(outside) > 3 {
			outside = outside[:3]
		}
		report.Shared = append(report.Shared, Finding{
			IP: ip, ASN: asn, Label: label, Because: because, Outside: outside,
			Sources: matched,
		})
		report.ByOrg[label]++
		for _, name := range matched {
			report.BySource[name]++
		}
	}
	return report, c.finish(&report)
}

func (c Config) sharedByAnySource(ip string) (int, string, []string) {
	type probe struct {
		name string
		asn  any
	}
	probes := []probe{{"maxmind", c.GeoIP.Lookup(ip).ASN}}
	if c.DBIP != nil {
		if rec := c.DBIP.Lookup(ip).Record; rec != nil {
			probes = append(probes, probe{"dbip", rec["asn"]})
		}
	}
	firstASN, firstLabel := 0, ""
	var matched []string
	for _, item := range probes {
		asn, ok := geoip.ASNumber(item.asn)
		if !ok {
			continue
		}
		label, shared := sharedDNSAS[asn]
		if !shared {
			continue
		}
		if firstLabel == "" {
			firstASN, firstLabel = asn, label
		}
		matched = append(matched, item.name)
	}
	sort.Strings(matched)
	return firstASN, firstLabel, matched
}

func (c Config) finish(report *Report) error {
	if c.DryRun {
		return nil
	}
	if err := write(c.outPath(), report.Shared, report.Note); err != nil {
		return err
	}
	report.Wrote = true
	return nil
}

func write(path string, shared []Finding, note string) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# generated-at %d\n", time.Now().Unix())
	fmt.Fprintf(&builder, "# count %d\n", len(shared))
	if note != "" {
		fmt.Fprintf(&builder, "# note %s\n", note)
	}
	for _, item := range shared {
		builder.WriteString(item.IP)
		builder.WriteString("\n")
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(builder.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}
