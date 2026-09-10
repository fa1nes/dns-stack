package polluted

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

type Evidence struct {
	FirstSeenAt int64 `json:"first_seen_at"`
	LastSeenAt  int64 `json:"last_seen_at"`
	SeenCount   int   `json:"seen_count"`
}

type Options struct {
	RawPath         string
	EvidencePath    string
	OldOutputPath   string
	ActiveOutPath   string
	EvidenceOutPath string
	CIDROutPath     string
	StatsPath       string
	MaxAgeDays      int
	MinObservations int
	Now             func() time.Time
}

type Result struct {
	Observed    int
	Added       int
	Total       int
	RawUnique   int
	CIDREntries int
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func readAddrs(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		addr, err := netip.ParseAddr(strings.TrimSpace(sc.Text()))
		if err != nil {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out, sc.Err()
}

func Run(opt Options) (Result, error) {
	var res Result
	if opt.MaxAgeDays < 1 || opt.MinObservations < 2 {
		return res, fmt.Errorf("invalid polluted evidence thresholds")
	}
	now := opt.now().Unix()

	rawAddrs, err := readAddrs(opt.RawPath)
	if err != nil && !os.IsNotExist(err) {
		return res, err
	}
	counts := map[string]int{}
	for _, a := range rawAddrs {
		counts[a.String()]++
	}
	res.RawUnique = len(counts)

	observed := map[string]struct{}{}
	for key, n := range counts {
		if n >= opt.MinObservations {
			observed[key] = struct{}{}
		}
	}
	res.Observed = len(observed)

	evidence := map[string]Evidence{}
	if data, err := os.ReadFile(opt.EvidencePath); err == nil {
		if err := json.Unmarshal(data, &evidence); err != nil {
			evidence = map[string]Evidence{}
		}
	}

	oldActive := map[string]struct{}{}
	if addrs, err := readAddrs(opt.OldOutputPath); err == nil {
		for _, a := range addrs {
			oldActive[a.String()] = struct{}{}
		}
	}
	if len(evidence) == 0 && len(oldActive) > 0 {
		for key := range oldActive {
			evidence[key] = Evidence{FirstSeenAt: now, LastSeenAt: now, SeenCount: 1}
		}
	}

	for key := range observed {
		item := evidence[key]
		first := item.FirstSeenAt
		if first == 0 {
			first = now
		}
		evidence[key] = Evidence{FirstSeenAt: first, LastSeenAt: now, SeenCount: item.SeenCount + 1}
	}

	cutoff := now - int64(opt.MaxAgeDays)*86400
	for key, item := range evidence {
		if item.LastSeenAt < cutoff {
			delete(evidence, key)
		}
	}

	active := make([]netip.Addr, 0, len(evidence))
	for key := range evidence {
		if addr, err := netip.ParseAddr(key); err == nil {
			active = append(active, addr.Unmap())
		}
	}
	cidrutil.SortAddrs(active)
	res.Total = len(active)
	for _, a := range active {
		if _, ok := oldActive[a.String()]; !ok {
			res.Added++
		}
	}

	var body strings.Builder
	for i, a := range active {
		if i > 0 {
			body.WriteString("\n")
		}
		body.WriteString(a.String())
	}
	if len(active) > 0 {
		body.WriteString("\n")
	}
	if err := os.WriteFile(opt.ActiveOutPath, []byte(body.String()), 0o644); err != nil {
		return res, err
	}

	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(opt.EvidenceOutPath, encoded, 0o644); err != nil {
		return res, err
	}

	if opt.CIDROutPath != "" {
		prefixes := cidrutil.CollapseAddrs(active)
		res.CIDREntries = len(prefixes)
		var cidr strings.Builder
		for i, p := range prefixes {
			if i > 0 {
				cidr.WriteString("\n")
			}
			cidr.WriteString(p.String())
		}
		if len(prefixes) > 0 {
			cidr.WriteString("\n")
		}
		if err := os.WriteFile(opt.CIDROutPath, []byte(cidr.String()), 0o644); err != nil {
			return res, err
		}
	}

	if opt.StatsPath != "" {
		stats := fmt.Sprintf("%d %d %d %d\n", res.Observed, res.Added, res.Total, res.RawUnique)
		if err := os.WriteFile(opt.StatsPath, []byte(stats), 0o644); err != nil {
			return res, err
		}
	}
	return res, nil
}
