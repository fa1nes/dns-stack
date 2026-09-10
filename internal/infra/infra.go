package infra

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type Entry struct {
	Zone   string
	IP     netip.Addr
	RTO    int
	HasRTO bool
}

type Snapshot struct {
	Entries []Entry
	Skipped int
}

func Parse(r io.Reader) (Snapshot, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := Snapshot{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			out.Skipped++
			continue
		}
		ip, err := netip.ParseAddr(parts[0])
		if err != nil {
			out.Skipped++
			continue
		}
		zone := strings.ToLower(strings.TrimRight(parts[1], "."))
		if !strings.HasSuffix(parts[1], ".") || zone == "" {
			out.Skipped++
			continue
		}
		e := Entry{Zone: zone, IP: ip}
		for i := 2; i+1 < len(parts); i++ {
			if parts[i] != "rto" {
				continue
			}
			v, err := strconv.Atoi(parts[i+1])
			if err == nil && v >= 0 {
				e.RTO = v
				e.HasRTO = true
			}
			break
		}
		out.Entries = append(out.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return Snapshot{}, err
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Zone != b.Zone {
			return a.Zone < b.Zone
		}
		if a.IP.String() != b.IP.String() {
			return a.IP.String() < b.IP.String()
		}
		if a.HasRTO != b.HasRTO {
			return !a.HasRTO
		}
		return a.RTO < b.RTO
	})
	return out, nil
}

func (s Snapshot) Pairs() []Entry {
	if len(s.Entries) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s.Entries))
	out := make([]Entry, 0, len(s.Entries))
	for _, e := range s.Entries {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%t", e.Zone, e.IP.String(), e.RTO, e.HasRTO)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

func (s Snapshot) Zones() map[string][]Entry {
	zones := make(map[string][]Entry)
	seen := make(map[string]map[string]struct{})
	for _, e := range s.Entries {
		if seen[e.Zone] == nil {
			seen[e.Zone] = make(map[string]struct{})
		}
		key := e.IP.String()
		if _, ok := seen[e.Zone][key]; ok {
			continue
		}
		seen[e.Zone][key] = struct{}{}
		zones[e.Zone] = append(zones[e.Zone], e)
	}
	for zone := range zones {
		sort.Slice(zones[zone], func(i, j int) bool {
			return zones[zone][i].IP.Compare(zones[zone][j].IP) < 0
		})
	}
	return zones
}
