package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/geoip"
)

const ipLookupTimeout = 12 * time.Second

type ipDivergence struct {
	Field  string            `json:"field"`
	Values map[string]string `json:"values"`
}

func (s *Server) dbipDB() *geoip.DBIP {
	s.geoMu.Lock()
	defer s.geoMu.Unlock()
	if s.dbip == nil {
		s.dbip = geoip.NewDBIP(s.statePath("geoip/dbip-asn.mmdb"), s.statePath("geoip/dbip-city.mmdb"))
	}
	return s.dbip
}

func (s *Server) databaseFreshness() map[string]any {
	out := map[string]any{}
	now := s.now().Unix()
	add := func(name string, status map[string]any) {
		entry := map[string]any{"available": status["available"], "error": status["error"]}
		if epoch, ok := status["build_epoch"].(int64); ok && epoch > 0 {
			entry["build_epoch"] = epoch
			entry["age_days"] = (now - epoch) / 86400
		}
		out[name] = entry
	}
	local := s.geoipStatus()
	for _, kind := range []string{"asn", "city", "cnip"} {
		if entry, ok := local[kind].(map[string]any); ok {
			add(kind, entry)
		}
	}
	dbip := s.dbipDB().Status()
	for _, kind := range []string{"asn", "city"} {
		if entry, ok := dbip[kind].(map[string]any); ok {
			add("dbip_"+kind, entry)
		}
	}
	return out
}

func truthyValue(raw any) bool {
	value, _ := raw.(bool)
	return value
}

func (s *Server) onlineDB() *geoip.OnlineLookup {
	s.geoMu.Lock()
	defer s.geoMu.Unlock()
	if s.online == nil {
		s.online = geoip.NewOnlineLookup()
	}
	return s.online
}

func stringField(record map[string]any, key string) string {
	if record == nil {
		return ""
	}
	switch value := record[key].(type) {
	case string:
		return value
	case nil:
		return ""
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return ""
		}
		return strings.Trim(string(encoded), `"`)
	}
}

var comparableFields = []string{"asn", "country_code"}

func divergences(sources []geoip.SourceResult) []ipDivergence {
	var out []ipDivergence
	for _, field := range comparableFields {
		values := map[string]string{}
		distinct := map[string]bool{}
		for _, item := range sources {
			value := stringField(item.Record, field)
			if value == "" {
				continue
			}
			values[item.Name] = value
			distinct[strings.ToUpper(value)] = true
		}
		if len(distinct) > 1 {
			out = append(out, ipDivergence{Field: field, Values: values})
		}
	}
	return out
}

func (s *Server) routingFacts(ip string) map[string]any {
	addr, err := netip.ParseAddr(ip)
	facts := map[string]any{
		"direct4": nil, "cn_authority": nil, "shared_anycast": nil,
		"polluted": nil, "global": nil,
	}
	if err != nil {
		return facts
	}
	facts["global"] = isPublicIP(addr.AsSlice())
	facts["direct4"] = prefixContains(loadedPrefixes(s.statePath("chnroute/direct4.txt")), ip)
	facts["cn_authority"] = prefixContains(loadedPrefixes(s.statePath("chnroute/cn-authority.txt")), ip)
	facts["polluted"] = prefixContains(loadedPrefixes(s.statePath("polluted-ip-cidr.txt")), ip)
	for _, line := range dataLines(s.statePath("chnroute/shared-anycast.txt")) {
		if line == ip {
			facts["shared_anycast"] = true
			break
		}
	}
	if facts["shared_anycast"] == nil {
		facts["shared_anycast"] = false
	}
	return facts
}

func (s *Server) reverseDNS(ctx context.Context, ip string) []string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	name, err := reverseName(addr)
	if err != nil {
		return nil
	}
	reply := dnsProbe(ctx, name, "PTR", "local-unbound", "")
	records, _ := reply["records"].([]map[string]any)
	var out []string
	for _, record := range records {
		if record["type"] != "PTR" {
			continue
		}
		if value, _ := record["value"].(string); value != "" {
			out = append(out, strings.TrimSuffix(value, "."))
		}
	}
	sort.Strings(out)
	return out
}

func reverseName(addr netip.Addr) (string, error) {
	if addr.Is4() {
		b := addr.As4()
		return itoa(int(b[3])) + "." + itoa(int(b[2])) + "." + itoa(int(b[1])) + "." + itoa(int(b[0])) + ".in-addr.arpa", nil
	}
	b := addr.As16()
	const hex = "0123456789abcdef"
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func (s *Server) ipLookup(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("ip"))
	if target == "" {
		target = clientIP(r)
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		writeJSON(w, 400, map[string]any{"detail": "不是合法的 IP 地址"})
		return
	}
	target = addr.String()

	ctx, cancel := context.WithTimeout(r.Context(), ipLookupTimeout)
	defer cancel()

	s.geoMu.Lock()
	if s.geo == nil {
		s.geo = newPanelGeoDB(s)
	}
	local := s.geo
	s.geoMu.Unlock()

	sources := local.Sources(target)
	sources = append(sources, s.dbipDB().Lookup(target))

	var wg sync.WaitGroup
	var ptr []string
	online := geoip.SourceResult{Name: "ipsb", Label: "ip.sb（在线）"}
	wg.Add(2)
	go func() {
		defer wg.Done()
		ptr = s.reverseDNS(ctx, target)
	}()
	go func() {
		defer wg.Done()
		if record := s.onlineDB().Lookup(ctx, target); record != nil {
			online.Available = true
			online.Record = record
		} else {
			online.Error = "在线查询未返回结果"
		}
	}()
	wg.Wait()
	sources = append(sources, online)

	writeJSON(w, 200, map[string]any{
		"ip":           target,
		"version":      map[bool]int{true: 4, false: 6}[addr.Is4()],
		"sources":      sources,
		"divergences":  divergences(sources),
		"routing":      s.routingFacts(target),
		"reverse_dns":  ptr,
		"geoip_status": s.geoipStatus(),
		"freshness":    s.databaseFreshness(),
	})
}
