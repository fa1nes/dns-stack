package panel

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/geoip"
)

func readRows(rows *sql.Rows) ([]map[string]any, error) {
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	for rows.Next() {
		values, targets := make([]any, len(columns)), make([]any, len(columns))
		for index := range values {
			targets[index] = &values[index]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for index, column := range columns {
			item[column] = values[index]
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func dnsProbe(ctx context.Context, name, qtype, server, subnet string) map[string]any {
	args := map[string]any{"domain": name, "qtype": qtype, "server": server}
	if subnet != "" {
		args["subnet"] = subnet
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	response, err := helperCall(ctx, "dns_test", args)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	data := helperData(response)
	if !boolValue(response["ok"]) || numberValue(data["returncode"]) != 0 {
		message, _ := response["message"].(string)
		if message == "" {
			message = "查询失败"
		}
		return map[string]any{"error": message}
	}
	stdout, _ := data["stdout"].(string)
	parsed := parseDig(stdout)
	if parsed["status"] != "NOERROR" {
		return parsed
	}
	records, _ := parsed["records"].([]map[string]any)
	owner := name
	visited := map[string]bool{}
	for depth := 0; depth < 32; depth++ {
		if visited[owner] {
			parsed["records"] = []map[string]any{}
			parsed["error"] = "CNAME 环路"
			return parsed
		}
		visited[owner] = true
		next := ""
		for _, record := range records {
			recordOwner, _ := record["name"].(string)
			if domain.Normalize(recordOwner) == owner && record["type"] == "CNAME" {
				value, _ := record["value"].(string)
				next = domain.Normalize(value)
				if !validDNSName(next) {
					next = ""
				}
				break
			}
		}
		if next == "" {
			break
		}
		owner = next
	}
	filtered := []map[string]any{}
	for _, record := range records {
		recordOwner, _ := record["name"].(string)
		if record["class"] != "IN" {
			continue
		}
		if record["type"] == "A" || record["type"] == "AAAA" {
			if domain.Normalize(recordOwner) != owner {
				continue
			}
		} else if !visited[domain.Normalize(recordOwner)] {
			continue
		}
		filtered = append(filtered, record)
	}
	parsed["records"] = filtered
	return parsed
}

func liveResolve(ctx context.Context, name, subnet string) map[string]any {
	type result struct {
		server, qtype string
		value         map[string]any
	}
	channel := make(chan result, 6)
	var workers sync.WaitGroup
	for _, server := range []string{"local-unbound", "foreign-hk"} {
		for _, qtype := range []string{"A", "AAAA", "CNAME"} {
			workers.Add(1)
			go func() {
				defer workers.Done()
				channel <- result{server, qtype, dnsProbe(ctx, name, qtype, server, subnet)}
			}()
		}
	}
	workers.Wait()
	close(channel)
	out := map[string]any{"local-unbound": map[string]any{}, "foreign-hk": map[string]any{}}
	for item := range channel {
		out[item.server].(map[string]any)[item.qtype] = item.value
	}
	return out
}

func loadedPrefixes(path string) []netip.Prefix {
	prefixes := []netip.Prefix{}
	for _, value := range dataLines(path) {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix == prefix.Masked() {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func prefixContains(prefixes []netip.Prefix, value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func newPanelGeoDB(s *Server) *geoip.GeoDB {
	return geoip.NewGeoDB(s.statePath("geoip/GeoLite2-ASN.mmdb"), s.statePath("geoip/GeoLite2-City.mmdb"), s.statePath("geoip/qqwry.ipdb"))
}

func (s *Server) geoLookup(ip string) map[string]any {
	if ip == "" {
		return nil
	}
	s.geoMu.Lock()
	defer s.geoMu.Unlock()
	if s.geo == nil {
		s.geo = newPanelGeoDB(s)
	}
	return s.geo.Lookup(ip).JSON()
}

func (s *Server) geoLookupOnline(ctx context.Context, ip string) map[string]any {
	local := s.geoLookup(ip)
	if local == nil {
		local = map[string]any{"ip": ip}
	}
	if label, _ := local["label"].(string); label != "" {
		return local
	}
	country, _ := local["country"].(string)
	org, _ := local["as_org"].(string)
	if country != "" && org != "" {
		return local
	}
	s.geoMu.Lock()
	if s.geoOnline == nil {
		s.geoOnline = geoip.NewOnlineLookup()
	}
	online := s.geoOnline
	s.geoMu.Unlock()
	rec := online.Lookup(ctx, ip)
	if rec == nil {
		return local
	}
	for _, key := range []string{"country", "region", "city", "asn", "as_org", "label"} {
		if v, ok := rec[key]; ok && v != nil && v != "" {
			if cur, _ := local[key].(string); cur == "" {
				local[key] = v
			}
		}
	}
	src, _ := local["source"].(string)
	if src == "" {
		local["source"] = "ipsb"
	} else if !strings.Contains(src, "ipsb") {
		local["source"] = src + "+ipsb"
	}
	local["available"] = true
	return local
}

func (s *Server) detailInfo(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/domain/")), "."))
	if !validDNSName(name) {
		writeJSON(w, 400, map[string]any{"detail": "不是合法 DNS 名"})
		return
	}
	out := map[string]any{"domain": name}
	if db, err := s.openDB(); err == nil {
		defer db.Close()
		if rows, err := db.QueryContext(r.Context(), "SELECT * FROM domains WHERE domain = ?", name); err == nil {
			if items, err := readRows(rows); err == nil && len(items) > 0 {
				aggregate := items[0]
				aggregate["last_rcode_name"] = aggregate["last_rcode"]
				if aggregate["last_rcode"] != nil {
					aggregate["last_rcode_name"] = rcodeName(numberValue(aggregate["last_rcode"]))
				}
				aggregate["last_route_name"] = aggregate["last_route"]
				if route, ok := aggregate["last_route"].(string); ok {
					aggregate["last_route_name"] = routeName(route)
				}
				out["aggregate"] = aggregate
			}
		}
		if rows, err := db.QueryContext(r.Context(), "SELECT * FROM query_events WHERE domain = ? ORDER BY id DESC LIMIT 10", name); err == nil {
			if items, err := readRows(rows); err == nil {
				for _, item := range items {
					item["qtype_name"] = qtypeName(numberValue(item["qtype"]))
					item["rcode_name"] = rcodeName(numberValue(item["rcode"]))
					item["route_name"] = item["route"]
					if route, ok := item["route"].(string); ok {
						item["route_name"] = routeName(route)
					}
					item["cache_hit"] = item["resp_by"] == "cache"
				}
				out["recent"] = items
			}
		}
		if rows, err := db.QueryContext(r.Context(), "SELECT COALESCE(NULLIF(resp_by,''),'(无)') AS resp_by, COUNT(*) AS count FROM query_events WHERE domain = ? GROUP BY resp_by ORDER BY count DESC", name); err == nil {
			if items, err := readRows(rows); err == nil {
				out["by_upstream"] = items
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	subnet := clientSubnet(r)

	wantLive := r.URL.Query().Get("live") == "true" || r.URL.Query().Get("live") == "1"
	routing, live := s.routingInfo(ctx, name, subnet, wantLive)
	out["routing"] = routing
	if wantLive {
		out["live"] = live
	}
	writeJSON(w, 200, out)
}

func (s *Server) routingInfo(ctx context.Context, name, subnet string, wantLive bool) (map[string]any, map[string]any) {
	direct := loadedPrefixes(s.statePath("chnroute/direct4.txt"))
	authority := loadedPrefixes(s.statePath("chnroute/cn-authority.txt"))
	routing := map[string]any{"manual_rule": nil, "direction": "adaptive", "zone": nil, "reason": "各级权威尚未观测到大陆 IP，按每跳权威的 IP 归属分流"}
	for _, file := range []string{"manual-exclude.txt", "manual-gfw.txt"} {
		for _, rule := range dataLines(s.statePath(file)) {
			rule = strings.ToLower(rule)
			if name == rule || strings.HasSuffix(name, "."+rule) {
				routing["manual_rule"] = file
				break
			}
		}
		if routing["manual_rule"] != nil {
			break
		}
	}

	psl, _ := domain.LoadPSL(nil)
	labels := strings.Split(name, ".")
	zone := ""
	if psl != nil {
		for index := len(labels) - 2; index >= 0; index-- {
			candidate := strings.Join(labels[index:], ".")
			if domain.ZoneDefect(candidate, psl) == "" {
				zone = candidate
				break
			}
		}
	}
	routing["zone_queried"] = zone
	authorities := []map[string]any{}
	hasDomesticAuthority := false
	if zone != "" {
		nsReply := dnsProbe(ctx, zone, "NS", "local-unbound", "")
		records, _ := nsReply["records"].([]map[string]any)
		for _, record := range records {
			owner, _ := record["name"].(string)
			if record["type"] != "NS" || domain.Normalize(owner) != zone {
				continue
			}
			value, _ := record["value"].(string)
			ns := domain.Normalize(value)
			if !validDNSName(ns) {
				continue
			}
			for _, qtype := range []string{"A", "AAAA"} {
				for _, ip := range parsedGlobalIPs(dnsProbe(ctx, ns, qtype, "local-unbound", "")) {
					inCN := prefixContains(direct, ip)
					inAuthority := prefixContains(authority, ip)
					exit := "tunnel"
					if inCN || inAuthority {
						exit = "direct"
					}
					authorities = append(authorities, map[string]any{"ns": ns, "ip": ip, "in_cn": inCN, "in_cn_authority": inAuthority, "geo": s.geoLookup(ip), "exit": exit})
					hasDomesticAuthority = hasDomesticAuthority || inCN
				}
			}
			if len(authorities) >= 16 {
				break
			}
		}
	}
	routing["authorities"] = authorities
	routing["exits"] = s.exitAddresses(ctx)
	routing["geoip_status"] = s.geoipStatus()

	var live map[string]any
	finalIPs := []string{}
	if wantLive {
		live = liveResolve(ctx, name, subnet)
		local := live["local-unbound"].(map[string]any)
		for _, qtype := range []string{"A", "AAAA"} {
			parsed := local[qtype].(map[string]any)
			finalIPs = append(finalIPs, parsedGlobalIPs(parsed)...)
			if parsed["ecs"] != nil {
				routing["ecs"] = parsed["ecs"]
			}
		}
		if len(finalIPs) > 0 {
			routing["result_ip"] = finalIPs[0]
			routing["result_in_cn"] = prefixContains(direct, finalIPs[0])
			routing["result_geo"] = s.geoLookup(finalIPs[0])
		}
		routing["viewer_subnet"] = nil
		if subnet != "" {
			routing["viewer_subnet"] = subnet
		}
	}
	if hasDomesticAuthority {
		routing["direction"], routing["zone"] = "direct", zone
		routing["reason"] = zone + " 的实时权威含 direct4 地址"
	}
	if routing["manual_rule"] == "manual-gfw.txt" {
		routing["direction"], routing["zone"], routing["reason"] = "hongkong", nil, "人工规则强制走香港递归器"
	}
	return routing, live
}
