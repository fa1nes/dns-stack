package panel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

func (s *Server) dnsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		Domain  string   `json:"domain"`
		QType   string   `json:"qtype"`
		Server  string   `json:"server"`
		Servers []string `json:"servers"`
		Subnet  string   `json:"subnet"`
	}
	if json.NewDecoder(r.Body).Decode(&p) != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, 400, map[string]any{"detail": "请输入要测试的域名"})
		return
	}
	p.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if !validDNSName(p.Domain) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不是合法 DNS 名"})
		return
	}
	p.QType = strings.ToUpper(strings.TrimSpace(p.QType))
	if p.QType == "" {
		p.QType = "A"
	}
	if !dnsTestQTypes[p.QType] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的查询类型"})
		return
	}
	if strings.TrimSpace(p.Subnet) == "" {
		p.Subnet = clientSubnet(r)
	} else if !validClientSubnet(p.Subnet) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "客户端子网必须是规范的全局 IPv4 /24 网段"})
		return
	}
	servers := p.Servers
	if len(servers) == 0 {
		if strings.TrimSpace(p.Server) != "" {
			servers = []string{strings.TrimSpace(p.Server)}
		} else {
			servers = []string{"local-unbound", "foreign-hk"}
		}
	}
	for _, server := range servers {
		if !dnsTestServers[server] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的测试目标"})
			return
		}
	}
	results := map[string]any{}
	type probeResult struct {
		server string
		parsed map[string]any
	}
	ch := make(chan probeResult, len(servers))
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			started := time.Now()
			parsed := dnsProbe(r.Context(), p.Domain, p.QType, server, strings.TrimSpace(p.Subnet))
			parsed["panel_elapsed_ms"] = time.Since(started).Milliseconds()
			ch <- probeResult{server: server, parsed: parsed}
		}(server)
	}
	wg.Wait()
	close(ch)
	for probe := range ch {
		if geoList := s.probeIPsGeo(r.Context(), probe.parsed); len(geoList) > 0 {
			probe.parsed["ips_geo"] = geoList
		}
		results[probe.server] = probe.parsed
	}

	routing, _ := s.routingInfo(r.Context(), p.Domain, strings.TrimSpace(p.Subnet), false)
	if p.Subnet != "" {
		routing["viewer_subnet"] = p.Subnet
	}
	if local, ok := results["local-unbound"].(map[string]any); ok {
		if ecs, ok := local["ecs"]; ok && ecs != nil {
			routing["ecs"] = ecs
		}

		var ips []string
		records, _ := local["records"].([]map[string]any)
		for _, record := range records {
			if record["type"] != "A" && record["type"] != "AAAA" {
				continue
			}
			if value, _ := record["value"].(string); value != "" {
				ips = append(ips, value)
			}
		}
		s.resultGeoFields(routing, ips)
	}
	writeJSON(w, 200, map[string]any{"domain": p.Domain, "qtype": p.QType, "results": results, "routing": routing})
}

var dnsTestServers = map[string]bool{
	"local-unbound": true,
	"foreign-hk":    true,
	"cn-unbound":    true,
}

var dnsTestQTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "HTTPS": true, "SVCB": true, "PTR": true,
}

func validClientSubnet(raw string) bool {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || ip.To4() == nil || !isPublicIP(ip) {
		return false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 24 || !ip.Equal(ip.Mask(network.Mask)) {
		return false
	}
	last := append(net.IP(nil), ip.To4()...)
	last[3] = 255
	return isPublicIP(last)
}

func (s *Server) probeIPsGeo(ctx context.Context, parsed map[string]any) []map[string]any {
	ips := parsedGlobalIPs(parsed)
	if len(ips) == 0 {
		return nil
	}
	limit := len(ips)
	if limit > 16 {
		limit = 16
	}
	type item struct {
		ip  string
		geo map[string]any
	}
	ch := make(chan item, limit)
	var wg sync.WaitGroup
	for _, ip := range ips[:limit] {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ch <- item{ip: ip, geo: s.geoLookupOnline(ctx, ip)}
		}(ip)
	}
	wg.Wait()
	close(ch)
	found := map[string]map[string]any{}
	for it := range ch {
		found[it.ip] = it.geo
	}
	out := make([]map[string]any, 0, limit)
	for _, ip := range ips[:limit] {
		out = append(out, map[string]any{"ip": ip, "geo": found[ip]})
	}
	return out
}

func parsedGlobalIPs(parsed map[string]any) []string {
	if parsed["error"] != nil || (parsed["status"] != nil && parsed["status"] != "NOERROR") {
		return nil
	}
	raw, ok := parsed["records"].([]map[string]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	ips := make([]string, 0, len(raw))
	for _, record := range raw {
		typ, _ := record["type"].(string)
		if typ != "A" && typ != "AAAA" {
			continue
		}
		value, _ := record["value"].(string)
		ip := net.ParseIP(value)
		if ip == nil || !isPublicIP(ip) || (typ == "A") != (ip.To4() != nil) || seen[value] {
			continue
		}
		seen[value] = true
		ips = append(ips, value)
	}
	return ips
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	address, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.Is4() || netip.MustParsePrefix("2000::/3").Contains(address)
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func compareDNSViews(results map[string]any) string {
	local, localOK := results["local-unbound"].(map[string]any)
	hk, hkOK := results["foreign-hk"].(map[string]any)
	if !localOK || !hkOK {
		return "incomplete"
	}
	localIPs := parsedGlobalIPs(local)
	hkIPs := parsedGlobalIPs(hk)
	if len(localIPs) == 0 || len(hkIPs) == 0 {
		return "no_final_global_address"
	}
	if sameStringSet(localIPs, hkIPs) {
		return "consistent"
	}
	return "geo_split"
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, value := range a {
		seen[value] = true
	}
	for _, value := range b {
		if !seen[value] {
			return false
		}
	}
	return true
}

func (s *Server) myLocation(w http.ResponseWriter, r *http.Request) {

	ip := clientIP(r)

	out := map[string]any{"client_ip": ip, "geo": s.geoLookup(ip)}
	subnet := clientSubnet(r)
	if subnet == "" {
		out["error"] = "只支持全局 IPv4 客户端"
		writeJSON(w, 200, out)
		return
	}
	out["ecs"] = subnet
	probes := [][2]string{{"淘宝", "www.taobao.com"}, {"京东", "www.jd.com"}, {"百度", "www.baidu.com"}, {"腾讯", "www.qq.com"}, {"抖音", "www.douyin.com"}, {"哔哩哔哩", "www.bilibili.com"}, {"微信", "res.wx.qq.com"}, {"网易", "www.163.com"}}
	type result struct {
		idx   int
		value map[string]any
	}
	ch := make(chan result, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(i int, name, domain string) {
			defer wg.Done()
			item := map[string]any{"name": name, "domain": domain}
			resp, err := helperCall(r.Context(), "dns_test", map[string]any{"domain": domain, "qtype": "A", "server": "local-unbound", "subnet": subnet})
			if err != nil {
				item["error"] = err.Error()
				ch <- result{i, item}
				return
			}

			data := helperData(resp)
			if !boolValue(resp["ok"]) || numberValue(data["returncode"]) != 0 {
				message, _ := resp["message"].(string)
				if message == "" {
					message = "查询失败"
				}
				item["error"] = message
				ch <- result{i, item}
				return
			}
			stdout, _ := data["stdout"].(string)
			parsed := parseDig(stdout)
			var ip string
			for _, raw := range parsed["records"].([]map[string]any) {
				if raw["type"] == "A" {
					ip, _ = raw["value"].(string)
					break
				}
			}

			item["ip"] = nil
			if ip != "" {
				item["ip"] = ip
			}
			item["geo"] = s.geoLookup(ip)
			item["ecs"] = parsed["ecs"]
			ch <- result{i, item}
		}(i, probe[0], probe[1])
	}
	wg.Wait()
	close(ch)
	nodes := make([]any, len(probes))
	for item := range ch {
		nodes[item.idx] = item.value
	}
	out["nodes"] = nodes
	writeJSON(w, 200, out)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func clientSubnet(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !isPublicIP(ip) {
		return ""
	}
	parts := strings.Split(host, ".")
	return strings.Join(parts[:3], ".") + ".0/24"
}

func parseDig(text string) map[string]any {
	out := map[string]any{"records": []any{}, "status": nil, "query_time_ms": nil, "ecs": nil}
	inAnswer := false
	records := []map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";; ->>HEADER<<-") {
			if i := strings.Index(line, "status:"); i >= 0 {
				v := strings.TrimSpace(strings.SplitN(line[i+7:], ",", 2)[0])
				out["status"] = v
			}
		} else if line == ";; ANSWER SECTION:" {
			inAnswer = true
		} else if strings.HasPrefix(line, ";;") {
			inAnswer = false
			if i := strings.Index(line, "Query time:"); i >= 0 {
				fields := strings.Fields(line[i+len("Query time:"):])
				if len(fields) > 0 {
					out["query_time_ms"] = parseInt(fields[0], 0)
				}
			}
		} else if strings.HasPrefix(line, "; CLIENT-SUBNET:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "; CLIENT-SUBNET:"))
			parts := strings.Split(v, "/")
			if len(parts) >= 3 {
				source := parseInt(parts[len(parts)-2], 0)
				scope := parseInt(parts[len(parts)-1], 0)
				out["ecs"] = map[string]any{"subnet": strings.Join(parts[:len(parts)-2], "/") + "/" + strconv.Itoa(source), "source": source, "scope": scope, "honored": scope > 0}
			}
		} else if inAnswer && line != "" && !strings.HasPrefix(line, ";") {
			f := strings.Fields(line)
			if len(f) >= 5 {
				if (f[3] == "A" || f[3] == "AAAA") && (!isPublicIP(net.ParseIP(f[4])) || (f[3] == "A") != (net.ParseIP(f[4]).To4() != nil)) {
					continue
				}
				records = append(records, map[string]any{"name": f[0], "ttl": parseInt(f[1], 0), "class": f[2], "type": f[3], "value": strings.Join(f[4:], " ")})
			}
		}
	}
	out["records"] = records
	return out
}
