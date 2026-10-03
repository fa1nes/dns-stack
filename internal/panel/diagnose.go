package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

func autoQuery(input, qtype string) (string, []string) {
	if addr, err := netip.ParseAddr(input); err == nil {
		if name, err := reverseName(addr.Unmap()); err == nil {
			return name, []string{"PTR"}
		}
	}
	if qtype != "" && qtype != "AUTO" {
		return input, []string{qtype}
	}
	switch {
	case strings.HasPrefix(input, "_") && (strings.Contains(input, "._tcp.") || strings.Contains(input, "._udp.")):
		return input, []string{"SRV"}
	case strings.HasPrefix(input, "_"):
		return input, []string{"TXT"}
	}
	return input, []string{"A", "AAAA"}
}

func mergeProbes(parts []map[string]any) map[string]any {
	if len(parts) == 1 {
		return parts[0]
	}
	out := map[string]any{"records": []map[string]any{}, "status": nil, "query_time_ms": nil, "ecs": nil}
	seen := map[string]bool{}
	records := []map[string]any{}
	slowest := -1
	for _, part := range parts {
		if status, _ := part["status"].(string); status != "" && (out["status"] == nil || status == "NOERROR") {
			out["status"] = status
		}
		if part["error"] != nil && out["error"] == nil {
			out["error"] = part["error"]
		}
		if out["ecs"] == nil {
			out["ecs"] = part["ecs"]
		}
		if ms, ok := part["query_time_ms"].(int); ok && ms > slowest {
			slowest = ms
			out["query_time_ms"] = ms
		}
		list, _ := part["records"].([]map[string]any)
		for _, record := range list {
			key := fmt.Sprint(record["type"], record["name"], record["value"])
			if !seen[key] {
				seen[key] = true
				records = append(records, record)
			}
		}
	}
	if out["status"] != nil {
		delete(out, "error")
	}
	out["records"] = records
	return out
}

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
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&p) != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, 400, map[string]any{"detail": "请输入要测试的域名或 IP"})
		return
	}
	input := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	qtype := strings.ToUpper(strings.TrimSpace(p.QType))
	if qtype != "" && qtype != "AUTO" && !dnsTestQTypes[qtype] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的查询类型"})
		return
	}
	name, qtypes := autoQuery(input, qtype)
	if !validDNSName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不是合法的域名或 IP"})
		return
	}
	if strings.TrimSpace(p.Subnet) == "" {
		p.Subnet = clientSubnet(r)
	} else if !validClientSubnet(p.Subnet) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "子网要写成 a.b.c.0/24，且必须是公网地址"})
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
	unique := servers[:0:0]
	for _, server := range servers {
		if !dnsTestServers[server] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的测试目标"})
			return
		}
		if !slices.Contains(unique, server) {
			unique = append(unique, server)
		}
	}
	servers = unique
	subnet := strings.TrimSpace(p.Subnet)
	results := map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			started := time.Now()
			parts := make([]map[string]any, len(qtypes))
			var inner sync.WaitGroup
			for i, qt := range qtypes {
				inner.Add(1)
				go func(i int, qt string) {
					defer inner.Done()
					parts[i] = dnsProbe(r.Context(), name, qt, server, subnet)
				}(i, qt)
			}
			inner.Wait()
			parsed := mergeProbes(parts)
			parsed["panel_elapsed_ms"] = time.Since(started).Milliseconds()
			if geoList := s.probeIPsGeo(r.Context(), parsed); len(geoList) > 0 {
				parsed["ips_geo"] = geoList
			}
			mu.Lock()
			results[server] = parsed
			mu.Unlock()
		}(server)
	}
	wg.Wait()

	out := map[string]any{"domain": name, "input": input, "qtypes": qtypes, "results": results, "routing": nil}
	if qtypes[0] != "PTR" {
		routing, _ := s.routingInfo(r.Context(), name, subnet, false)
		if p.Subnet != "" {
			routing["viewer_subnet"] = p.Subnet
		}
		if local, ok := results["local-unbound"].(map[string]any); ok {
			if ecs, ok := local["ecs"]; ok && ecs != nil {
				routing["ecs"] = ecs
			}
			s.resultGeoFields(routing, parsedGlobalIPs(local))
		}
		out["routing"] = routing
	}
	writeJSON(w, 200, out)
}

var dnsTestServers = map[string]bool{
	"local-unbound": true,
	"foreign-hk":    true,
	"cn-unbound":    true,
}

var dnsTestQTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "HTTPS": true, "SVCB": true, "PTR": true, "SRV": true,
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
	direct := loadedPrefixes(s.statePath("chnroute/direct4.txt"))
	out := make([]map[string]any, 0, limit)
	for _, ip := range ips[:limit] {
		out = append(out, map[string]any{"ip": ip, "in_cn": prefixContains(direct, ip), "geo": found[ip]})
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

func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && ipset.IsGlobalAddr(addr.Unmap())
}
