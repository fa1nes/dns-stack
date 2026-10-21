package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/ecszone"
	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/resolve"
	"github.com/dns-stack/dns-stack/internal/stack"
)

type precisionVantage struct {
	Zone     string `json:"zone"`
	Subnet   string `json:"subnet"`
	Queries  int    `json:"client_queries"`
	Province string `json:"-"`
	Carrier  string `json:"-"`
}

type precisionAnswer struct {
	Addrs    []string `json:"addrs"`
	Scope    int      `json:"scope"`
	Echo     bool     `json:"echo"`
	Carriers []string `json:"carriers"`
	Places   []string `json:"provinces"`
	Domestic bool     `json:"domestic"`
}

type precisionDomain struct {
	Domain   string                     `json:"domain"`
	Queries  int                        `json:"queries"`
	Steered  bool                       `json:"steered"`
	ByZone   map[string]precisionAnswer `json:"by_zone"`
	Mismatch []string                   `json:"carrier_mismatch,omitempty"`
}

type precisionZoneStats struct {
	Zone           string `json:"zone"`
	Resolved       int    `json:"resolved"`
	Domestic       int    `json:"domestic"`
	Carrier        int    `json:"carrier_match"`
	Province       int    `json:"province_match"`
	SteeredTotal   int    `json:"steered_total"`
	SteeredCarrier int    `json:"steered_carrier_match"`
	WeightTotal    int    `json:"weighted_total"`
	WeightCarrier  int    `json:"weighted_carrier_match"`
}

func cmdECSPrecision(args []string) error {
	fs := flag.NewFlagSet("ecs-precision", flag.ContinueOnError)
	state := fs.String("state", envOr("DNS_STACK_STATE", "/var/lib/dns-stack"), "状态目录")
	dbPath := fs.String("db", envOr("DNS_STACK_DB", ""), "collector SQLite 路径(默认 <state>/collector.db)")
	ipdbPath := fs.String("ipdb", "", "qqwry.ipdb 路径(默认 <state>/geoip/qqwry.ipdb)")
	resolver := fs.String("resolver", stack.LocalUnbound, "递归解析器地址")
	hours := fs.Int("hours", 168, "统计最近多少小时的客户端查询")
	top := fs.Int("top", 150, "重放查询量最高的多少个 A 记录域名")
	maxZones := fs.Int("zones", 6, "最多取多少个客户端分片作为观测点")
	asJSON := fs.Bool("json", false, "输出 JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		*dbPath = filepath.Join(*state, "collector.db")
	}
	if *ipdbPath == "" {
		*ipdbPath = filepath.Join(*state, "geoip", "qqwry.ipdb")
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(*dbPath)+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	since := time.Now().Add(-time.Duration(*hours) * time.Hour).Unix()

	family, zones, err := precisionClientZones(db, since)
	if err != nil {
		return fmt.Errorf("读不到客户端分片: %w", err)
	}
	domains, err := precisionTopDomains(db, since, *top)
	if err != nil {
		return fmt.Errorf("读不到热门域名: %w", err)
	}
	rows, err := ecszone.LoadRows(filepath.Join(*state, "ecs-ip-zone.txt"))
	if err != nil {
		return fmt.Errorf("读不到 ECS 分片表: %w", err)
	}
	vantages := precisionVantages(zones, rows, loadFanoutSubnets(filepath.Join(*state, "ecs-fanout.txt")), *maxZones)
	if len(vantages) == 0 {
		return fmt.Errorf("没有带省份和运营商的客户端分片，无从比较")
	}

	reader, err := geoip.OpenIPDB(*ipdbPath)
	if err != nil {
		return fmt.Errorf("打不开归属库: %w", err)
	}
	defer reader.Close()
	host, port, err := splitHostPort(*resolver)
	if err != nil {
		return err
	}
	client, err := resolve.NewClient(host, port, 8*time.Second)
	if err != nil {
		return err
	}

	results := precisionReplay(client, reader, domains, vantages)
	stats := precisionSummarize(results, vantages)

	if *asJSON {
		return writeCompactJSON(map[string]any{
			"hours": *hours, "client_family": family, "client_zones": zones,
			"vantages": vantages, "zones": stats, "domains": results,
		})
	}
	fmt.Printf("[信息] 最近 %d 小时客户端查询来源: IPv4 %d, IPv6 %d, 无子网 %d\n",
		*hours, family["v4"], family["v6"], family["none"])
	fmt.Println("[信息] 客户端分片(查询数):")
	for _, z := range zones {
		label := z.Zone
		if label == "" {
			label = "(未打标)"
		}
		fmt.Printf("  %-12s %-20s %d\n", label, z.Subnet, z.Queries)
	}
	steered := 0
	for _, r := range results {
		if r.Steered {
			steered++
		}
	}
	fmt.Printf("[信息] 重放 %d 个域名，其中 %d 个按子网给了不同答案(有调度)\n", len(results), steered)
	fmt.Println("  观测点         解析  国内  同运营商  同省  | 有调度的同运营商 | 按查询量加权同运营商")
	for _, s := range stats {
		fmt.Printf("  %-12s %5d %5d %8s %5s  | %16s | %s\n", s.Zone, s.Resolved, s.Domestic,
			percent(s.Carrier, s.Resolved), percent(s.Province, s.Resolved),
			percent(s.SteeredCarrier, s.SteeredTotal), percent(s.WeightCarrier, s.WeightTotal))
	}
	fmt.Println("[信息] 运营商对不上的域名(有其他观测点拿到对口运营商才算):")
	for _, r := range results {
		if len(r.Mismatch) == 0 {
			continue
		}
		fmt.Printf("  %-36s %5d 次  %s\n", r.Domain, r.Queries, strings.Join(r.Mismatch, "; "))
	}
	return nil
}

func percent(n, d int) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", float64(n)*100/float64(d))
}

func splitHostPort(addr string) (string, int, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("解析器地址 %q 不是 IP:端口", addr)
	}
	return ap.Addr().String(), int(ap.Port()), nil
}

func precisionClientZones(db *sql.DB, since int64) (map[string]int, []precisionVantage, error) {
	rs, err := db.Query(`SELECT COALESCE(ecs_zone,''), COALESCE(client_subnet,''), COUNT(*)
		FROM query_events WHERE ts >= ? AND prefetch = 0 GROUP BY 1, 2`, since)
	if err != nil {
		return nil, nil, err
	}
	defer rs.Close()
	family := map[string]int{"v4": 0, "v6": 0, "none": 0}
	type agg struct {
		total      int
		subnet     string
		subnetHits int
	}
	byZone := map[string]*agg{}
	for rs.Next() {
		var zone, subnet string
		var n int
		if err := rs.Scan(&zone, &subnet, &n); err != nil {
			return nil, nil, err
		}
		prefix, perr := netip.ParsePrefix(subnet)
		switch {
		case perr != nil:
			family["none"] += n
			continue
		case prefix.Addr().Is4():
			family["v4"] += n
		default:
			family["v6"] += n
		}
		a := byZone[zone]
		if a == nil {
			a = &agg{}
			byZone[zone] = a
		}
		a.total += n
		if prefix.Addr().Is4() && n > a.subnetHits {
			a.subnet, a.subnetHits = subnet, n
		}
	}
	if err := rs.Err(); err != nil {
		return nil, nil, err
	}
	var out []precisionVantage
	for zone, a := range byZone {
		province, carrier := ecszone.SplitZone(zone)
		out = append(out, precisionVantage{Zone: zone, Subnet: a.subnet, Queries: a.total,
			Province: province, Carrier: carrier})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Queries > out[j].Queries })
	return family, out, nil
}

func precisionTopDomains(db *sql.DB, since int64, limit int) ([]precisionDomain, error) {
	rs, err := db.Query(`SELECT domain, COUNT(*) FROM query_events
		WHERE ts >= ? AND prefetch = 0 AND qtype = 1 AND rcode = 0
		GROUP BY domain ORDER BY 2 DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []precisionDomain
	for rs.Next() {
		var d precisionDomain
		if err := rs.Scan(&d.Domain, &d.Queries); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rs.Err()
}

func loadFanoutSubnets(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		zone, subnet, ok := strings.Cut(line, ",")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := netip.ParsePrefix(subnet); err == nil {
			out[zone] = subnet
		}
	}
	return out
}

func precisionVantages(zones []precisionVantage, rows []ecszone.Row, known map[string]string, limit int) []precisionVantage {
	var out []precisionVantage
	seen := map[string]bool{}
	for _, z := range zones {
		if len(out) >= limit {
			break
		}
		if z.Province == "" || z.Carrier == "" || z.Subnet == "" {
			continue
		}
		out = append(out, z)
		seen[z.Zone] = true
	}
	if len(out) == 0 {
		return nil
	}
	for _, zone := range sortedKeys(known) {
		subnet := known[zone]
		province, carrier := ecszone.SplitZone(zone)
		if !seen[zone] && province != "" && carrier != "" {
			out = append(out, precisionVantage{Zone: zone, Subnet: subnet, Province: province, Carrier: carrier})
			seen[zone] = true
		}
	}
	province := out[0].Province
	for _, carrier := range []string{"电信", "联通", "移动"} {
		zone := province + carrier
		if seen[zone] {
			continue
		}
		subnet := known[zone]
		if subnet == "" {
			subnet = zoneSampleSubnet(rows, zone)
		}
		if subnet != "" {
			out = append(out, precisionVantage{Zone: zone, Subnet: subnet, Province: province, Carrier: carrier})
			seen[zone] = true
		}
	}
	return out
}

func zoneSampleSubnet(rows []ecszone.Row, zone string) string {
	best := -1
	for i, row := range rows {
		if row.Zone == zone && row.Hi-row.Lo >= 255 && (best < 0 || row.Hi-row.Lo > rows[best].Hi-rows[best].Lo) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	r := rows[best]
	base := (r.Lo + (r.Hi-r.Lo)/2) &^ 0xff
	if base < r.Lo {
		base = (r.Lo + 255) &^ 0xff
	}
	return cidrutil.FormatAddr4(base) + "/24"
}

func precisionReplay(client *resolve.Client, reader *geoip.IPDBReader, domains []precisionDomain, vantages []precisionVantage) []precisionDomain {
	type job struct{ d, v int }
	jobs := make(chan job)
	answers := make([][]precisionAnswer, len(domains))
	for i := range answers {
		answers[i] = make([]precisionAnswer, len(vantages))
	}
	var lookup sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				subnet := netip.MustParsePrefix(vantages[j.v].Subnet)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				ans := client.QueryWithSubnet(ctx, domains[j.d].Domain, dnswire.TypeA, subnet)
				cancel()
				if ans.Msg == nil {
					continue
				}
				var pa precisionAnswer
				if cs, ok := ans.Msg.ClientSubnet(); ok {
					pa.Echo, pa.Scope = true, cs.Scope
				}
				carriers, places := map[string]bool{}, map[string]bool{}
				for _, rr := range ans.Msg.Answers {
					addr, ok := rr.A()
					if !ok {
						continue
					}
					pa.Addrs = append(pa.Addrs, addr.String())
					lookup.Lock()
					rec, _ := reader.Get(addr.String())
					lookup.Unlock()
					if rec["country_code"] == "CN" {
						pa.Domestic = true
					}
					if c := ecszone.CarrierOf(rec); c != "" {
						carriers[c] = true
					}
					if p := ecszone.ProvinceOf(rec); p != "" {
						places[p] = true
					}
				}
				sort.Strings(pa.Addrs)
				pa.Carriers, pa.Places = sortedSet(carriers), sortedSet(places)
				answers[j.d][j.v] = pa
			}
		}()
	}
	for d := range domains {
		for v := range vantages {
			jobs <- job{d, v}
		}
	}
	close(jobs)
	wg.Wait()

	for d := range domains {
		item := &domains[d]
		item.ByZone = map[string]precisionAnswer{}
		distinct := map[string]bool{}
		for v, pa := range answers[d] {
			if len(pa.Addrs) == 0 {
				continue
			}
			item.ByZone[vantages[v].Zone] = pa
			distinct[strings.Join(pa.Addrs, " ")] = true
		}
		item.Steered = len(distinct) > 1
		for v, pa := range answers[d] {
			if len(pa.Addrs) == 0 || !pa.Domestic || containsString(pa.Carriers, vantages[v].Carrier) {
				continue
			}
			for w, other := range answers[d] {
				if w != v && containsString(other.Carriers, vantages[w].Carrier) {
					item.Mismatch = append(item.Mismatch, fmt.Sprintf("%s→%s(scope %d)",
						vantages[v].Zone, strings.Join(pa.Carriers, "/"), pa.Scope))
					break
				}
			}
		}
	}
	return domains
}

func precisionSummarize(results []precisionDomain, vantages []precisionVantage) []precisionZoneStats {
	var out []precisionZoneStats
	for _, v := range vantages {
		s := precisionZoneStats{Zone: v.Zone}
		for _, r := range results {
			pa, ok := r.ByZone[v.Zone]
			if !ok {
				continue
			}
			s.Resolved++
			if !pa.Domestic {
				continue
			}
			s.Domestic++
			carrier := containsString(pa.Carriers, v.Carrier)
			if carrier {
				s.Carrier++
			}
			if containsString(pa.Places, v.Province) {
				s.Province++
			}
			if r.Steered {
				s.SteeredTotal++
				s.WeightTotal += r.Queries
				if carrier {
					s.SteeredCarrier++
					s.WeightCarrier += r.Queries
				}
			}
		}
		out = append(out, s)
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
