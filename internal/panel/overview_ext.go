package panel

import (
	"context"
	"database/sql"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var exitNames = map[string]string{
	"cache": "缓存命中", "direct": "直连出网", "tunnel": "经香港隧道",
	"hongkong": "香港递归器", "reject": "已拒绝", "unknown": "未知",
}

func exitName(path string) string {
	if name := exitNames[path]; name != "" {
		return name
	}
	return path
}

func (s *Server) archEpoch() int64 {
	raw, err := os.ReadFile(s.statePath("architecture-epoch"))
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

const latencySampleCap = 10000

const failWindowSec = 86400

const (
	resolveCap      = 60
	resolveTotalSec = 20
	resolveParallel = 8
)

func roundTo(value float64, digits int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return value
	}
	out, err := strconv.ParseFloat(strconv.FormatFloat(value, 'f', digits, 64), 64)
	if err != nil {
		return value
	}
	return out
}

type rateTracker struct {
	mu     sync.Mutex
	last   map[string]float64
	lastAt time.Time
	now    func() time.Time
}

func (t *rateTracker) update(counters map[string]float64) map[string]float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	clock := t.now
	if clock == nil {
		clock = time.Now
	}
	now := clock()
	rates := map[string]float64{}
	if !t.lastAt.IsZero() {
		elapsed := now.Sub(t.lastAt).Seconds()
		if elapsed >= 0.5 {
			for key, value := range counters {
				prev, ok := t.last[key]
				if ok && value >= prev {
					rates[key] = (value - prev) / elapsed
				} else {
					rates[key] = 0
				}
			}
		}
	}
	if t.lastAt.IsZero() || now.Sub(t.lastAt).Seconds() >= 0.5 {
		t.last = map[string]float64{}
		for key, value := range counters {
			t.last[key] = value
		}
		t.lastAt = now
	}
	return rates
}

func latencyStats(db *sql.DB, since int64) map[string]any {
	out := map[string]any{"samples": 0, "avg": nil}
	var samples sql.NullInt64
	var avg sql.NullFloat64
	err := db.QueryRow(
		"SELECT COUNT(*), AVG(elapsed_ms) FROM query_events "+
			"WHERE ts >= ? AND elapsed_ms IS NOT NULL", since).Scan(&samples, &avg)
	if err != nil {
		return out
	}
	total := samples.Int64
	out["samples"] = total
	if avg.Valid {
		out["avg"] = roundTo(avg.Float64, 2)
	}
	if total == 0 {
		return out
	}
	sampleN := total
	if sampleN > latencySampleCap {
		sampleN = latencySampleCap
	}
	for _, item := range []struct {
		label string
		q     int64
	}{{"p50", 50}, {"p95", 95}} {
		offset := sampleN*item.q/100 - 1
		if offset < 0 {
			offset = 0
		}
		var value sql.NullFloat64
		err := db.QueryRow(
			"SELECT elapsed_ms FROM ("+
				"  SELECT elapsed_ms FROM query_events "+
				"  WHERE ts >= ? AND elapsed_ms IS NOT NULL "+
				"  ORDER BY id DESC LIMIT ?"+
				") ORDER BY elapsed_ms LIMIT 1 OFFSET ?",
			since, sampleN, offset).Scan(&value)
		if err != nil || !value.Valid {
			out[item.label] = nil
			continue
		}
		out[item.label] = roundTo(value.Float64, 2)
	}
	out["sampled"] = sampleN < total
	var slow int64
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM query_events WHERE ts >= ? AND elapsed_ms >= 1000",
		since).Scan(&slow); err == nil {
		out["slow_1s"] = slow
	}
	return out
}

func (s *Server) routingServiceState(r *http.Request) map[string]bool {
	out := map[string]bool{}
	units := []string{"dns-stack-recursive-routing", "wg-quick@wg0"}
	for _, item := range s.serviceStatus(r, units) {
		entry, _ := item.(map[string]any)
		unit, _ := entry["unit"].(string)
		key := "tunnel_active"
		if strings.HasPrefix(unit, "dns-stack-recursive") {
			key = "chain_active"
		}
		out[key] = entry["active"] == "active"
	}
	return out
}

func domainSummaryExtras(db *sql.DB, out map[string]any, now, since int64) {

	byExit := []map[string]any{}
	if rows, err := db.Query(
		"SELECT exit_path, COUNT(*) FROM query_events "+
			"WHERE ts >= ? AND exit_path IS NOT NULL GROUP BY exit_path ORDER BY 2 DESC",
		since); err == nil {
		defer rows.Close()
		for rows.Next() {
			var path string
			var count int
			if rows.Scan(&path, &count) == nil {
				byExit = append(byExit, map[string]any{
					"path": path, "name": exitName(path), "count": count})
			}
		}
	}
	out["by_exit"] = byExit

	var new24, active1h, failing, failedEver int
	_ = db.QueryRow("SELECT COUNT(*) FROM domains WHERE first_seen_at >= ?", now-86400).Scan(&new24)
	_ = db.QueryRow("SELECT COUNT(*) FROM domains WHERE last_seen_at >= ?", now-3600).Scan(&active1h)

	_ = db.QueryRow(
		"SELECT COUNT(DISTINCT domain) FROM query_events WHERE rcode > 0 AND ts >= ?",
		now-failWindowSec).Scan(&failing)

	_ = db.QueryRow("SELECT COUNT(*) FROM domains WHERE COALESCE(fail_count,0) > 0").Scan(&failedEver)
	out["new_24h"] = new24
	out["active_1h"] = active1h
	out["failing"] = failing
	out["failed_ever"] = failedEver

	byQtype := []map[string]any{}
	if rows, err := db.Query(
		"SELECT qtype, COUNT(*) FROM query_events WHERE ts >= ? "+
			"GROUP BY qtype ORDER BY 2 DESC LIMIT 10", now-86400); err == nil {
		defer rows.Close()
		for rows.Next() {
			var qtype int64
			var count int
			if rows.Scan(&qtype, &count) == nil {
				byQtype = append(byQtype, map[string]any{
					"qtype": qtype, "name": qtypeName(qtype), "count": count})
			}
		}
	}
	out["by_qtype"] = byQtype

	byRcode := []map[string]any{}
	if rows, err := db.Query(
		"SELECT rcode, COUNT(*) FROM query_events WHERE ts >= ? "+
			"GROUP BY rcode ORDER BY 2 DESC LIMIT 10", now-86400); err == nil {
		defer rows.Close()
		for rows.Next() {
			var rcode int64
			var count int
			if rows.Scan(&rcode, &count) == nil {
				byRcode = append(byRcode, map[string]any{
					"rcode": rcode, "name": rcodeName(rcode), "count": count})
			}
		}
	}
	out["by_rcode"] = byRcode
}

func (s *Server) attachResolvedNode(ctx context.Context, items []map[string]any) {
	targets := make([]string, 0, resolveCap)
	for _, item := range items {
		name, _ := item["domain"].(string)
		if name == "" {
			continue
		}
		targets = append(targets, name)
		if len(targets) >= resolveCap {
			break
		}
	}
	if len(targets) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTotalSec*time.Second)
	defer cancel()
	var mu sync.Mutex
	found := map[string]map[string]any{}
	sem := make(chan struct{}, resolveParallel)
	var wg sync.WaitGroup
	for _, name := range targets {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			reply := dnsProbe(ctx, name, "A", "local-unbound", "")
			records, _ := reply["records"].([]map[string]any)
			for _, record := range records {
				if record["type"] != "A" {
					continue
				}
				ip, _ := record["value"].(string)
				if ip == "" {
					continue
				}
				mu.Lock()
				found[name] = map[string]any{"ip": ip, "geo": s.geoLookup(ip)}
				mu.Unlock()
				return
			}
		}(name)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for _, item := range items {
		name, _ := item["domain"].(string)
		if node, ok := found[name]; ok {
			item["node"] = node
		}
	}
}

func (s *Server) resultGeoFields(routing map[string]any, ips []string) {
	if len(ips) == 0 {
		return
	}
	direct := loadedPrefixes(s.statePath("chnroute/direct4.txt"))
	routing["result_ip"] = ips[0]
	routing["result_in_cn"] = prefixContains(direct, ips[0])
	routing["result_geo"] = s.geoLookup(ips[0])
	if len(ips) <= 1 {
		return
	}
	limit := len(ips)
	if limit > 8 {
		limit = 8
	}
	list := make([]map[string]any, 0, limit)
	for _, ip := range ips[:limit] {
		list = append(list, map[string]any{
			"ip": ip, "in_cn": prefixContains(direct, ip), "geo": s.geoLookup(ip),
		})
	}
	routing["result_ips_geo"] = list
}
