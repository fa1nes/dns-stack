package panel

import (
	"context"
	"database/sql"
	"github.com/dns-stack/dns-stack/internal/stack"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

func (s *Server) statsWindowStart(now int64) int64 {
	return max(now-86400, s.archEpoch())
}

const latencySampleCap = 10000

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

func latencyStats(ctx context.Context, db *sql.DB, since int64) (map[string]any, error) {
	out := map[string]any{"samples": 0, "avg": nil}
	var samples sql.NullInt64
	var avg sql.NullFloat64
	err := db.QueryRowContext(ctx,
		"SELECT COUNT(*), AVG(elapsed_ms) FROM query_events "+
			"WHERE ts >= ? AND elapsed_ms IS NOT NULL", since).Scan(&samples, &avg)
	if err != nil {
		return out, err
	}
	total := samples.Int64
	out["samples"] = total
	if avg.Valid {
		out["avg"] = roundTo(avg.Float64, 2)
	}
	if total == 0 {
		return out, nil
	}
	values, err := latencySample(ctx, db,
		"SELECT elapsed_ms FROM query_events WHERE ts >= ? AND elapsed_ms IS NOT NULL ORDER BY ts DESC LIMIT ?",
		since, latencySampleCap)
	if err != nil {
		return out, err
	}
	sampleN := int64(len(values))
	out["p50"], out["p95"] = quantile(values, 50), quantile(values, 95)
	out["sampled"] = sampleN < total
	if sampleN < total {
		out["sampled_from"] = sampleN
	}
	var slow int64
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM query_events WHERE ts >= ? AND elapsed_ms >= 1000",
		since).Scan(&slow); err != nil {
		return out, err
	}
	out["slow_1s"] = slow
	byRoute := map[string]any{}
	for _, route := range []string{"cache", "cn", "foreign"} {
		values, err := latencySample(ctx, db,
			"SELECT elapsed_ms FROM query_events WHERE route = ? AND ts >= ? AND elapsed_ms IS NOT NULL ORDER BY ts DESC LIMIT ?",
			route, since, latencySampleCap)
		if err != nil {
			return out, err
		}
		if len(values) > 0 {
			byRoute[route] = map[string]any{"n": len(values), "p50": quantile(values, 50), "p95": quantile(values, 95)}
		}
	}
	out["by_route"] = byRoute
	return out, nil
}

func latencySample(ctx context.Context, db *sql.DB, query string, args ...any) ([]float64, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []float64
	for rows.Next() {
		var value float64
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Float64s(values)
	return values, nil
}

func quantile(sorted []float64, q int) any {
	if len(sorted) == 0 {
		return nil
	}
	index := len(sorted)*q/100 - 1
	if index < 0 {
		index = 0
	}
	return roundTo(sorted[index], 2)
}

func (s *Server) routingServiceState(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	units := []string{"dns-stack-recursive-routing", "wg-quick@" + stack.TunnelIf}
	for _, item := range s.serviceStatus(ctx, units) {
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

func domainSummaryExtras(ctx context.Context, db *sql.DB, out map[string]any, now, since int64) error {
	byExit := []map[string]any{}
	rows, err := db.QueryContext(ctx,
		"SELECT exit_path, COUNT(*) FROM query_events "+
			"WHERE ts >= ? AND exit_path IS NOT NULL GROUP BY exit_path ORDER BY 2 DESC",
		since)
	if err != nil {
		return err
	}
	for rows.Next() {
		var path string
		var count int
		if err := rows.Scan(&path, &count); err != nil {
			_ = rows.Close()
			return err
		}
		byExit = append(byExit, map[string]any{"path": path, "count": count})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	out["by_exit"] = byExit

	var new24, active1h, failing, failedEver int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains WHERE first_seen_at >= ?", since).Scan(&new24); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains WHERE last_seen_at >= ?", max(now-3600, since)).Scan(&active1h); err != nil {
		return err
	}

	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT +domain) FROM query_events WHERE rcode NOT IN (0,3) AND ts >= ?",
		since).Scan(&failing); err != nil {
		return err
	}

	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains WHERE COALESCE(fail_count,0) > 0").Scan(&failedEver); err != nil {
		return err
	}
	out["new_24h"] = new24
	out["active_1h"] = active1h
	out["failing"] = failing
	out["failed_ever"] = failedEver

	byQtype := []map[string]any{}
	rows, err = db.QueryContext(ctx,
		"SELECT qtype, COUNT(*) FROM query_events WHERE ts >= ? "+
			"GROUP BY qtype ORDER BY 2 DESC LIMIT 10", since)
	if err != nil {
		return err
	}
	for rows.Next() {
		var qtype int64
		var count int
		if err := rows.Scan(&qtype, &count); err != nil {
			_ = rows.Close()
			return err
		}
		byQtype = append(byQtype, map[string]any{
			"qtype": qtype, "name": qtypeName(qtype), "count": count})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	out["by_qtype"] = byQtype

	byRcode := []map[string]any{}
	rows, err = db.QueryContext(ctx,
		"SELECT rcode, COUNT(*) FROM query_events WHERE ts >= ? "+
			"GROUP BY rcode ORDER BY 2 DESC LIMIT 10", since)
	if err != nil {
		return err
	}
	for rows.Next() {
		var rcode int64
		var count int
		if err := rows.Scan(&rcode, &count); err != nil {
			_ = rows.Close()
			return err
		}
		byRcode = append(byRcode, map[string]any{
			"rcode": rcode, "name": rcodeName(rcode), "count": count})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	out["by_rcode"] = byRcode
	return nil
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
