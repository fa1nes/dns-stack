package panel

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const statsReportTTL = 60 * time.Second

var statsSpans = map[string]struct {
	seconds, bucket int64
}{
	"24h": {86400, 3600},
	"7d":  {7 * 86400, 6 * 3600},
}

var latencyEdges = []float64{1, 5, 20, 50, 100, 300, 1000}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	span := r.URL.Query().Get("span")
	if _, ok := statsSpans[span]; !ok {
		span = "24h"
	}
	status, body := s.statsShared.entry("report-"+span).get(r.Context(), s.now(), statsReportTTL, func() (int, []byte) {
		return encodeShared(s.buildStats(context.Background(), span))
	})
	writeShared(w, status, body)
}

func (s *Server) buildStats(ctx context.Context, span string) (int, map[string]any) {
	db, err := s.openDB()
	if err != nil {
		return http.StatusServiceUnavailable, map[string]any{"error": "数据库不可用"}
	}
	defer db.Close()
	window := statsSpans[span]
	now := s.now().Unix()
	since := max(now-window.seconds, s.archEpoch())
	out := map[string]any{"span": span, "since": since, "until": now, "bucket": window.bucket}
	if err := statsReport(ctx, db, out, since, now, window.bucket); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"error": "查询失败：" + err.Error()}
	}
	return http.StatusOK, out
}

const clientEvents = "FROM query_events WHERE ts >= ? AND prefetch = 0"

func statsReport(ctx context.Context, db *sql.DB, out map[string]any, since, now, bucket int64) error {
	var total, cached, servfail, nxdomain, slow int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*), "+
		"COALESCE(SUM(resp_by = 'cache'), 0), COALESCE(SUM(rcode = 2), 0), COALESCE(SUM(rcode = 3), 0), "+
		"COALESCE(SUM(elapsed_ms >= 1000), 0) "+clientEvents, since).
		Scan(&total, &cached, &servfail, &nxdomain, &slow); err != nil {
		return err
	}
	var prefetch int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM query_events WHERE ts >= ? AND prefetch != 0", since).Scan(&prefetch); err != nil {
		return err
	}
	out["totals"] = map[string]any{"queries": total, "cached": cached, "servfail": servfail, "nxdomain": nxdomain,
		"slow_1s": slow, "prefetch": prefetch, "cache_ratio": percentage(float64(cached), float64(total)),
		"servfail_ratio": percentage(float64(servfail), float64(total))}

	series, err := statsSeries(ctx, db, since, now, bucket)
	if err != nil {
		return err
	}
	out["series"] = series

	latency := map[string]any{"edges": latencyEdges}
	for name, where := range map[string]string{"cache": "resp_by = 'cache'", "upstream": "resp_by != 'cache'"} {
		entry, err := latencyClass(ctx, db, since, where)
		if err != nil {
			return err
		}
		latency[name] = entry
	}
	out["latency"] = latency

	for _, group := range []struct {
		key, query string
		name       func(string) string
	}{
		{"by_qtype", "SELECT qtype, COUNT(*) " + clientEvents + " GROUP BY qtype ORDER BY 2 DESC LIMIT 8", qtypeLabel},
		{"by_rcode", "SELECT rcode, COUNT(*) " + clientEvents + " GROUP BY rcode ORDER BY 2 DESC LIMIT 8", rcodeLabel},
		{"by_exit", "SELECT COALESCE(exit_path, ''), COUNT(*) " + clientEvents + " GROUP BY 1 ORDER BY 2 DESC LIMIT 8", nil},
		{"top_domains", "SELECT domain, COUNT(*) " + clientEvents + " GROUP BY domain ORDER BY 2 DESC LIMIT 10", nil},
		{"top_failing", "SELECT domain, COUNT(*) " + clientEvents + " AND rcode = 2 GROUP BY domain ORDER BY 2 DESC LIMIT 10", nil},
		{"top_clients", "SELECT client_subnet, COUNT(*) " + clientEvents + " AND COALESCE(client_subnet, '') != '' GROUP BY 1 ORDER BY 2 DESC LIMIT 10", nil},
	} {
		items, err := groupCounts(ctx, db, group.query, since, group.name)
		if err != nil {
			if strings.Contains(err.Error(), "no such column") {
				out[group.key] = []any{}
				continue
			}
			return err
		}
		out[group.key] = items
	}
	return nil
}

func qtypeLabel(raw string) string { return qtypeName(int64(parseInt(raw, 0))) }

func rcodeLabel(raw string) string { return rcodeName(int64(parseInt(raw, 0))) }

func statsSeries(ctx context.Context, db *sql.DB, since, now, bucket int64) ([]map[string]any, error) {
	start := since - since%bucket
	rows, err := db.QueryContext(ctx, "SELECT (ts - ?) / ?, COUNT(*), COALESCE(SUM(resp_by = 'cache'), 0), "+
		"COALESCE(SUM(rcode = 2), 0) "+clientEvents+" GROUP BY 1", start, bucket, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	slots := int((now-start)/bucket) + 1
	series := make([]map[string]any, slots)
	for i := range series {
		series[i] = map[string]any{"t": start + int64(i)*bucket, "total": 0, "cached": 0, "servfail": 0}
	}
	for rows.Next() {
		var slot, total, cached, failed int64
		if err := rows.Scan(&slot, &total, &cached, &failed); err != nil {
			return nil, err
		}
		if slot >= 0 && slot < int64(slots) {
			series[slot]["total"], series[slot]["cached"], series[slot]["servfail"] = total, cached, failed
		}
	}
	return series, rows.Err()
}

func latencyClass(ctx context.Context, db *sql.DB, since int64, where string) (map[string]any, error) {
	cases := []string{}
	for i, edge := range latencyEdges {
		cases = append(cases, "WHEN elapsed_ms < "+strconv.FormatFloat(edge, 'f', -1, 64)+" THEN "+strconv.Itoa(i))
	}
	rows, err := db.QueryContext(ctx, "SELECT CASE "+strings.Join(cases, " ")+" ELSE "+strconv.Itoa(len(latencyEdges))+
		" END, COUNT(*) "+clientEvents+" AND elapsed_ms IS NOT NULL AND "+where+" GROUP BY 1", since)
	if err != nil {
		return nil, err
	}
	buckets := make([]int64, len(latencyEdges)+1)
	for rows.Next() {
		var slot, count int64
		if err := rows.Scan(&slot, &count); err != nil {
			rows.Close()
			return nil, err
		}
		if slot >= 0 && slot < int64(len(buckets)) {
			buckets[slot] = count
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	values, err := latencySample(ctx, db, "SELECT elapsed_ms "+clientEvents+" AND elapsed_ms IS NOT NULL AND "+where+
		" ORDER BY ts DESC LIMIT ?", since, latencySampleCap)
	if err != nil {
		return nil, err
	}
	return map[string]any{"buckets": buckets, "samples": len(values), "p50": quantile(values, 50),
		"p95": quantile(values, 95), "p99": quantile(values, 99)}, nil
}

func groupCounts(ctx context.Context, db *sql.DB, query string, since int64, label func(string) string) ([]map[string]any, error) {
	rows, err := db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var key sql.NullString
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		name := key.String
		if label != nil {
			name = label(key.String)
		}
		items = append(items, map[string]any{"key": key.String, "name": name, "count": count})
	}
	return items, rows.Err()
}
