package panel

import (
	"context"
	"database/sql"
	"net/http"
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
	if err := statsReport(ctx, db, &s.statsRollup, out, since, now, window.bucket); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"error": "查询失败：" + err.Error()}
	}
	return http.StatusOK, out
}

const clientEvents = "FROM query_events WHERE ts >= ? AND prefetch = 0"

func statsReport(ctx context.Context, db *sql.DB, rollup *statsRollup, out map[string]any, since, now, bucket int64) error {
	if rollup == nil {
		rollup = &statsRollup{}
	}
	hours, err := rollup.hoursSince(ctx, db, since)
	if err != nil {
		return err
	}
	start := since - since%bucket
	slots := int((now-start)/bucket) + 1
	series := make([]map[string]any, slots)
	for i := range series {
		series[i] = map[string]any{"t": start + int64(i)*bucket, "total": int64(0), "cached": int64(0), "servfail": int64(0)}
	}
	sum := newStatsHour()
	for hour, h := range hours {
		sum.queries += h.queries
		sum.cached += h.cached
		sum.servfail += h.servfail
		sum.nxdomain += h.nxdomain
		sum.slow += h.slow
		sum.prefetch += h.prefetch
		for class := range h.latency {
			for i, n := range h.latency[class] {
				sum.latency[class][i] += n
			}
		}
		for _, pair := range [][2]map[string]int64{{sum.qtype, h.qtype}, {sum.rcode, h.rcode}, {sum.exit, h.exit},
			{sum.domains, h.domains}, {sum.failing, h.failing}, {sum.clients, h.clients}} {
			for key, n := range pair[1] {
				pair[0][key] += n
			}
		}
		if slot := (max(hour, since) - start) / bucket; slot >= 0 && slot < int64(slots) {
			point := series[slot]
			point["total"] = point["total"].(int64) + h.queries
			point["cached"] = point["cached"].(int64) + h.cached
			point["servfail"] = point["servfail"].(int64) + h.servfail
		}
	}
	out["totals"] = map[string]any{"queries": sum.queries, "cached": sum.cached, "servfail": sum.servfail, "nxdomain": sum.nxdomain,
		"slow_1s": sum.slow, "prefetch": sum.prefetch, "cache_ratio": percentage(float64(sum.cached), float64(sum.queries)),
		"servfail_ratio": percentage(float64(sum.servfail), float64(sum.queries))}
	out["series"] = series

	latency := map[string]any{"edges": latencyEdges}
	for class, name := range []string{"cache", "upstream"} {
		where := map[string]string{"cache": "resp_by = 'cache'", "upstream": "resp_by != 'cache'"}[name]
		values, err := latencySample(ctx, db, "SELECT elapsed_ms "+clientEvents+" AND elapsed_ms IS NOT NULL AND "+where+
			" ORDER BY ts DESC LIMIT ?", since, latencySampleCap)
		if err != nil {
			return err
		}
		latency[name] = map[string]any{"buckets": sum.latency[class], "samples": len(values), "p50": quantile(values, 50),
			"p95": quantile(values, 95), "p99": quantile(values, 99)}
	}
	out["latency"] = latency

	out["by_qtype"] = rankedItems(sum.qtype, 8, qtypeLabel)
	out["by_rcode"] = rankedItems(sum.rcode, 8, rcodeLabel)
	out["by_exit"] = rankedItems(sum.exit, 8, nil)
	out["top_domains"] = rankedItems(sum.domains, 10, nil)
	out["top_failing"] = rankedItems(sum.failing, 10, nil)
	out["top_clients"] = rankedItems(sum.clients, 10, nil)
	return nil
}

func qtypeLabel(raw string) string { return qtypeName(int64(parseInt(raw, 0))) }

func rcodeLabel(raw string) string { return rcodeName(int64(parseInt(raw, 0))) }
