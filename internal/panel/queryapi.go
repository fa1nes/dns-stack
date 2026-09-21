package panel

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const queryCountCap = 10000

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "items": []any{}, "total": 0})
		return
	}
	defer db.Close()
	q := r.URL.Query()
	page, size := parseInt(q.Get("page"), 1), parseInt(q.Get("size"), 50)
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	where := []string{"1=1"}
	args := []any{}
	if v := strings.TrimSpace(q.Get("domain")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "route = ?")
		args = append(args, v)
	}
	if v := q.Get("resp_by"); v != "" {
		where = append(where, "resp_by = ?")
		args = append(args, v)
	}
	if v := q.Get("since"); v != "" {
		where = append(where, "ts >= ?")
		args = append(args, parseInt(v, 0))
	}
	if v := q.Get("until"); v != "" {
		where = append(where, "ts <= ?")
		args = append(args, parseInt(v, 0))
	}
	if v := q.Get("qtype"); v != "" {
		if n := parseType(v); n >= 0 {
			where = append(where, "qtype = ?")
			args = append(args, n)
		}
	}
	if v := q.Get("rcode"); v != "" {
		if n := parseRcode(v); n >= 0 {
			where = append(where, "rcode = ?")
			args = append(args, n)
		}
	}
	clause := strings.Join(where, " AND ")

	var total int
	countArgs := append(append([]any{}, args...), queryCountCap+1)
	_ = db.QueryRow("SELECT COUNT(*) FROM (SELECT 1 FROM query_events WHERE "+clause+" LIMIT ?)", countArgs...).Scan(&total)
	capped := total > queryCountCap
	if capped {
		total = queryCountCap
	}

	offset := (page - 1) * size
	if offset > queryCountCap {
		offset = queryCountCap
	}
	dataArgs := append(append([]any{}, args...), size, offset)
	rows, err := db.Query("SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events WHERE "+clause+" ORDER BY id DESC LIMIT ? OFFSET ?", dataArgs...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ts, qt, rc int64
		var domain, resp, route, tag string
		var prefetch int64
		var elapsed sql.NullFloat64
		var exit sql.NullString
		if rows.Scan(&id, &ts, &domain, &qt, &rc, &resp, &route, &tag, &prefetch, &elapsed, &exit) != nil {
			continue
		}
		items = append(items, enrichItem(id, ts, qt, rc, domain, resp, route, tag, prefetch, elapsed, exit))
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "total_capped": capped, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func enrichItem(id, ts, qt, rc int64, domain, resp, route, tag string, prefetch int64, elapsed sql.NullFloat64, exit sql.NullString) map[string]any {
	m := map[string]any{"id": id, "ts": ts, "domain": domain, "qtype": qt, "qtype_name": qtypeName(qt), "rcode": rc, "rcode_name": rcodeName(rc), "resp_by": resp, "route": route, "route_name": routeNameEnrich(route), "server_tag": tag, "prefetch": prefetch, "cache_hit": resp == "cache", "elapsed_ms": nil, "exit_path": nil}
	if elapsed.Valid {
		m["elapsed_ms"] = elapsed.Float64
	}
	if exit.Valid {
		m["exit_path"] = exit.String
	}
	return m
}

func queryItem(id, ts, qt, rc int64, domain, resp, route, tag string, prefetch int64, elapsed sql.NullFloat64, exit sql.NullString) map[string]any {
	m := map[string]any{"id": id, "ts": ts, "domain": domain, "qtype": qt, "qtype_name": qtypeName(qt), "rcode": rc, "rcode_name": rcodeName(rc), "resp_by": resp, "route": route, "route_name": routeName(route), "server_tag": tag, "prefetch": prefetch != 0, "cache_hit": resp == "cache"}
	if elapsed.Valid {
		m["elapsed_ms"] = elapsed.Float64
	}
	if exit.Valid {
		m["exit_path"] = exit.String
	}
	return m
}

func (s *Server) queryStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	last := int64(parseInt(r.URL.Query().Get("after_id"), 0))
	db, err := s.openDB()
	if err != nil {
		_, _ = w.Write([]byte("data: {\"error\":\"数据库不可用\"}\n\n"))
		fl.Flush()
		return
	}
	defer db.Close()
	if last == 0 {
		_ = db.QueryRow("SELECT COALESCE(MAX(id),0) FROM query_events").Scan(&last)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	idle := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			rows, err := db.Query("SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events WHERE id > ? ORDER BY id ASC LIMIT 200", last)
			if err == nil {
				events := []map[string]any{}
				for rows.Next() {
					var id, ts, qt, rc, pre int64
					var domain, resp, route, tag string
					var elapsed sql.NullFloat64
					var exit sql.NullString
					if rows.Scan(&id, &ts, &domain, &qt, &rc, &resp, &route, &tag, &pre, &elapsed, &exit) != nil {
						continue
					}
					events = append(events, enrichItem(id, ts, qt, rc, domain, resp, route, tag, pre, elapsed, exit))
				}
				rows.Close()
				if len(events) > 0 {
					last = events[len(events)-1]["id"].(int64)
					payload, _ := json.Marshal(map[string]any{"events": events})
					_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
					fl.Flush()
					idle = 0
					continue
				}
			}
			idle++
			if idle >= 15 {
				_, _ = w.Write([]byte(": keepalive\n\n"))
				fl.Flush()
				idle = 0
			}
		}
	}
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "items": []any{}, "total": 0})
		return
	}
	defer db.Close()
	q := r.URL.Query()
	page, size := parseInt(q.Get("page"), 1), parseInt(q.Get("size"), 50)
	if size < 1 || size > 500 {
		size = 50
	}

	if limit := parseInt(q.Get("limit"), 0); limit >= 1 && limit <= 500 {
		size = limit
	}
	metric := q.Get("metric")
	if metric == "" {
		metric = "count"
	}
	if metric == "slow" {
		s.domainsSlow(w, r, db, page, size)
		return
	}
	where := []string{"1=1"}
	args := []any{}
	if v := strings.TrimSpace(q.Get("search")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "last_route = ?")
		args = append(args, v)
	}
	if metric == "fail" {
		where = append(where, "domain IN (SELECT domain FROM query_events WHERE rcode NOT IN (0,3) AND ts >= ?)")
		args = append(args, s.now().Add(-24*time.Hour).Unix())
	}
	order := map[string]string{"count": "occurrence_count DESC", "recent": "last_seen_at DESC", "new": "first_seen_at DESC", "fail": "fail_count DESC, occurrence_count DESC"}[metric]
	if order == "" {
		order = "occurrence_count DESC"
	}
	clause := strings.Join(where, " AND ")
	var total int
	_ = db.QueryRow("SELECT COUNT(*) FROM domains WHERE "+clause, args...).Scan(&total)
	rows, err := db.Query("SELECT domain,first_seen_at,last_seen_at,occurrence_count,COALESCE(fail_count,0),last_rcode,last_route FROM domains WHERE "+clause+" ORDER BY "+order+" LIMIT ? OFFSET ?", append(args, size, (page-1)*size)...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var d, lr sql.NullString
		var first, last, count, fail, rcode sql.NullInt64
		if rows.Scan(&d, &first, &last, &count, &fail, &rcode, &lr) != nil {
			continue
		}
		items = append(items, domainItem(d, first, last, count, fail, rcode, lr))
	}
	s.attachResolvedNode(r.Context(), items)
	writeJSON(w, 200, map[string]any{"items": items, "metric": metric, "total": total, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func (s *Server) domainsSlow(w http.ResponseWriter, r *http.Request, db *sql.DB, page, size int) {
	q := r.URL.Query()
	where := []string{"elapsed_ms IS NOT NULL", "ts >= ?"}
	args := []any{s.now().Add(-24 * time.Hour).Unix()}
	if v := strings.TrimSpace(q.Get("search")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "route = ?")
		args = append(args, v)
	}
	sub := "SELECT domain, elapsed_ms, ts FROM query_events WHERE " + strings.Join(where, " AND ") + " ORDER BY id DESC LIMIT 100000"
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM (SELECT domain FROM ("+sub+") GROUP BY domain HAVING COUNT(*) >= 2)", args...).Scan(&total); err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	dataArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := db.Query("SELECT domain, COUNT(*) AS samples, ROUND(AVG(elapsed_ms),2) AS avg_ms, ROUND(MAX(elapsed_ms),2) AS max_ms, MAX(ts) AS last_seen_at FROM ("+sub+") GROUP BY domain HAVING COUNT(*) >= 2 ORDER BY avg_ms DESC LIMIT ? OFFSET ?", dataArgs...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var domain string
		var samples, lastSeen int64
		var avg, max sql.NullFloat64
		if rows.Scan(&domain, &samples, &avg, &max, &lastSeen) != nil {
			continue
		}
		items = append(items, map[string]any{"domain": domain, "samples": samples, "avg_ms": nilFloat(avg), "max_ms": nilFloat(max), "last_seen_at": lastSeen})
	}
	s.attachResolvedNode(r.Context(), items)
	writeJSON(w, 200, map[string]any{"items": items, "metric": "slow", "total": total, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func nilFloat(v sql.NullFloat64) any {
	if v.Valid {
		return v.Float64
	}
	return nil
}

func domainItem(d sql.NullString, first, last, count, fail, rcode sql.NullInt64, lr sql.NullString) map[string]any {
	m := map[string]any{"domain": d.String, "first_seen_at": first.Int64, "last_seen_at": last.Int64, "occurrence_count": count.Int64, "fail_count": fail.Int64, "last_rcode": nilInt(rcode), "last_route": lr.String, "last_route_name": routeName(lr.String)}
	if rcode.Valid {
		m["last_rcode_name"] = rcodeName(rcode.Int64)
	}
	return m
}

func nilInt(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

func (s *Server) domainSummary(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用"})
		return
	}
	defer db.Close()

	now := s.now().Unix()
	since := now - 86400
	if epoch := s.archEpoch(); epoch > since {
		since = epoch
	}
	out := map[string]any{}
	domainSummaryExtras(db, out, now, since)
	writeJSON(w, 200, out)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "series": []any{}})
		return
	}
	defer db.Close()
	span := parseInt(r.URL.Query().Get("span"), 3600)
	buckets := parseInt(r.URL.Query().Get("buckets"), 60)
	if span < 300 {
		span = 300
	}
	if buckets < 10 {
		buckets = 10
	}
	if buckets > 200 {
		buckets = 200
	}
	step := span / buckets
	if step < 1 {
		step = 1
	}
	now := s.now().Unix()
	since := now - int64(span)
	rows, _ := db.Query("SELECT ((ts-?)/?) AS b, route, COUNT(*) FROM query_events WHERE ts >= ? GROUP BY b,route ORDER BY b", since, step, since)
	vals := map[int64]map[string]int{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b int64
			var route string
			var c int
			_ = rows.Scan(&b, &route, &c)
			if vals[b] == nil {
				vals[b] = map[string]int{}
			}
			vals[b][route] = c
		}
	}
	series := []map[string]any{}
	for i := 0; i <= buckets; i++ {
		b := int64(i)
		x := vals[b]
		series = append(series, map[string]any{"t": since + b*int64(step), "cn": x["cn"], "foreign": x["foreign"], "cache": x["cache"], "reject": x["reject"], "unknown": x["unknown"]})
	}
	writeJSON(w, 200, map[string]any{"series": series, "step": step, "start": since, "end": now})
}

func (s *Server) domainDetail(w http.ResponseWriter, r *http.Request) {
	s.detailInfo(w, r)
}

func (s *Server) collected(w http.ResponseWriter, r *http.Request) {
	s.collectedInfo(w, r)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	now := s.now().Unix()
	out := map[string]any{"role": s.role(), "ts": now, "upstreams": []any{}, "system": map[string]any{}, "routing": map[string]any{}}
	mos, mosErr := helperCall(r.Context(), "mosproxy_metrics", nil)
	unbound, unboundErr := helperCall(r.Context(), "unbound_stats", nil)
	if mosErr == nil && helperOK(mos) {
		parsed := parseMetrics(helperStdout(mos))
		queries := metricByLabel(parsed, "upstream_query_total", "upstream")
		errors := metricByLabel(parsed, "upstream_err_total", "upstream")
		cache := metricScalar(parsed, "query_cache_hit_total")
		total, failed := cache, 0.0
		for _, value := range queries {
			total += value
		}
		for _, value := range errors {
			failed += value
		}

		latSum, latCount := 0.0, 0.0
		for _, value := range metricByLabel(parsed, "upstream_response_latency_millisecond_sum", "upstream") {
			latSum += value
		}
		for _, value := range metricByLabel(parsed, "upstream_response_latency_millisecond_count", "upstream") {
			latCount += value
		}
		var avgLatency any
		if latCount > 0 {
			avgLatency = roundTo(latSum/latCount, 1)
		}

		counters := map[string]float64{"query_total": total, "cache_hit_total": cache}
		for key, value := range queries {
			counters["uq_"+key] = value
		}
		for key, value := range errors {
			counters["ue_"+key] = value
		}
		rates := s.rates.update(counters)
		out["mosproxy"] = map[string]any{"available": true, "avg_latency_ms": avgLatency, "latency_samples": int(latCount), "query_total": int(total), "query_total_synthetic": true, "cache_hit_total": int(cache), "cache_hit_ratio": percentage(cache, total), "qps": roundTo(rates["query_total"], 2), "upstream_query_total": int(total - cache), "upstream_err_total": int(failed), "error_ratio": percentage(failed, total-cache), "prefetch_total": int(metricScalar(parsed, "prefetch_total")), "cache_entries": int(metricScalar(parsed, "cache_memorysize")), "rejected_cc": int(metricScalar(parsed, "rejected_cc_total")), "rejected_qps": int(metricScalar(parsed, "rejected_qps_total"))}
	} else {
		out["mosproxy"] = map[string]any{"available": false, "message": helperError(mosErr, mos)}
	}
	if unboundErr == nil && helperOK(unbound) {
		stats := parseUnboundStats(helperStdout(unbound))
		total := stats["total.num.queries"]
		hits := stats["total.num.cachehits"]
		out["unbound"] = map[string]any{"available": true, "queries": int(total), "cache_hits": int(hits), "cache_miss": int(stats["total.num.cachemiss"]), "cache_hit_ratio": percentage(hits, total), "prefetch": int(stats["total.num.prefetch"]), "recursion_time_avg_ms": roundTo(stats["total.recursion.time.avg"]*1000, 1), "recursion_time_median_ms": roundTo(stats["total.recursion.time.median"]*1000, 1), "requestlist_current": int(stats["total.requestlist.current.all"]), "subnet_queries": optionalStat(stats, "num.query.subnet"), "subnet_cache_hits": optionalStat(stats, "num.query.subnet_cache")}
	} else {
		out["unbound"] = map[string]any{"available": false, "message": helperError(unboundErr, unbound)}
	}
	out["system"] = systemInfo()
	db, err := s.openDB()
	if err == nil {
		defer db.Close()
		var last5, last1, domains int
		_ = db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ?", now-300).Scan(&last5)
		_ = db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ?", now-3600).Scan(&last1)
		_ = db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domains)
		out["events"] = map[string]any{"last_5m": last5, "last_1h": last1, "domains": domains,
			"latency": latencyStats(db, now-3600)}
	} else {
		out["events"] = map[string]any{"error": "数据库不可用"}
	}
	routing := out["routing"].(map[string]any)
	routing["direct4_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "direct4.txt"))
	routing["cn_authority_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "cn-authority.txt"))
	routing["cn_zones_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "cn-zones-matched.txt"))
	routing["exits"] = s.exitAddresses(r.Context())

	if s.role() == "cn-resolver" {
		for key, active := range s.routingServiceState(r) {
			routing[key] = active
		}
	}
	writeJSON(w, 200, out)
}
