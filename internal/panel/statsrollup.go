package panel

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	rollupHour = 3600
	rollupKeep = 500
	rollupSpan = 8 * 86400
)

type statsHour struct {
	rows                                                int64
	queries, cached, servfail, nxdomain, slow, prefetch int64
	latency                                             [2][]int64
	qtype, rcode, exit                                  map[string]int64
	domains, failing, clients                           map[string]int64
}

type statsRollup struct {
	mu    sync.Mutex
	hours map[int64]*statsHour
}

func (r *statsRollup) reset() {
	r.mu.Lock()
	r.hours = nil
	r.mu.Unlock()
}

func newStatsHour() *statsHour {
	h := &statsHour{qtype: map[string]int64{}, rcode: map[string]int64{}, exit: map[string]int64{},
		domains: map[string]int64{}, failing: map[string]int64{}, clients: map[string]int64{}}
	for i := range h.latency {
		h.latency[i] = make([]int64, len(latencyEdges)+1)
	}
	return h
}

const rollupScanColumns = "SELECT ts, prefetch, resp_by = 'cache', rcode, elapsed_ms, qtype, COALESCE(exit_path, ''), domain, "

func (r *statsRollup) hoursSince(ctx context.Context, db *sql.DB, since int64) (map[int64]*statsHour, error) {
	first := since - since%rollupHour
	rows, err := db.QueryContext(ctx, "SELECT ts / 3600, COUNT(*) FROM query_events WHERE ts >= ? GROUP BY 1", first)
	if err != nil {
		return nil, err
	}
	counts := map[int64]int64{}
	for rows.Next() {
		var slot, count int64
		if err := rows.Scan(&slot, &count); err != nil {
			rows.Close()
			return nil, err
		}
		counts[slot*rollupHour] = count
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hours == nil {
		r.hours = map[int64]*statsHour{}
	}
	out := make(map[int64]*statsHour, len(counts))
	for hour, count := range counts {
		if hour < since {
			h, err := scanStatsHours(ctx, db, since, hour+rollupHour)
			if err != nil {
				return nil, err
			}
			out[hour] = h
			continue
		}
		if cached := r.hours[hour]; cached != nil && cached.rows == count {
			out[hour] = cached
			continue
		}
		h, err := scanStatsHours(ctx, db, hour, hour+rollupHour)
		if err != nil {
			return nil, err
		}
		h.trim()
		r.hours[hour] = h
		out[hour] = h
	}
	for hour := range r.hours {
		if _, ok := counts[hour]; (!ok && hour >= first) || hour < first-rollupSpan {
			delete(r.hours, hour)
		}
	}
	return out, nil
}

func scanStatsHours(ctx context.Context, db *sql.DB, from, to int64) (*statsHour, error) {
	rows, err := db.QueryContext(ctx, rollupScanColumns+"COALESCE(client_subnet, '') FROM query_events WHERE ts >= ? AND ts < ?", from, to)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		rows, err = db.QueryContext(ctx, rollupScanColumns+"'' FROM query_events WHERE ts >= ? AND ts < ?", from, to)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	h := newStatsHour()
	for rows.Next() {
		var (
			ts, prefetch, cached, rcode, qtype int64
			elapsed                            sql.NullFloat64
			exit, domain, client               string
		)
		if err := rows.Scan(&ts, &prefetch, &cached, &rcode, &elapsed, &qtype, &exit, &domain, &client); err != nil {
			return nil, err
		}
		h.rows++
		if prefetch != 0 {
			h.prefetch++
			continue
		}
		h.queries++
		h.cached += cached
		switch rcode {
		case 2:
			h.servfail++
			h.failing[domain]++
		case 3:
			h.nxdomain++
		}
		if elapsed.Valid {
			if elapsed.Float64 >= 1000 {
				h.slow++
			}
			slot := len(latencyEdges)
			for i, edge := range latencyEdges {
				if elapsed.Float64 < edge {
					slot = i
					break
				}
			}
			h.latency[1-cached][slot]++
		}
		h.qtype[strconv.FormatInt(qtype, 10)]++
		h.rcode[strconv.FormatInt(rcode, 10)]++
		h.exit[exit]++
		h.domains[domain]++
		if client != "" {
			h.clients[client]++
		}
	}
	return h, rows.Err()
}

func (h *statsHour) trim() {
	for _, m := range []map[string]int64{h.domains, h.failing, h.clients} {
		if len(m) <= rollupKeep {
			continue
		}
		kept := rankCounts(m, rollupKeep)
		clear(m)
		for _, item := range kept {
			m[item.key] = item.count
		}
	}
}

type keyCount struct {
	key   string
	count int64
}

func rankCounts(m map[string]int64, limit int) []keyCount {
	items := make([]keyCount, 0, len(m))
	for key, count := range m {
		items = append(items, keyCount{key, count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func rankedItems(m map[string]int64, limit int, label func(string) string) []map[string]any {
	items := []map[string]any{}
	for _, item := range rankCounts(m, limit) {
		name := item.key
		if label != nil {
			name = label(item.key)
		}
		items = append(items, map[string]any{"key": item.key, "name": name, "count": item.count})
	}
	return items
}
