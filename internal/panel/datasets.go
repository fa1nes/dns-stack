package panel

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func dataLines(path string) []string {
	values := []string{}
	file, err := os.Open(path)
	if err != nil {
		return values
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value != "" && !strings.HasPrefix(value, "#") {
			values = append(values, value)
		}
	}
	return values
}

func (s *Server) statePath(path string) string { return filepath.Join(s.cfg.StateDir, path) }

func (s *Server) rulesInfo() map[string]any {
	info := map[string]any{"updated_at": nil, "polluted_ip_updated_at": nil, "last_sync_at": nil, "history": []string{}, "rollback_versions": []map[string]any{}}
	paths := map[string]string{"cn": "cn.txt", "manual_cn": "manual-cn.txt", "gfw": "gfw.txt", "manual_gfw": "manual-gfw.txt", "cn_cidr": "cn-ip-cidr.txt", "polluted_cidr": "polluted-ip-cidr.txt", "polluted_ip": "polluted-ip.txt", "direct4": "chnroute/direct4.txt", "cn_authority": "chnroute/cn-authority.txt", "cn_zones_matched": "chnroute/cn-zones-matched.txt", "manual_cn_zones": "manual-cn-zones.txt"}
	for key, path := range paths {
		info[key+"_count"] = countLines(s.statePath(path))
	}
	for key, path := range map[string]string{"updated_at": "cn.txt", "polluted_ip_updated_at": "polluted-ip.txt", "last_sync_at": "sync-state/last-generated-at"} {
		if stat, err := os.Stat(s.statePath(path)); err == nil {
			info[key] = stat.ModTime().Unix()
		}
	}
	if content, err := os.ReadFile(s.statePath("sync-state/history.log")); err == nil {
		lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		start := len(lines) - 30
		if start < 0 {
			start = 0
		}
		history := []string{}
		for index := len(lines) - 1; index >= start; index-- {
			if line := strings.TrimSpace(lines[index]); line != "" {
				history = append(history, line)
			}
		}
		info["history"] = history
	}
	versions, _ := filepath.Glob(s.statePath("rule-history/bundle-*"))
	sort.SliceStable(versions, func(left, right int) bool {
		leftInfo, leftErr := os.Stat(versions[left])
		rightInfo, rightErr := os.Stat(versions[right])
		return leftErr == nil && (rightErr != nil || leftInfo.ModTime().After(rightInfo.ModTime()))
	})
	if len(versions) > 10 {
		versions = versions[:10]
	}
	items := []map[string]any{}
	for _, version := range versions {
		stat, err := os.Stat(version)
		if err != nil {
			continue
		}
		count := 0
		for _, name := range []string{"cn.txt", "gfw.txt", "cn-ip-cidr.txt", "polluted-ip-cidr.txt"} {
			count += countLines(filepath.Join(version, name))
		}
		items = append(items, map[string]any{"name": filepath.Base(version), "mtime": stat.ModTime().Unix(), "count": count})
	}
	info["rollback_versions"] = items
	return info
}

const exportRowLimit = 100000

var exportQueryColumns = []string{"id", "ts", "domain", "qtype", "rcode", "resp_by", "route", "server_tag", "prefetch", "elapsed_ms", "exit_path", "qtype_name", "rcode_name", "route_name", "cache_hit"}
var exportDomainColumns = []string{"domain", "first_seen_at", "last_seen_at", "occurrence_count", "fail_count", "last_rcode", "last_route", "last_rcode_name", "last_route_name"}

func (s *Server) exportData(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dataset, format := q.Get("dataset"), q.Get("format")
	if format == "" {
		format = "json"
	}
	if dataset != "queries" && dataset != "domains" && dataset != "rules" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的 dataset 参数"})
		return
	}

	if format != "json" && (format != "csv" || dataset == "rules") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的 format 参数"})
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"dns-stack-"+dataset+"."+format+"\"")
	if dataset == "rules" {
		writeExportJSON(w, s.rulesInfo())
		return
	}
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "数据库不可用"})
		return
	}
	defer db.Close()
	var items []map[string]any
	if dataset == "queries" {
		items, err = exportQueryItems(db, exportRowLimit)
	} else {
		items, err = exportDomainItems(db, exportRowLimit)
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "查询失败"})
		return
	}
	if format == "csv" {
		columns := exportQueryColumns
		if dataset == "domains" {
			columns = exportDomainColumns
		}
		writeExportCSV(w, columns, items)
		return
	}
	writeExportJSON(w, items)
}

func exportQueryItems(db *sql.DB, limit int) ([]map[string]any, error) {
	rows, err := db.Query("SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events ORDER BY id ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
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
		items = append(items, queryItem(id, ts, qt, rc, domain, resp, route, tag, prefetch, elapsed, exit))
	}
	return items, nil
}

func exportDomainItems(db *sql.DB, limit int) ([]map[string]any, error) {
	rows, err := db.Query("SELECT domain,first_seen_at,last_seen_at,occurrence_count,COALESCE(fail_count,0),last_rcode,last_route FROM domains ORDER BY occurrence_count DESC, domain ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
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
	return items, nil
}

func writeExportJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeExportCSV(w http.ResponseWriter, columns []string, items []map[string]any) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	writer := csv.NewWriter(w)
	_ = writer.Write(columns)
	record := make([]string, len(columns))
	for _, item := range items {
		for i, column := range columns {
			record[i] = exportCSVValue(item[column])
		}
		_ = writer.Write(record)
	}
	writer.Flush()
}

func exportCSVValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func (s *Server) collectedInfo(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用"})
		return
	}
	defer db.Close()
	now := time.Now()
	if s.clock != nil {
		now = s.clock()
	}
	since := now.Unix() - 86400
	if content, err := os.ReadFile(s.statePath("architecture-epoch")); err == nil {
		if epoch, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64); err == nil && epoch > since {
			since = epoch
		}
	}
	out := map[string]any{}
	for key, query := range map[string]string{"domains_total": "SELECT COUNT(*) FROM domains", "domains_active_24h": "SELECT COUNT(DISTINCT domain) FROM query_events WHERE ts >= ?", "queries_24h": "SELECT COUNT(*) FROM query_events WHERE ts >= ?"} {
		args := []any{}
		if key != "domains_total" {
			args = append(args, since)
		}
		var count int64
		if err := db.QueryRowContext(r.Context(), query, args...).Scan(&count); err != nil {
			out["error"] = err.Error()
			break
		}
		out[key] = count
	}
	rows, err := db.QueryContext(r.Context(), "SELECT domain, COUNT(*) AS c FROM query_events WHERE ts >= ? AND rcode != 0 GROUP BY domain", since)
	if err != nil {
		out["error"] = err.Error()
	} else {
		type failing struct {
			Domain     string `json:"domain"`
			Count      int64  `json:"count"`
			Subdomains int    `json:"subdomains"`
		}
		groups := map[string]int{}
		items := []failing{}
		for rows.Next() {
			var name string
			var count int64
			if err := rows.Scan(&name, &count); err != nil {
				out["error"] = err.Error()
				break
			}
			labels := strings.Split(strings.ToLower(name), ".")
			if len(labels) > 2 {
				labels = labels[len(labels)-2:]
			}
			key := strings.Join(labels, ".")
			index, exists := groups[key]
			if !exists {
				index = len(items)
				groups[key] = index
				items = append(items, failing{Domain: key})
			}
			items[index].Count += count
			items[index].Subdomains++
		}
		if err := rows.Err(); err != nil {
			out["error"] = err.Error()
		}
		rows.Close()
		sort.SliceStable(items, func(left, right int) bool { return items[left].Count > items[right].Count })
		if len(items) > 12 {
			items = items[:12]
		}
		out["failing_domains"] = items
	}
	zones := []string{}
	seen := map[string]bool{}
	for _, zone := range dataLines(s.statePath("chnroute/cn-zones-matched.txt")) {
		zone = strings.ToLower(zone)
		if !seen[zone] {
			seen[zone] = true
			zones = append(zones, zone)
		}
	}
	sort.Strings(zones)
	polluted := dataLines(s.statePath("polluted-ip.txt"))
	data, metadata := map[string]any{}, map[string]any{}
	for key, items := range map[string][]string{"cn_zones": zones, "polluted": polluted} {
		total := len(items)
		if total > 20000 {
			items = items[:20000]
		}
		data[key] = items
		metadata[key] = map[string]any{"returned": len(items), "total": total, "truncated": total > len(items)}
	}
	directCount := 0
	for _, line := range dataLines(s.statePath("chnroute/direct4.txt")) {
		if prefix, err := netip.ParsePrefix(line); err == nil && prefix.Addr().Is4() && prefix == prefix.Masked() {
			directCount++
		}
	}
	out["data"], out["data_meta"] = data, metadata
	out["ip"] = map[string]any{"direct4": directCount, "cn_authority": countLines(s.statePath("chnroute/cn-authority.txt")), "cn_zones": len(zones), "polluted": len(polluted), "polluted_cidr": countLines(s.statePath("polluted-ip-cidr.txt"))}
	writeJSON(w, 200, out)
}
