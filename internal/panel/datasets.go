package panel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
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
	info := map[string]any{"cdn_generated_at": nil}
	paths := map[string]string{
		"manual_gfw":    "manual-gfw.txt",
		"polluted_cidr": "polluted-ip-cidr.txt",
	}
	for key, path := range paths {
		info[key+"_count"] = countLines(s.statePath(path))
	}
	info["cdn_providers"], info["cdn_prefixes"], info["cdn_mainland"] = 0, 0, 0
	if set, err := cdnrules.Load(cdnrules.Path(s.cfg.StateDir)); err == nil {
		mainland := 0
		for _, provider := range set.Providers() {
			mainland += len(provider.Mainland)
		}
		info["cdn_providers"] = len(set.Providers())
		info["cdn_prefixes"] = set.PrefixCount()
		info["cdn_mainland"] = mainland
		info["cdn_generated_at"] = set.GeneratedAt().Unix()
	}
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
	listSource := map[string]string{
		"cn_zones": filepath.Join("chnroute", "cn-zones-matched.txt"),
		"polluted": "polluted-ip.txt",
	}[dataset]

	switch dataset {
	case "queries", "domains", "cn_zones", "polluted":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的 dataset 参数"})
		return
	}
	switch {
	case format == "json":
	case format == "txt" && listSource != "":
	case format == "csv" && listSource == "":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的 format 参数"})
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"dns-stack-"+dataset+"."+format+"\"")
	if listSource != "" {
		lines := dataLines(s.statePath(listSource))
		if format == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, line := range lines {
				_, _ = w.Write([]byte(line + "\n"))
			}
			return
		}
		writeExportJSON(w, map[string]any{"dataset": dataset, "count": len(lines), "items": lines})
		return
	}
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "数据库不可用"})
		return
	}
	defer db.Close()
	columns, open := exportQueryColumns, openQueryExport
	if dataset == "domains" {
		columns, open = exportDomainColumns, openDomainExport
	}
	cursor, err := open(r.Context(), db, exportRowLimit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "查询失败"})
		return
	}
	defer cursor.close()
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	body, finish := exportStream(w, r)
	var streamErr error
	if format == "csv" {
		streamErr = streamExportCSV(body, columns, cursor)
	} else {
		streamErr = streamExportJSON(body, cursor)
	}
	finish()
	if streamErr != nil {
		panic(http.ErrAbortHandler)
	}
}

type exportCursor struct {
	rows *sql.Rows
	item func(*sql.Rows) (map[string]any, error)
}

func (c *exportCursor) close() { c.rows.Close() }

func (c *exportCursor) each(fn func(map[string]any) error) error {
	for c.rows.Next() {
		item, err := c.item(c.rows)
		if err != nil {
			return err
		}
		if err := fn(item); err != nil {
			return err
		}
	}
	return c.rows.Err()
}

func openQueryExport(ctx context.Context, db *sql.DB, limit int) (*exportCursor, error) {
	rows, err := db.QueryContext(ctx, "SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events ORDER BY id ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	return &exportCursor{rows: rows, item: scanQueryItem}, nil
}

func scanQueryItem(rows *sql.Rows) (map[string]any, error) {
	var id, ts, qt, rc int64
	var domain, resp, route, tag string
	var prefetch int64
	var elapsed sql.NullFloat64
	var exit sql.NullString
	if err := rows.Scan(&id, &ts, &domain, &qt, &rc, &resp, &route, &tag, &prefetch, &elapsed, &exit); err != nil {
		return nil, err
	}
	return queryItem(id, ts, qt, rc, domain, resp, route, tag, prefetch, elapsed, exit), nil
}

func openDomainExport(ctx context.Context, db *sql.DB, limit int) (*exportCursor, error) {
	rows, err := db.QueryContext(ctx, "SELECT domain,first_seen_at,last_seen_at,occurrence_count,COALESCE(fail_count,0),last_rcode,last_route FROM domains ORDER BY occurrence_count DESC, domain ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	return &exportCursor{rows: rows, item: scanDomainItem}, nil
}

func scanDomainItem(rows *sql.Rows) (map[string]any, error) {
	var d, lr sql.NullString
	var first, last, count, fail, rcode sql.NullInt64
	if err := rows.Scan(&d, &first, &last, &count, &fail, &rcode, &lr); err != nil {
		return nil, err
	}
	return domainItem(d, first, last, count, fail, rcode, lr), nil
}

func exportStream(w http.ResponseWriter, r *http.Request) (io.Writer, func()) {
	if clientAcceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
		zw := gzip.NewWriter(w)
		buffered := bufio.NewWriterSize(zw, 32*1024)
		return buffered, func() { buffered.Flush(); zw.Close() }
	}
	w.WriteHeader(http.StatusOK)
	buffered := bufio.NewWriterSize(w, 32*1024)
	return buffered, func() { buffered.Flush() }
}

func streamExportJSON(w io.Writer, cursor *exportCursor) error {
	if _, err := w.Write([]byte("[")); err != nil {
		return err
	}
	var line bytes.Buffer
	encoder := json.NewEncoder(&line)
	encoder.SetEscapeHTML(false)
	first := true
	if err := cursor.each(func(item map[string]any) error {
		line.Reset()
		if err := encoder.Encode(item); err != nil {
			return err
		}
		if !first {
			if _, err := w.Write([]byte(",")); err != nil {
				return err
			}
		}
		first = false
		_, err := w.Write(bytes.TrimRight(line.Bytes(), "\n"))
		return err
	}); err != nil {
		return err
	}
	_, err := w.Write([]byte("]\n"))
	return err
}

func streamExportCSV(w io.Writer, columns []string, cursor *exportCursor) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(columns); err != nil {
		return err
	}
	record := make([]string, len(columns))
	if err := cursor.each(func(item map[string]any) error {
		for i, column := range columns {
			record[i] = exportCSVValue(item[column])
		}
		return writer.Write(record)
	}); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func writeExportJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(v)
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
	rows, err := db.QueryContext(r.Context(), "SELECT domain, COUNT(*) AS c FROM query_events WHERE ts >= ? AND rcode NOT IN (0,3) GROUP BY domain", since)
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
