package panel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "数据库不可用", "items": []any{}})
		return
	}
	defer db.Close()
	limit := parseInt(r.URL.Query().Get("limit"), 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(r.Context(), "SELECT id,ts,actor,operation,args,ok,message FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "查询失败", "items": []any{}})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ts int64
		var actor, op, args, msg string
		var ok int
		if err := rows.Scan(&id, &ts, &actor, &op, &args, &ok, &msg); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "查询失败", "items": []any{}})
			return
		}
		if args == "{}" {
			args = ""
		}
		items = append(items, map[string]any{"id": id, "ts": ts, "actor": actor, "operation": op,
			"label": auditLabel(op, args), "args": args, "ok": ok, "message": msg})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "查询失败", "items": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

var auditOnlyLabels = map[string]string{
	"revoke_sessions":       "让其它设备退出",
	"set_panel_username":    "修改用户名",
	"set_panel_password":    "修改密码",
	"set_oauth_config":      "配置 GitHub 登录",
	"set_password_disabled": "开关密码登录",
	"enable_totp":           "启用二次认证",
	"disable_totp":          "停用二次认证",
	"mark_oauth_verified":   "GitHub 首次登录",
	"cdn_hit_fresh":         "CDN 就近复核",
	"audit_clear":           "清空审计记录",
}

var routeListLabels = map[string]string{"cn": "国内解析", "hk": "香港解析"}

func auditLabel(op, args string) string {
	if verb := map[string]string{"route_add": "加入", "route_remove": "移出"}[op]; verb != "" {
		var parsed struct {
			List string `json:"list"`
		}
		if json.Unmarshal([]byte(args), &parsed) == nil && routeListLabels[parsed.List] != "" {
			return verb + routeListLabels[parsed.List]
		}
	}
	if spec, ok := operationSpecs[op]; ok {
		return spec.Label
	}
	if label := accessActions[op]; label != "" {
		return label
	}
	if label := auditOnlyLabels[op]; label != "" {
		return label
	}
	return op
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.rulesInfo())
}

func (s *Server) cert(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "cert_info", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"exists": false, "error": err.Error()})
		return
	}
	data := helperData(resp)
	if data["returncode"] != float64(0) {
		writeJSON(w, 200, map[string]any{"exists": false, "error": data["stderr"]})
		return
	}
	stdout, _ := data["stdout"].(string)
	writeJSON(w, 200, parseCertInfo(stdout, s.now()))
}

func parseCertInfo(stdout string, now time.Time) map[string]any {
	info := map[string]any{"exists": true}
	var san []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && (k == "notAfter" || k == "notBefore" || k == "issuer") {
			info[strings.ToLower(strings.ReplaceAll(k, "not", "not_"))] = strings.TrimSpace(v)
			continue
		}
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			for _, prefix := range []string{"IP Address:", "DNS:"} {
				if strings.HasPrefix(part, prefix) {
					san = append(san, strings.TrimSpace(strings.TrimPrefix(part, prefix)))
				}
			}
		}
	}
	if len(san) > 0 {
		info["san"] = strings.Join(san, ", ")
	}
	if raw, _ := info["not_after"].(string); raw != "" {
		if expiry, err := time.Parse("Jan _2 15:04:05 2006 MST", raw); err == nil {
			info["days_left"] = int(expiry.Sub(now).Hours() / 24)
			info["expires_at"] = expiry.Unix()
		}
	}
	return info
}

func (s *Server) cache(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "cache_info", nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	var out map[string]any
	if json.Unmarshal([]byte(stdout), &out) != nil {
		writeJSON(w, 503, map[string]any{"error": "缓存配置返回格式异常"})
		return
	}
	out["note"] = "Unbound 侧改动立即生效；mosproxy 的缓存配置只在启动时读取，改完需要重启 mosproxy 才会生效"
	writeJSON(w, 200, out)
}

func (s *Server) doh(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "doh_info", nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	out := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if out["doh_url"] == nil {
		writeJSON(w, 503, map[string]any{"error": "DoH 配置返回格式异常"})
		return
	}
	out["is_default"] = out["doh_path_is_default"] == "1"
	delete(out, "doh_path_is_default")
	delete(out, "doh_path")
	writeJSON(w, 200, out)
}

func (s *Server) backups(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "list_backups", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"backups": []any{}, "exports": []any{}, "error": err.Error(), "policy": s.backupPolicy()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	var out map[string]any
	if json.Unmarshal([]byte(stdout), &out) != nil {
		reason, _ := resp["message"].(string)
		if reason == "" {
			reason = "无法读取备份目录"
		}
		out = map[string]any{"backups": []any{}, "exports": []any{}, "error": reason}
	}
	out["policy"] = s.backupPolicy()
	writeJSON(w, 200, out)
}

func (s *Server) backupPolicy() map[string]any {
	cfg := s.readConfig()
	number := func(key string, fallback, min int) int {
		value, err := strconv.Atoi(strings.TrimSpace(cfg[key]))
		if err != nil || value < min {
			return fallback
		}
		return value
	}
	return map[string]any{
		"interval_hours": number("BACKUP_INTERVAL_HOURS", 24, 0),
		"keep_daily":     number("BACKUP_RETENTION_DAILY", 3, 1),
		"keep_weekly":    number("BACKUP_RETENTION_WEEKLY", 2, 1),
	}
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "mosproxy"
	}

	if !s.watchedUnit(unit) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的服务: " + unit})
		return
	}
	lines := parseInt(r.URL.Query().Get("lines"), 200)
	if lines < 1 || lines > 2000 {
		lines = 200
	}
	args := map[string]any{"unit": unit, "lines": lines}
	if v := r.URL.Query().Get("priority"); v != "" {
		args["priority"] = v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		args["since"] = v
	}
	resp, err := helperCall(r.Context(), "logs", args)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error(), "lines": []string{}})
		return
	}
	if ok, _ := resp["ok"].(bool); !ok {
		writeJSON(w, 503, map[string]any{"error": resp["message"], "lines": []string{}})
		return
	}
	data, _ := resp["data"].(map[string]any)
	stdout, _ := data["stdout"].(string)
	if numberValue(data["returncode"]) != 0 && stdout == "" {
		message := "读取日志失败"
		if stderr, ok := data["stderr"].(string); ok && stderr != "" {
			message = stderr
		}
		writeJSON(w, 503, map[string]any{"error": message, "lines": []string{}})
		return
	}
	out := []string{}
	needle := strings.ToLower(r.URL.Query().Get("search"))
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) != "" && (needle == "" || strings.Contains(strings.ToLower(line), needle)) {
			out = append(out, line)
		}
	}
	writeJSON(w, 200, map[string]any{"unit": unit, "lines": out, "count": len(out)})
}

func (s *Server) logsStream(w http.ResponseWriter, r *http.Request) {
	extendReadDeadline(w, 0)
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "mosproxy"
	}

	if !s.watchedUnit(unit) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的服务: " + unit})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	priority := r.URL.Query().Get("priority")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	seen := map[string]bool{}
	order := []string{}
	first := true
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			args := map[string]any{"unit": unit, "lines": 100}
			if priority != "" {
				args["priority"] = priority
			}
			resp, err := helperCall(r.Context(), "logs", args)
			respOK := false
			if err == nil {
				respOK, _ = resp["ok"].(bool)
			}
			if err != nil || !respOK {
				var message any
				if err != nil {
					message = err.Error()
				} else {
					message = resp["message"]
				}
				payload, _ := json.Marshal(map[string]any{"error": message})
				_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
				fl.Flush()
				continue
			}
			data, _ := resp["data"].(map[string]any)
			stdout, _ := data["stdout"].(string)
			lines := []string{}
			for _, line := range strings.Split(stdout, "\n") {
				if strings.TrimSpace(line) != "" && !seen[line] {
					seen[line] = true
					order = append(order, line)
					lines = append(lines, line)
				}
			}

			if len(order) > 3000 {
				for _, old := range order[:len(order)-1500] {
					delete(seen, old)
				}
				order = append([]string{}, order[len(order)-1500:]...)
			}
			if len(lines) > 0 {

				if first && len(lines) > 100 {
					lines = lines[len(lines)-100:]
				}
				first = false
				payload, _ := json.Marshal(map[string]any{"lines": lines})
				_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
			} else {
				_, _ = w.Write([]byte(": keepalive\n\n"))
			}
			fl.Flush()
		}
	}
}
