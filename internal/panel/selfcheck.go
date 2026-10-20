package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const selfcheckTimeout = 100 * time.Second

func (s *Server) selfcheck(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.checkMu.Lock()
		last := s.lastCheck
		s.checkMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"report": last})
	case http.MethodPost:
		ctx, cancel := context.WithTimeout(r.Context(), selfcheckTimeout)
		defer cancel()
		resp, err := helperCall(ctx, "healthcheck", nil)
		data := helperData(resp)
		stdout, _ := data["stdout"].(string)
		var report map[string]any
		if err != nil || json.Unmarshal([]byte(strings.TrimSpace(stdout)), &report) != nil || report["results"] == nil {
			message, _ := data["stderr"].(string)
			if err != nil {
				message = err.Error()
			}
			if strings.TrimSpace(message) == "" {
				message = "健康检查没有返回结果"
			}
			s.writeAudit("healthcheck", map[string]any{}, false, message)
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": strings.TrimSpace(message)})
			return
		}
		report["at"] = s.now().Unix()
		s.checkMu.Lock()
		s.lastCheck = report
		s.checkMu.Unlock()
		fail := numberValue(report["fail"])
		summary := "通过 " + jsonNumber(report["ok"]) + " 项，警告 " + jsonNumber(report["warn"]) + " 项，失败 " + jsonNumber(report["fail"]) + " 项"
		s.writeAudit("healthcheck", map[string]any{}, fail == 0, summary)
		writeJSON(w, http.StatusOK, map[string]any{"ok": fail == 0, "report": report, "message": summary})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func jsonNumber(v any) string {
	encoded, _ := json.Marshal(v)
	return string(encoded)
}
