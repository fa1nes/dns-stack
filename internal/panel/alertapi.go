package panel

import (
	"net/http"
	"strings"

	"github.com/dns-stack/dns-stack/internal/alert"
)

func (s *Server) alertInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	webhook := strings.TrimSpace(s.readConfig()["ALERT_WEBHOOK"])
	writeJSON(w, http.StatusOK, map[string]any{"configured": webhook != "", "endpoint": alert.MaskWebhook(webhook)})
}
