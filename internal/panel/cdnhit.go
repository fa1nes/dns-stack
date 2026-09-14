package panel

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnhit"
	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/rulesync"
)

const cdnHitTTL = 90 * time.Second

type cdnHitCache struct {
	mu     sync.Mutex
	at     time.Time
	subnet string
	report cdnhit.Report
}

func (s *Server) cdnHit(w http.ResponseWriter, r *http.Request) {
	subnet := r.URL.Query().Get("subnet")
	if subnet == "" {
		subnet = cdnhit.BeijingTelecom
	}
	refresh := r.URL.Query().Get("refresh") == "1"

	s.cdnHits.mu.Lock()
	defer s.cdnHits.mu.Unlock()
	if !refresh && s.cdnHits.subnet == subnet && s.now().Sub(s.cdnHits.at) < cdnHitTTL {
		writeJSON(w, 200, s.cdnHits.report)
		return
	}

	set, err := cdnrules.Load(rulesync.CDNPath(s.cfg.StateDir))
	if err != nil {
		writeJSON(w, 503, map[string]any{
			"error": "读不到 CDN 直连规则集，命中判据无法回答任何问题: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := cdnhit.Run(ctx, cdnhit.Options{
		Subnet: subnet, Set: set, Timeout: 5 * time.Second, Now: s.now,
	})
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	s.cdnHits.at, s.cdnHits.subnet, s.cdnHits.report = s.now(), subnet, report
	writeJSON(w, 200, report)
}
