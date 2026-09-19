package panel

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnhit"
	"github.com/dns-stack/dns-stack/internal/cdnrules"
)

const (
	cdnHitTTL      = 90 * time.Second
	cdnFreshWindow = 10 * time.Minute
)

type cdnHitCache struct {
	mu      sync.Mutex
	at      time.Time
	freshAt time.Time
	subnet  string
	report  cdnhit.Report
}

func cdnHitFlusher() cdnhit.Flusher {
	return func(ctx context.Context, name string) error {
		resp, err := helperCall(ctx, "flush_cache", map[string]any{"domain": name, "confirm": true})
		if err != nil {
			return err
		}
		data := helperData(resp)
		if !boolValue(resp["ok"]) || numberValue(data["returncode"]) != 0 {
			message, _ := data["stderr"].(string)
			if message == "" {
				message, _ = resp["message"].(string)
			}
			if message == "" {
				message = "助手拒绝了清缓存请求"
			}
			return fmt.Errorf("%s", message)
		}
		return nil
	}
}

func (s *Server) cdnHit(w http.ResponseWriter, r *http.Request) {
	subnet := r.URL.Query().Get("subnet")
	if subnet == "" {
		subnet = cdnhit.BeijingTelecom
	}
	known := false
	for _, item := range cdnhit.Vantages {
		if item.Prefix == subnet {
			known = true
			break
		}
	}
	if !known {
		writeJSON(w, 400, map[string]any{
			"error": "客户端子网只接受内置的观测点，面板不是任意网段的探测入口"})
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	fresh := r.URL.Query().Get("fresh") == "1"

	s.cdnHits.mu.Lock()
	defer s.cdnHits.mu.Unlock()
	if !refresh && !fresh && s.cdnHits.subnet == subnet && s.now().Sub(s.cdnHits.at) < cdnHitTTL {
		writeJSON(w, 200, s.cdnHits.report)
		return
	}
	if fresh {
		if wait := cdnFreshWindow - s.now().Sub(s.cdnHits.freshAt); !s.cdnHits.freshAt.IsZero() && wait > 0 {
			writeJSON(w, 429, map[string]any{
				"error": fmt.Sprintf(
					"清缓存重查会让这些热门域名下一次解析走完整递归，%d 分钟内只允许一次，还需等待 %d 秒",
					int(cdnFreshWindow/time.Minute), int(wait.Seconds())),
				"retry_after": int(wait.Seconds())})
			return
		}
	}

	set, err := cdnrules.Load(cdnrules.Path(s.cfg.StateDir))
	if err != nil {
		writeJSON(w, 503, map[string]any{
			"error": "读不到 CDN 直连规则集，命中判据无法回答任何问题: " + err.Error()})
		return
	}
	mainland, err := cdnhit.LoadMainland(filepath.Join(s.cfg.StateDir, "chnroute", "direct4.txt"))
	if err != nil {
		mainland = nil
	}
	timeout := 30 * time.Second
	if fresh {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	opt := cdnhit.Options{
		Subnet: subnet, Set: set, Mainland: mainland, Timeout: 5 * time.Second, Now: s.now,
	}
	if fresh {
		opt.Flush = cdnHitFlusher()
	}
	report, err := cdnhit.Run(ctx, opt)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	if fresh {
		s.cdnHits.freshAt = s.now()
		s.writeAudit("cdn_hit_fresh", map[string]any{"subnet": subnet}, true,
			fmt.Sprintf("清缓存重查 %d 个域名：就近命中 %d，ECS 未送达 %d",
				len(report.Probes), report.Mainland, report.NotDelivered))
	}
	s.cdnHits.at, s.cdnHits.subnet, s.cdnHits.report = s.now(), subnet, report
	writeJSON(w, 200, report)
}
