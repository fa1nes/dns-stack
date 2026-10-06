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
	key     string
	result  map[string]any
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
	subnets := []string{}
	if r.URL.Query().Get("all") == "1" {
		for _, item := range cdnhit.Vantages {
			subnets = append(subnets, item.Prefix)
		}
	} else {
		subnet := r.URL.Query().Get("subnet")
		if subnet == "" {
			subnet = cdnhit.BeijingTelecom
		}
		known := false
		for _, item := range cdnhit.Vantages {
			known = known || item.Prefix == subnet
		}
		if !known {
			writeJSON(w, 400, map[string]any{
				"error": "客户端子网只接受内置的观测点，面板不是任意网段的探测入口"})
			return
		}
		subnets = append(subnets, subnet)
	}
	key := fmt.Sprint(subnets)
	refresh := r.URL.Query().Get("refresh") == "1"
	fresh := r.URL.Query().Get("fresh") == "1"
	if fresh && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error": "清缓存重查会改动解析缓存，只接受 POST"})
		return
	}

	s.cdnHits.mu.Lock()
	defer s.cdnHits.mu.Unlock()
	if !refresh && !fresh && s.cdnHits.key == key && s.now().Sub(s.cdnHits.at) < cdnHitTTL {
		writeJSON(w, 200, s.cdnHits.result)
		return
	}
	if fresh {
		if wait := cdnFreshWindow - s.now().Sub(s.cdnHits.freshAt); !s.cdnHits.freshAt.IsZero() && wait > 0 {
			writeJSON(w, 429, map[string]any{
				"error": fmt.Sprintf("复核会清掉这些热门域名的缓存，%d 分钟内只能做一次，还要等 %d 秒",
					int(cdnFreshWindow/time.Minute), int(wait.Seconds())),
				"retry_after": int(wait.Seconds())})
			return
		}
	}

	set, err := cdnrules.Load(cdnrules.Path(s.cfg.StateDir))
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "读不到 CDN 规则集: " + err.Error()})
		return
	}
	mainland, err := cdnhit.LoadMainland(filepath.Join(s.cfg.StateDir, "chnroute", "direct4.txt"))
	if err != nil {
		mainland = nil
	}
	timeout := 40 * time.Second
	if fresh {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	opt := cdnhit.Options{Set: set, Mainland: mainland, Timeout: 5 * time.Second, Now: s.now}
	if fresh {
		opt.Flush = cdnHitFlusher()
	}
	reports, err := cdnhit.RunAll(ctx, opt, subnets)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	for r := range reports {
		for i := range reports[r].Probes {
			if addrs := reports[r].Probes[i].Addrs; len(addrs) > 0 {
				if label, _ := s.geoLookup(addrs[0])["label"].(string); label != "" {
					reports[r].Probes[i].Geo = label
				}
			}
		}
	}
	if fresh {
		s.cdnHits.freshAt = s.now()
		mainlandHits, total := 0, 0
		for _, report := range reports {
			mainlandHits += report.Mainland
			total += len(report.Probes)
		}
		s.writeAudit("cdn_hit_fresh", map[string]any{"subnets": subnets}, true,
			fmt.Sprintf("清缓存复核 %d 项：国内节点 %d", total, mainlandHits))
	}
	vantages := []map[string]string{}
	for _, item := range cdnhit.Vantages {
		for _, subnet := range subnets {
			if item.Prefix == subnet {
				vantages = append(vantages, map[string]string{"prefix": item.Prefix, "label": item.Label})
			}
		}
	}
	result := map[string]any{"vantages": vantages, "reports": reports, "fresh": fresh, "generated_at": s.now().Unix()}
	s.cdnHits.at, s.cdnHits.key, s.cdnHits.result = s.now(), key, result
	writeJSON(w, 200, result)
}
