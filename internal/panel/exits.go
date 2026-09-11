package panel

import (
	"context"
	"sync"
	"time"
)

const exitTTL = 300 * time.Second

type exitCache struct {
	mu   sync.Mutex
	at   time.Time
	info map[string]any
}

func (s *Server) exitAddresses(ctx context.Context) map[string]any {
	s.exits.mu.Lock()
	if s.exits.info != nil && s.now().Sub(s.exits.at) < exitTTL {
		info := s.exits.info
		s.exits.mu.Unlock()
		return info
	}
	s.exits.mu.Unlock()

	resp, err := helperCall(ctx, "network_exits", map[string]any{"interface": "wg0"})
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}
	}
	if !boolValue(resp["ok"]) {
		message, _ := resp["message"].(string)
		if message == "" {
			message = "helper 调用失败"
		}
		return map[string]any{"available": false, "error": message}
	}
	data := helperData(resp)
	publicV4, _ := data["public_ipv4"].(string)
	tunnelPeer, _ := data["tunnel_peer"].(string)
	info := map[string]any{
		"available":  true,
		"direct":     s.exitGeoLabel(publicV4),
		"tunnel":     s.exitGeoLabel(tunnelPeer),
		"direct_ip":  publicV4,
		"tunnel_ip":  tunnelPeer,
		"direct_geo": s.exitGeoInfo(publicV4),
		"tunnel_geo": s.exitGeoInfo(tunnelPeer),

		"tunnel_note": data["tunnel_peer_note"],
	}
	s.exits.mu.Lock()
	s.exits.at, s.exits.info = s.now(), info
	s.exits.mu.Unlock()
	return info
}

func (s *Server) exitGeoLabel(ip string) any {
	geo := s.exitGeoInfo(ip)
	if label, ok := geo["label"].(string); ok && label != "" {
		return label
	}
	if ip == "" {
		return nil
	}
	return "归属库未收录"
}

// exitGeoInfo 返回结构化的出口归属（含 IP），供面板直接展示出口线路。
func (s *Server) exitGeoInfo(ip string) map[string]any {
	geo := map[string]any{"ip": ip, "available": false}
	if ip == "" {
		return geo
	}
	result := s.geoLookup(ip)
	if available, _ := result["available"].(bool); available {
		geo["available"] = true
		if label, ok := result["label"].(string); ok && label != "" {
			geo["label"] = label
		}
		if country, ok := result["country"].(string); ok && country != "" {
			geo["country"] = country
		}
	}
	return geo
}

func (s *Server) geoipStatus() map[string]any {
	s.geoMu.Lock()
	if s.geo == nil {
		s.geo = newPanelGeoDB(s)
	}
	db := s.geo
	s.geoMu.Unlock()
	if db == nil {
		return map[string]any{"available": false, "degraded": false, "error": "归属模块不可用"}
	}
	status := db.Status()

	for _, kind := range []string{"asn", "city", "cnip"} {
		entry, ok := status[kind].(map[string]any)
		if !ok {
			continue
		}
		if message, ok := entry["error"].(string); ok && message == "" {
			entry["error"] = nil
		}
	}
	return status
}
