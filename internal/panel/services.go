package panel

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

func (s *Server) watchedUnits() []string {
	return stack.UnitsForRole(s.role())
}

func (s *Server) watchedUnit(unit string) bool {
	for _, u := range s.watchedUnits() {
		if u == unit {
			return true
		}
	}
	return false
}

type svcCacheEntry struct {
	at   time.Time
	item map[string]any
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"services": s.serviceStatus(r, s.watchedUnits())})
}

func (s *Server) serviceStatus(r *http.Request, units []string) []any {
	now := time.Now()
	s.svcMu.Lock()
	if s.svcCache == nil {
		s.svcCache = map[string]svcCacheEntry{}
	}
	need := []string{}
	for _, unit := range units {
		entry, ok := s.svcCache[unit]
		if !ok || now.Sub(entry.at) >= 3*time.Second {
			need = append(need, unit)
		}
	}
	s.svcMu.Unlock()

	if len(need) > 0 {

		results := make([]map[string]any, len(need))
		var wg sync.WaitGroup
		for i, unit := range need {
			wg.Add(1)
			go func(i int, unit string) {
				defer wg.Done()
				resp, err := helperCall(r.Context(), "service_status", map[string]any{"unit": unit})
				if err != nil {

					return
				}
				results[i] = parseServiceProps(unit, resp)
			}(i, unit)
		}
		wg.Wait()
		s.svcMu.Lock()
		for i, unit := range need {
			if results[i] != nil {
				s.svcCache[unit] = svcCacheEntry{at: now, item: results[i]}
			}
		}
		s.svcMu.Unlock()
	}

	out := make([]any, 0, len(units))
	s.svcMu.Lock()
	defer s.svcMu.Unlock()
	for _, unit := range units {
		if entry, ok := s.svcCache[unit]; ok {
			out = append(out, entry.item)
			continue
		}
		out = append(out, map[string]any{"unit": unit, "active": "unknown", "sub": "", "since": nil, "memory": nil, "restarts": nil, "error": "查询失败"})
	}
	return out
}

var servicePropRe = regexp.MustCompile(`^([A-Za-z]+)=(.*)$`)

func parseServiceProps(unit string, resp map[string]any) map[string]any {
	entry := map[string]any{"unit": unit, "active": "unknown", "sub": "", "since": nil,
		"memory": nil, "restarts": nil, "next": nil, "last_trigger": nil, "last_result": nil}
	if ok, _ := resp["ok"].(bool); !ok {
		entry["error"] = resp["message"]
		return entry
	}
	data, _ := resp["data"].(map[string]any)
	stdout, _ := data["stdout"].(string)
	blocks := []map[string]string{}
	props := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(props) > 0 {
				blocks = append(blocks, props)
				props = map[string]string{}
			}
			continue
		}
		m := servicePropRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		props[m[1]] = m[2]
	}
	if len(props) > 0 {
		blocks = append(blocks, props)
	}
	service, timer := map[string]string{}, map[string]string{}
	for _, block := range blocks {
		if block["Id"] == unit+".service" && len(service) == 0 {
			service = block
		}
		if block["Id"] == unit+".timer" && len(timer) == 0 {
			timer = block
		}
	}
	for key, value := range service {
		switch key {
		case "ActiveState":
			entry["active"] = value
		case "SubState":
			entry["sub"] = value
		case "ExecMainStartTimestamp":
			entry["since"] = epochSeconds(value)
		case "MemoryCurrent":
			if isDigits(value) {
				entry["memory"] = parseInt(value, 0)
			}
		case "NRestarts":
			if isDigits(value) {
				entry["restarts"] = parseInt(value, 0)
			}
		}
	}
	if timer["LoadState"] == "loaded" {
		entry["timer_active"] = propGet(timer, "ActiveState")
		entry["timer_sub"] = propGet(timer, "SubState")
		entry["next"] = timerSeconds(timer["NextElapseUSecRealtime"])
		entry["last_trigger"] = timerSeconds(timer["LastTriggerUSec"])
		entry["last_result"] = propOrNil(service, "Result")
		if entry["active"] == "inactive" && timer["ActiveState"] == "active" {
			entry["active"] = "waiting"
			entry["sub"] = timer["SubState"]
			if status := service["ExecMainStatus"]; status != "" && status != "0" {
				entry["active"] = "failed"
			}
		}
	}
	return entry
}

func epochSeconds(value string) any { return nilIfZero(stack.ServiceStamp(value)) }

func timerSeconds(value string) any { return nilIfZero(stack.TimerStamp(value)) }

func propGet(props map[string]string, key string) any {
	if value, ok := props[key]; ok {
		return value
	}
	return nil
}

func propOrNil(props map[string]string, key string) any {
	if value := props[key]; value != "" {
		return value
	}
	return nil
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
