package panel

import (
	"net/http"
	"os"

	"github.com/dns-stack/dns-stack/internal/stack"
)

func (s *Server) modules(w http.ResponseWriter, r *http.Request) {
	role := s.role()
	list := stack.ForRole(role)
	units := make([]string, 0, len(list))
	for _, m := range list {
		units = append(units, m.Unit)
	}
	raw := s.serviceStatus(r, units)
	byUnit := make(map[string]map[string]any, len(raw))
	for _, item := range raw {
		entry, _ := item.(map[string]any)
		if unit, _ := entry["unit"].(string); unit != "" {
			byUnit[unit] = entry
		}
	}

	now := s.now()
	counts := map[string]int{stack.StateOK: 0, stack.StateWarn: 0, stack.StateDown: 0, stack.StateUnknown: 0}
	impl := map[string]int{}
	grouped := map[string][]any{}
	groupState := map[string]string{}
	overall := stack.StateOK
	attention := []string{}

	for _, m := range list {
		status := readStatus(byUnit[m.Unit])
		state, note := stack.Evaluate(m, status, now)
		counts[state]++
		impl[string(m.Impl)]++
		grouped[m.Group] = append(grouped[m.Group], moduleItem(s, m, status, state, note))
		groupState[m.Group] = stack.Worse(groupState[m.Group], state)
		switch state {
		case stack.StateUnknown:
			overall = stack.Worse(overall, stack.StateUnknown)
		case stack.StateWarn, stack.StateDown:
			overall = stack.Worse(overall, stack.StateWarn)
			attention = append(attention, m.Name+"："+note)
		}
		if state == stack.StateDown && m.Critical {
			overall = stack.StateDown
		}
	}

	groups := make([]any, 0, len(stack.GroupOrder))
	for _, name := range stack.GroupOrder {
		items := grouped[name]
		if len(items) == 0 {
			continue
		}
		state := groupState[name]
		if state == "" {
			state = stack.StateOK
		}
		groups = append(groups, map[string]any{"name": name, "state": state, "modules": items})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"role":      role,
		"verdict":   overall,
		"headline":  stack.Headline(overall, len(attention)),
		"total":     len(list),
		"counts":    counts,
		"impl":      impl,
		"attention": attention,
		"groups":    groups,
	})
}

func readStatus(entry map[string]any) stack.Status {
	if entry == nil {
		return stack.Status{Unreachable: true}
	}
	if _, failed := entry["error"]; failed {
		return stack.Status{Unreachable: true}
	}
	status := stack.Status{}
	status.Active, _ = entry["active"].(string)
	status.TimerActive, _ = entry["timer_active"].(string)
	status.LastResult, _ = entry["last_result"].(string)
	status.LastRun = unixValue(entry["last_trigger"], entry["since"])
	status.NextRun = unixValue(entry["next"])
	status.Memory = unixValue(entry["memory"])
	status.Restarts = int(unixValue(entry["restarts"]))
	return status
}

func moduleItem(s *Server, m stack.Module, st stack.Status, state, note string) map[string]any {
	item := map[string]any{
		"unit": m.Unit, "name": m.Name, "group": m.Group, "purpose": m.Purpose,
		"kind": string(m.Kind), "impl": string(m.Impl), "critical": m.Critical,
		"state": state, "note": note, "active": st.Active,
		"last_run": nilIfZero(st.LastRun), "next_run": nilIfZero(st.NextRun),
		"memory": nilIfZero(st.Memory), "restarts": st.Restarts,
	}
	if m.Every > 0 {
		item["every_seconds"] = int64(m.Every.Seconds())
	}
	if m.Artifact != "" {
		item["artifact"] = s.artifactInfo(m.Artifact)
	}
	return item
}

func (s *Server) artifactInfo(rel string) map[string]any {
	out := map[string]any{"path": rel, "exists": false, "mtime": nil, "lines": nil}
	info, err := os.Stat(s.statePath(rel))
	if err != nil {
		return out
	}
	out["exists"] = true
	out["mtime"] = info.ModTime().Unix()
	out["size"] = info.Size()
	if !info.IsDir() {
		out["lines"] = countLines(s.statePath(rel))
	}
	return out
}

func nilIfZero(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func unixValue(values ...any) int64 {
	for _, value := range values {
		switch typed := value.(type) {
		case int64:
			if typed > 0 {
				return typed
			}
		case int:
			if typed > 0 {
				return int64(typed)
			}
		case float64:
			if typed > 0 {
				return int64(typed)
			}
		}
	}
	return 0
}
