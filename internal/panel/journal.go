package panel

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type logEntry struct {
	T     int64  `json:"t"`
	Unit  string `json:"unit"`
	Level int    `json:"lvl"`
	Noise bool   `json:"noise,omitempty"`
	Msg   string `json:"msg"`
	Raw   string `json:"raw"`

	cursor string
}

var (
	unboundPrefix = regexp.MustCompile(`^\[\d+\] unbound\[[\d:]+\] (\w+): `)
	goLogPrefix   = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
	levelPrefix   = regexp.MustCompile(`^(?i)(\[(错误|警告|信息)\]|(error|fatal|panic|warn|warning)\s*:)\s*`)
)

var scannerNoise = []string{
	"TLS handshake error",
	"invalid path",
	"client sent an HTTP request to an HTTPS server",
}

func parseJournal(stdout string) []logEntry {
	out := []logEntry{}
	for _, line := range strings.Split(stdout, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		out = append(out, journalEntry(rec))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

func journalEntry(rec map[string]any) logEntry {
	field := func(key string) string {
		v, _ := rec[key].(string)
		return v
	}
	raw := field("MESSAGE")
	e := logEntry{Raw: raw, Msg: raw, cursor: field("__CURSOR")}
	if us, err := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		e.T = us / 1000
	}
	unit := field("_SYSTEMD_UNIT")
	if unit == "" || unit == "init.scope" {
		unit = field("UNIT")
	}
	e.Unit = strings.TrimSuffix(unit, ".service")
	if p, err := strconv.Atoi(field("PRIORITY")); err == nil && p <= 4 {
		e.Level = 1
		if p <= 3 {
			e.Level = 2
		}
	}
	lvl := 0
	switch {
	case strings.HasPrefix(raw, "{"):
		lvl, e.Msg = formatStructured(raw)
	case unboundPrefix.MatchString(raw):
		m := unboundPrefix.FindStringSubmatch(raw)
		lvl, e.Msg = wordLevel(m[1]), raw[len(m[0]):]
	default:
		msg := goLogPrefix.ReplaceAllString(raw, "")
		if m := levelPrefix.FindStringSubmatch(msg); m != nil {
			lvl = wordLevel(strings.Trim(strings.ToLower(m[1]), "[]: "))
			msg = msg[len(m[0]):]
		}
		e.Msg = msg
		if field("SYSLOG_IDENTIFIER") == "systemd" && (strings.Contains(raw, "Failed") || strings.Contains(raw, "FAILURE")) {
			lvl = 2
		}
	}
	e.Level = max(e.Level, lvl)
	for _, needle := range scannerNoise {
		if strings.Contains(raw, needle) {
			e.Noise, e.Level = true, 0
			break
		}
	}
	return e
}

func wordLevel(word string) int {
	switch strings.ToLower(word) {
	case "error", "err", "fatal", "panic", "crit", "错误":
		return 2
	case "warn", "warning", "警告":
		return 1
	}
	return 0
}

var structuredSkip = map[string]bool{"level": true, "time": true, "message": true, "msg": true, "caller": true, "module": true}

func formatStructured(raw string) (int, string) {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return 0, raw
	}
	level, _ := m["level"].(string)
	msg, _ := m["message"].(string)
	if inner, ok := m["msg"].(string); ok && inner != "" {
		if msg == "" || msg == "redirected http log" {
			msg = inner
		} else {
			msg += ": " + inner
		}
	}
	parts := []string{}
	if module, ok := m["module"].(string); ok && module != "" {
		parts = append(parts, "["+module+"]")
	}
	if msg != "" {
		parts = append(parts, msg)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if !structuredSkip[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, flattenField(k, m[k])...)
	}
	return wordLevel(level), strings.Join(parts, " ")
}

func flattenField(key string, value any) []string {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			if k != "ua" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		out := []string{}
		for _, k := range keys {
			out = append(out, flattenField(k, v[k])...)
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		if strings.ContainsAny(v, " \t") {
			return []string{key + "=" + strconv.Quote(v)}
		}
		return []string{key + "=" + v}
	case nil:
		return nil
	default:
		b, _ := json.Marshal(v)
		return []string{key + "=" + string(b)}
	}
}
