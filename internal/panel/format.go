package panel

import (
	"database/sql"
	"encoding/json"
	"github.com/dns-stack/dns-stack/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

func (s *Server) role() string {
	cfg := s.readConfig()
	if v := cfg["ROLE"]; v != "" {
		return v
	}
	return "unknown"
}

func (s *Server) readConfig() map[string]string {
	return config.Read(s.cfg.ConfigPath)
}

func (s *Server) openDB() (*sql.DB, error) {
	path := s.cfg.DBPath
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=busy_timeout(3000)"
	return sql.Open("sqlite", dsn)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func parseInt(v string, d int) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

var qtypeNames = map[int64]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA"}

var rcodeNames = map[int64]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS"}

var routeNames = map[string]string{"cn": "本机递归", "foreign": "香港递归", "cache": "缓存命中", "recursive": "本机递归", "reject": "已拒绝", "failed": "无人应答", "unknown": "未知"}

func qtypeName(n int64) string {
	if x := qtypeNames[n]; x != "" {
		return x
	}
	return strconv.FormatInt(n, 10)
}

func rcodeName(n int64) string {
	if x := rcodeNames[n]; x != "" {
		return x
	}
	return strconv.FormatInt(n, 10)
}

func routeName(v string) string {
	if x := routeNames[v]; x != "" {
		return x
	}
	if v == "" {
		return "未知"
	}
	return v
}

func routeNameEnrich(v string) string {
	if x := routeNames[v]; x != "" {
		return x
	}
	return v
}

func parseType(v string) int {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	upper := strings.ToUpper(v)
	for code, name := range qtypeNames {
		if name == upper {
			return int(code)
		}
	}
	return -1
}

func parseRcode(v string) int {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	upper := strings.ToUpper(v)
	for code, name := range rcodeNames {
		if name == upper {
			return int(code)
		}
	}
	return -1
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

func percentage(value, total float64) float64 {
	if total == 0 {
		return 0
	}
	return roundTo(value/total*100, 2)
}

func optionalStat(stats map[string]float64, key string) any {
	if value, ok := stats[key]; ok {
		return int(value)
	}
	return nil
}
