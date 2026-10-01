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

	"github.com/dns-stack/dns-stack/internal/dnswire"
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

var rcodeNames = map[int64]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS"}

var routeNames = map[string]string{"cn": "本机递归", "foreign": "香港递归", "cache": "缓存命中", "recursive": "本机递归", "reject": "已拒绝", "failed": "无人应答", "unknown": "未知"}

func qtypeName(n int64) string { return dnswire.TypeName(uint16(n)) }

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

func parseType(v string) int {
	if code, ok := dnswire.TypeCode(v); ok {
		return int(code)
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
