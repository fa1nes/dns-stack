package panel

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dns-stack/dns-stack/internal/geoip"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	_ "modernc.org/sqlite"

	webfs "github.com/dns-stack/dns-stack/web"
)

type Config struct {
	Addr         string
	DBPath       string
	ConfigPath   string
	AuthPath     string
	StateDir     string
	TOTPStepPath string
	CertPath     string
	KeyPath      string
	ECSConfPath  string
}

type Server struct {
	cfg          Config
	authMu       sync.RWMutex
	auth         authRecord
	authLimit    authLimiter
	pendingMu    sync.Mutex
	pendingTOTP  string
	pendingAt    time.Time
	totpLastStep int64
	oauthStates  map[string]time.Time
	clock        func() time.Time
	geoMu        sync.Mutex
	geo          *geoip.GeoDB
	dbip         *geoip.DBIP
	online       *geoip.OnlineLookup
	geoOnline    *geoip.OnlineLookup

	rates rateTracker

	exits    exitCache
	svcMu    sync.Mutex
	svcCache map[string]svcCacheEntry
	http     *http.Server
}

type authRecord struct {
	Salt             string         `json:"salt"`
	Hash             string         `json:"hash"`
	N                int            `json:"n"`
	R                int            `json:"r"`
	P                int            `json:"p"`
	SessionKey       string         `json:"session_key"`
	PasswordDisabled bool           `json:"password_disabled"`
	TOTP             map[string]any `json:"totp"`
	OAuth            map[string]any `json:"oauth"`
}

func New(cfg Config) *Server {

	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "/var/lib/dns-stack/collector.db"
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = DefaultConfigPath
	}
	if cfg.AuthPath == "" {
		cfg.AuthPath = DefaultAuthPath
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/dns-stack"
	}
	if cfg.TOTPStepPath == "" {
		cfg.TOTPStepPath = "/run/dns-stack/panel-totp-step"
	}
	if cfg.CertPath == "" {
		cfg.CertPath = DefaultCertPath
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = DefaultKeyPath
	}
	if cfg.ECSConfPath == "" {
		cfg.ECSConfPath = DefaultECSConfPath
	}
	return &Server{cfg: cfg}
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/bootstrap", s.bootstrap)
	mux.HandleFunc("/api/login", s.login)
	mux.HandleFunc("/api/logout", s.logout)
	mux.HandleFunc("/api/password", s.passwordChange)
	mux.HandleFunc("/api/overview", s.overview)
	mux.HandleFunc("/api/ip-lookup", s.ipLookup)
	mux.HandleFunc("/api/queries", s.queries)
	mux.HandleFunc("/api/queries/stream", s.queryStream)
	mux.HandleFunc("/api/domains", s.domains)
	mux.HandleFunc("/api/domains/summary", s.domainSummary)
	mux.HandleFunc("/api/export", s.exportData)
	mux.HandleFunc("/api/migration-export", s.migrationExport)
	mux.HandleFunc("/api/migration-import", s.migrationImport)
	mux.HandleFunc("/api/timeseries", s.timeseries)
	mux.HandleFunc("/api/domain/", s.domainDetail)
	mux.HandleFunc("/api/collected", s.collected)
	mux.HandleFunc("/api/audit", s.audit)
	mux.HandleFunc("/api/services", s.services)
	mux.HandleFunc("/api/modules", s.modules)
	mux.HandleFunc("/api/ops", s.opsList)
	mux.HandleFunc("/api/auth/config", s.authConfig)
	mux.HandleFunc("/api/auth/oauth", s.authOAuth)
	mux.HandleFunc("/api/oauth/github/start", s.oauthStart)
	mux.HandleFunc("/api/oauth/github/callback", s.oauthCallback)
	mux.HandleFunc("/api/auth/password-toggle", s.passwordToggle)
	mux.HandleFunc("/api/auth/totp/setup", s.totpSetup)
	mux.HandleFunc("/api/auth/totp/enable", s.totpEnable)
	mux.HandleFunc("/api/auth/totp/disable", s.totpDisable)
	mux.HandleFunc("/api/action/", s.action)
	mux.HandleFunc("/api/rules", s.rules)
	mux.HandleFunc("/api/cert", s.cert)
	mux.HandleFunc("/api/cache", s.cache)
	mux.HandleFunc("/api/doh", s.doh)
	mux.HandleFunc("/api/backups", s.backups)
	mux.HandleFunc("/api/logs", s.logs)
	mux.HandleFunc("/api/logs/stream", s.logsStream)
	mux.HandleFunc("/api/my-location", s.myLocation)
	mux.HandleFunc("/api/dns-test", s.dnsTest)
	mux.HandleFunc("/", s.static)

	return s.gzipMiddleware(s.corsMiddleware(s.originMiddleware(s.authMiddleware(mux))))
}

func (s *Server) ListenAndServe() error {
	s.http = &http.Server{Addr: s.cfg.Addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if !isLoopbackListen(s.cfg.Addr) {

		return s.http.ListenAndServeTLS(s.cfg.CertPath, s.cfg.KeyPath)
	}
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if path == "login" {

		if _, ok := s.loadAuth(); !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		path = "login.html"
	}
	if strings.Contains(path, "..") {
		http.NotFound(w, r)
		return
	}
	item := assets()[path]
	if item == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("ETag", item.etag)
	if strings.HasPrefix(path, "assets/") {

		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	} else {

		w.Header().Set("Cache-Control", "no-store")
	}
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, item.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", item.contentType)
	body := item.body
	if item.compressed != nil && clientAcceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		body = item.compressed
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin == "" || !s.allowedOrigin(origin) {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete) {
			o := strings.TrimRight(r.Header.Get("Origin"), "/")
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			same := scheme + "://" + r.Host
			if o != same && !s.allowedOrigin(o) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "请求来源未获授权"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedOrigin(origin string) bool {
	for _, x := range s.corsOrigins() {
		if x == origin {
			return true
		}
	}
	return false
}

var originRe = regexp.MustCompile(`^https?://[^/]+$`)

func (s *Server) corsOrigins() []string {
	raw := os.Getenv("PANEL_CORS_ORIGINS")
	if strings.TrimSpace(raw) == "" {

		raw = s.readConfig()["PANEL_CORS_ORIGINS"]
	}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimRight(strings.TrimSpace(part), "/")
		if origin == "" || strings.Contains(origin, "*") || !originRe.MatchString(origin) {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == origin {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, origin)
		}
	}
	return out
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, ok := s.loadAuth()
		if !ok {
			if !isLocal(r) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "面板尚未设置访问密码"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if path == "/api/health" || path == "/api/bootstrap" || path == "/api/login" || path == "/login" || strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/api/oauth/github/") {
			next.ServeHTTP(w, r)
			return
		}
		if validSession(r, rec) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录或会话已过期", "need_login": true})
			return
		}

		data, err := fs.ReadFile(webfs.Files, "login.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(data)
	})
}

func isLocal(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func (s *Server) loadAuth() (authRecord, bool) {
	b, err := os.ReadFile(s.cfg.AuthPath)
	if err != nil {
		return authRecord{}, false
	}
	var rec authRecord
	if json.Unmarshal(b, &rec) != nil {
		return authRecord{}, false
	}
	s.authMu.Lock()
	s.auth = rec
	s.authMu.Unlock()
	return rec, rec.Hash != ""
}

func validSession(r *http.Request, rec authRecord) bool {
	c, err := r.Cookie("dns_stack_session")
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(rec.SessionKey)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	sig := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(parts[1])) {
		return false
	}
	var p struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(body, &p) != nil {
		return false
	}
	return p.Exp > time.Now().Unix()
}

func issueSession(rec authRecord) (string, error) {
	key, err := base64.StdEncoding.DecodeString(rec.SessionKey)
	if err != nil {
		return "", err
	}
	body := []byte(fmt.Sprintf(`{"exp": %d}`, time.Now().Add(12*time.Hour).Unix()))
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func verifyPassword(password string, rec authRecord) bool {
	salt, e1 := base64.StdEncoding.DecodeString(rec.Salt)
	expected, e2 := base64.StdEncoding.DecodeString(rec.Hash)
	if e1 != nil || e2 != nil || len(expected) != 32 || len(salt) == 0 {
		return false
	}
	n, r, p := rec.N, rec.R, rec.P
	if n == 0 {
		n = 32768
	}
	if r == 0 {
		r = 8
	}
	if p == 0 {
		p = 1
	}
	if n < 2 || n > 1<<20 || r < 1 || r > 32 || p < 1 || p > 16 || int64(n)*int64(r)*128 > 128<<20 {
		return false
	}
	derived, err := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	return err == nil && hmac.Equal(derived, expected)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	rec, ok := s.loadAuth()
	if !ok {
		writeJSON(w, 400, map[string]any{"ok": false, "message": "面板尚未设置密码"})
		return
	}
	if rec.PasswordDisabled {
		writeJSON(w, 403, map[string]any{"ok": false, "message": "密码登录已关闭，请使用 GitHub 登录"})
		return
	}
	ip := remoteIP(r)
	if wait := s.authWait(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeJSON(w, 429, map[string]any{"ok": false, "message": fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", wait), "retry_after": wait})
		return
	}
	var p struct {
		Password string `json:"password"`
		Code     string `json:"totp_code"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&p) != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	passwordOK := verifyPassword(p.Password, rec)
	totpOK := true
	if boolValue(rec.TOTP["enabled"]) {
		secret, _ := rec.TOTP["secret"].(string)
		totpOK = s.checkTOTPCode(p.Code, secret, true)
	}
	if !passwordOK || !totpOK {
		s.authFailure(ip)
		message := "密码错误"
		if boolValue(rec.TOTP["enabled"]) {
			message = "密码或动态验证码错误"
		}
		writeJSON(w, 401, map[string]any{"ok": false, "message": message})
		return
	}
	s.authSuccess(ip)
	token, err := issueSession(rec)
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "message": "会话创建失败"})
		return
	}
	setSessionCookie(w, token)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dns_stack_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: os.Getenv("PANEL_COOKIE_SECURE") != "0"})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "role": s.role(), "ts": time.Now().Unix()})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	rec, configured := s.loadAuth()
	out := map[string]any{"auth_enabled": configured, "totp_enabled": configured && rec.TOTP["enabled"] == true}
	if !configured || !validSession(r, rec) {
		writeJSON(w, 200, out)
		return
	}
	out["role"] = s.role()

	roleName := "规则构建服务器"
	if s.role() == "cn-resolver" {
		roleName = "国内 DNS 服务器"
	}
	out["role_name"] = roleName
	out["log_units"] = s.watchedUnits()
	writeJSON(w, 200, out)
}

func (s *Server) role() string {
	cfg := s.readConfig()
	if v := cfg["ROLE"]; v != "" {
		return v
	}
	return "unknown"
}

func (s *Server) readConfig() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil {
		return out
	}
	keys := map[string]bool{"ROLE": true, "PUBLIC_IPV4": true, "DOH_PORT": true, "DOH_PATH": true, "UNBOUND_ADDR": true, "UNBOUND_PORT": true, "PANEL_LISTEN": true, "PANEL_PORT": true, "PANEL_CORS_ORIGINS": true, "GITHUB_RAW_BASE": true, "GITHUB_MIRROR_1": true, "GITHUB_MIRROR_2": true, "GITHUB_REPOSITORY": true, "GITHUB_BRANCH": true}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && keys[strings.TrimSpace(k)] {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func (s *Server) dbPath() string {
	if _, err := os.Stat(s.cfg.DBPath); err == nil {
		return s.cfg.DBPath
	}
	fallback := filepath.Join(filepath.Dir(s.cfg.DBPath), "classifier.db")
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	return s.cfg.DBPath
}

func (s *Server) openDB() (*sql.DB, error) {
	path := s.dbPath()
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
var routeNames = map[string]string{"cn": "本机递归", "foreign": "香港递归", "cache": "缓存命中", "recursive": "本机递归", "reject": "已拒绝", "unknown": "未知", "dynamic": "动态判定(架构已退场)"}

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

const queryCountCap = 10000

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "items": []any{}, "total": 0})
		return
	}
	defer db.Close()
	q := r.URL.Query()
	page, size := parseInt(q.Get("page"), 1), parseInt(q.Get("size"), 50)
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	where := []string{"1=1"}
	args := []any{}
	if v := strings.TrimSpace(q.Get("domain")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "route = ?")
		args = append(args, v)
	}
	if v := q.Get("resp_by"); v != "" {
		where = append(where, "resp_by = ?")
		args = append(args, v)
	}
	if v := q.Get("since"); v != "" {
		where = append(where, "ts >= ?")
		args = append(args, parseInt(v, 0))
	}
	if v := q.Get("until"); v != "" {
		where = append(where, "ts <= ?")
		args = append(args, parseInt(v, 0))
	}
	if v := q.Get("qtype"); v != "" {
		if n := parseType(v); n >= 0 {
			where = append(where, "qtype = ?")
			args = append(args, n)
		}
	}
	if v := q.Get("rcode"); v != "" {
		if n := parseRcode(v); n >= 0 {
			where = append(where, "rcode = ?")
			args = append(args, n)
		}
	}
	clause := strings.Join(where, " AND ")

	var total int
	countArgs := append(append([]any{}, args...), queryCountCap+1)
	_ = db.QueryRow("SELECT COUNT(*) FROM (SELECT 1 FROM query_events WHERE "+clause+" LIMIT ?)", countArgs...).Scan(&total)
	capped := total > queryCountCap
	if capped {
		total = queryCountCap
	}

	offset := (page - 1) * size
	if offset > queryCountCap {
		offset = queryCountCap
	}
	dataArgs := append(append([]any{}, args...), size, offset)
	rows, err := db.Query("SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events WHERE "+clause+" ORDER BY id DESC LIMIT ? OFFSET ?", dataArgs...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ts, qt, rc int64
		var domain, resp, route, tag string
		var prefetch int64
		var elapsed sql.NullFloat64
		var exit sql.NullString
		if rows.Scan(&id, &ts, &domain, &qt, &rc, &resp, &route, &tag, &prefetch, &elapsed, &exit) != nil {
			continue
		}
		items = append(items, enrichItem(id, ts, qt, rc, domain, resp, route, tag, prefetch, elapsed, exit))
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "total_capped": capped, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func enrichItem(id, ts, qt, rc int64, domain, resp, route, tag string, prefetch int64, elapsed sql.NullFloat64, exit sql.NullString) map[string]any {
	m := map[string]any{"id": id, "ts": ts, "domain": domain, "qtype": qt, "qtype_name": qtypeName(qt), "rcode": rc, "rcode_name": rcodeName(rc), "resp_by": resp, "route": route, "route_name": routeNameEnrich(route), "server_tag": tag, "prefetch": prefetch, "cache_hit": resp == "cache", "elapsed_ms": nil, "exit_path": nil}
	if elapsed.Valid {
		m["elapsed_ms"] = elapsed.Float64
	}
	if exit.Valid {
		m["exit_path"] = exit.String
	}
	return m
}

func queryItem(id, ts, qt, rc int64, domain, resp, route, tag string, prefetch int64, elapsed sql.NullFloat64, exit sql.NullString) map[string]any {
	m := map[string]any{"id": id, "ts": ts, "domain": domain, "qtype": qt, "qtype_name": qtypeName(qt), "rcode": rc, "rcode_name": rcodeName(rc), "resp_by": resp, "route": route, "route_name": routeName(route), "server_tag": tag, "prefetch": prefetch != 0, "cache_hit": resp == "cache"}
	if elapsed.Valid {
		m["elapsed_ms"] = elapsed.Float64
	}
	if exit.Valid {
		m["exit_path"] = exit.String
	}
	return m
}

func (s *Server) queryStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	last := int64(parseInt(r.URL.Query().Get("after_id"), 0))
	db, err := s.openDB()
	if err != nil {
		_, _ = w.Write([]byte("data: {\"error\":\"数据库不可用\"}\n\n"))
		fl.Flush()
		return
	}
	defer db.Close()
	if last == 0 {
		_ = db.QueryRow("SELECT COALESCE(MAX(id),0) FROM query_events").Scan(&last)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	idle := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			rows, err := db.Query("SELECT id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path FROM query_events WHERE id > ? ORDER BY id ASC LIMIT 200", last)
			if err == nil {
				events := []map[string]any{}
				for rows.Next() {
					var id, ts, qt, rc, pre int64
					var domain, resp, route, tag string
					var elapsed sql.NullFloat64
					var exit sql.NullString
					if rows.Scan(&id, &ts, &domain, &qt, &rc, &resp, &route, &tag, &pre, &elapsed, &exit) != nil {
						continue
					}
					events = append(events, enrichItem(id, ts, qt, rc, domain, resp, route, tag, pre, elapsed, exit))
				}
				rows.Close()
				if len(events) > 0 {
					last = events[len(events)-1]["id"].(int64)
					payload, _ := json.Marshal(map[string]any{"events": events})
					_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
					fl.Flush()
					idle = 0
					continue
				}
			}
			idle++
			if idle >= 15 {
				_, _ = w.Write([]byte(": keepalive\n\n"))
				fl.Flush()
				idle = 0
			}
		}
	}
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "items": []any{}, "total": 0})
		return
	}
	defer db.Close()
	q := r.URL.Query()
	page, size := parseInt(q.Get("page"), 1), parseInt(q.Get("size"), 50)
	if size < 1 || size > 500 {
		size = 50
	}

	if limit := parseInt(q.Get("limit"), 0); limit >= 1 && limit <= 500 {
		size = limit
	}
	metric := q.Get("metric")
	if metric == "" {
		metric = "count"
	}
	if metric == "slow" {
		s.domainsSlow(w, r, db, page, size)
		return
	}
	where := []string{"1=1"}
	args := []any{}
	if v := strings.TrimSpace(q.Get("search")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "last_route = ?")
		args = append(args, v)
	}
	if metric == "fail" {
		where = append(where, "domain IN (SELECT domain FROM query_events WHERE rcode > 0 AND ts >= ?)")
		args = append(args, s.now().Add(-24*time.Hour).Unix())
	}
	order := map[string]string{"count": "occurrence_count DESC", "recent": "last_seen_at DESC", "new": "first_seen_at DESC", "fail": "fail_count DESC, occurrence_count DESC"}[metric]
	if order == "" {
		order = "occurrence_count DESC"
	}
	clause := strings.Join(where, " AND ")
	var total int
	_ = db.QueryRow("SELECT COUNT(*) FROM domains WHERE "+clause, args...).Scan(&total)
	rows, err := db.Query("SELECT domain,first_seen_at,last_seen_at,occurrence_count,COALESCE(fail_count,0),last_rcode,last_route FROM domains WHERE "+clause+" ORDER BY "+order+" LIMIT ? OFFSET ?", append(args, size, (page-1)*size)...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var d, lr sql.NullString
		var first, last, count, fail, rcode sql.NullInt64
		if rows.Scan(&d, &first, &last, &count, &fail, &rcode, &lr) != nil {
			continue
		}
		items = append(items, domainItem(d, first, last, count, fail, rcode, lr))
	}
	s.attachResolvedNode(r.Context(), items)
	writeJSON(w, 200, map[string]any{"items": items, "metric": metric, "total": total, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func (s *Server) domainsSlow(w http.ResponseWriter, r *http.Request, db *sql.DB, page, size int) {
	q := r.URL.Query()
	where := []string{"elapsed_ms IS NOT NULL", "ts >= ?"}
	args := []any{s.now().Add(-24 * time.Hour).Unix()}
	if v := strings.TrimSpace(q.Get("search")); v != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(v)+"%")
	}
	if v := q.Get("route"); v != "" {
		where = append(where, "route = ?")
		args = append(args, v)
	}
	sub := "SELECT domain, elapsed_ms, ts FROM query_events WHERE " + strings.Join(where, " AND ") + " ORDER BY id DESC LIMIT 100000"
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM (SELECT domain FROM ("+sub+") GROUP BY domain HAVING COUNT(*) >= 2)", args...).Scan(&total); err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	dataArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := db.Query("SELECT domain, COUNT(*) AS samples, ROUND(AVG(elapsed_ms),2) AS avg_ms, ROUND(MAX(elapsed_ms),2) AS max_ms, MAX(ts) AS last_seen_at FROM ("+sub+") GROUP BY domain HAVING COUNT(*) >= 2 ORDER BY avg_ms DESC LIMIT ? OFFSET ?", dataArgs...)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "查询失败", "items": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var domain string
		var samples, lastSeen int64
		var avg, max sql.NullFloat64
		if rows.Scan(&domain, &samples, &avg, &max, &lastSeen) != nil {
			continue
		}
		items = append(items, map[string]any{"domain": domain, "samples": samples, "avg_ms": nilFloat(avg), "max_ms": nilFloat(max), "last_seen_at": lastSeen})
	}
	s.attachResolvedNode(r.Context(), items)
	writeJSON(w, 200, map[string]any{"items": items, "metric": "slow", "total": total, "page": page, "size": size, "pages": (total + size - 1) / size})
}

func nilFloat(v sql.NullFloat64) any {
	if v.Valid {
		return v.Float64
	}
	return nil
}

func domainItem(d sql.NullString, first, last, count, fail, rcode sql.NullInt64, lr sql.NullString) map[string]any {
	m := map[string]any{"domain": d.String, "first_seen_at": first.Int64, "last_seen_at": last.Int64, "occurrence_count": count.Int64, "fail_count": fail.Int64, "last_rcode": nilInt(rcode), "last_route": lr.String, "last_route_name": routeName(lr.String)}
	if rcode.Valid {
		m["last_rcode_name"] = rcodeName(rcode.Int64)
	}
	return m
}

func nilInt(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

func (s *Server) domainSummary(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用"})
		return
	}
	defer db.Close()

	now := s.now().Unix()
	since := now - 86400
	if epoch := s.archEpoch(); epoch > since {
		since = epoch
	}
	out := map[string]any{}
	rows, _ := db.Query("SELECT COALESCE(route,'unknown') AS r, COUNT(DISTINCT domain) AS c FROM query_events WHERE ts >= ? GROUP BY r ORDER BY c DESC, r ASC", since)
	var routes []map[string]any
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var v string
			var c int
			_ = rows.Scan(&v, &c)
			routes = append(routes, map[string]any{"route": v, "route_name": routeName(v), "count": c})
		}
	}
	out["by_route"] = routes
	domainSummaryExtras(db, out, now, since)
	writeJSON(w, 200, out)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "数据库不可用", "series": []any{}})
		return
	}
	defer db.Close()
	span := parseInt(r.URL.Query().Get("span"), 3600)
	buckets := parseInt(r.URL.Query().Get("buckets"), 60)
	if span < 300 {
		span = 300
	}
	if buckets < 10 {
		buckets = 10
	}
	if buckets > 200 {
		buckets = 200
	}
	step := span / buckets
	if step < 1 {
		step = 1
	}
	now := s.now().Unix()
	since := now - int64(span)
	rows, _ := db.Query("SELECT ((ts-?)/?) AS b, route, COUNT(*) FROM query_events WHERE ts >= ? GROUP BY b,route ORDER BY b", since, step, since)
	vals := map[int64]map[string]int{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b int64
			var route string
			var c int
			_ = rows.Scan(&b, &route, &c)
			if vals[b] == nil {
				vals[b] = map[string]int{}
			}
			vals[b][route] = c
		}
	}
	series := []map[string]any{}
	for i := 0; i <= buckets; i++ {
		b := int64(i)
		x := vals[b]
		series = append(series, map[string]any{"t": since + b*int64(step), "cn": x["cn"], "foreign": x["foreign"], "cache": x["cache"], "reject": x["reject"], "unknown": x["unknown"]})
	}
	writeJSON(w, 200, map[string]any{"series": series, "step": step, "start": since, "end": now})
}

func (s *Server) domainDetail(w http.ResponseWriter, r *http.Request) {
	s.detailInfo(w, r)
}

func (s *Server) collected(w http.ResponseWriter, r *http.Request) {
	s.collectedInfo(w, r)
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

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	now := s.now().Unix()
	out := map[string]any{"role": s.role(), "ts": now, "upstreams": []any{}, "system": map[string]any{}, "routing": map[string]any{}}
	mos, mosErr := helperCall(r.Context(), "mosproxy_metrics", nil)
	unbound, unboundErr := helperCall(r.Context(), "unbound_stats", nil)
	if mosErr == nil && helperOK(mos) {
		parsed := parseMetrics(helperStdout(mos))
		queries := metricByLabel(parsed, "upstream_query_total", "upstream")
		errors := metricByLabel(parsed, "upstream_err_total", "upstream")
		cache := metricScalar(parsed, "query_cache_hit_total")
		total, failed := cache, 0.0
		for _, value := range queries {
			total += value
		}
		for _, value := range errors {
			failed += value
		}

		latSum, latCount := 0.0, 0.0
		for _, value := range metricByLabel(parsed, "upstream_response_latency_millisecond_sum", "upstream") {
			latSum += value
		}
		for _, value := range metricByLabel(parsed, "upstream_response_latency_millisecond_count", "upstream") {
			latCount += value
		}
		var avgLatency any
		if latCount > 0 {
			avgLatency = roundTo(latSum/latCount, 1)
		}

		counters := map[string]float64{"query_total": total, "cache_hit_total": cache}
		for key, value := range queries {
			counters["uq_"+key] = value
		}
		for key, value := range errors {
			counters["ue_"+key] = value
		}
		rates := s.rates.update(counters)
		out["mosproxy"] = map[string]any{"available": true, "avg_latency_ms": avgLatency, "latency_samples": int(latCount), "query_total": int(total), "query_total_synthetic": true, "cache_hit_total": int(cache), "cache_hit_ratio": percentage(cache, total), "qps": roundTo(rates["query_total"], 2), "upstream_query_total": int(total - cache), "upstream_err_total": int(failed), "error_ratio": percentage(failed, total-cache), "prefetch_total": int(metricScalar(parsed, "prefetch_total")), "cache_entries": int(metricScalar(parsed, "cache_memorysize")), "rejected_cc": int(metricScalar(parsed, "rejected_cc_total")), "rejected_qps": int(metricScalar(parsed, "rejected_qps_total"))}
	} else {
		out["mosproxy"] = map[string]any{"available": false, "message": helperError(mosErr, mos)}
	}
	if unboundErr == nil && helperOK(unbound) {
		stats := parseUnboundStats(helperStdout(unbound))
		total := stats["total.num.queries"]
		hits := stats["total.num.cachehits"]
		out["unbound"] = map[string]any{"available": true, "queries": int(total), "cache_hits": int(hits), "cache_miss": int(stats["total.num.cachemiss"]), "cache_hit_ratio": percentage(hits, total), "prefetch": int(stats["total.num.prefetch"]), "recursion_time_avg_ms": roundTo(stats["total.recursion.time.avg"]*1000, 1), "recursion_time_median_ms": roundTo(stats["total.recursion.time.median"]*1000, 1), "requestlist_current": int(stats["total.requestlist.current.all"]), "subnet_queries": optionalStat(stats, "num.query.subnet"), "subnet_cache_hits": optionalStat(stats, "num.query.subnet_cache")}
	} else {
		out["unbound"] = map[string]any{"available": false, "message": helperError(unboundErr, unbound)}
	}
	out["system"] = systemInfo()
	db, err := s.openDB()
	if err == nil {
		defer db.Close()
		var last5, last1, domains int
		_ = db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ?", now-300).Scan(&last5)
		_ = db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ?", now-3600).Scan(&last1)
		_ = db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domains)
		out["events"] = map[string]any{"last_5m": last5, "last_1h": last1, "domains": domains,
			"latency": latencyStats(db, now-3600)}
	} else {
		out["events"] = map[string]any{"error": "数据库不可用"}
	}
	routing := out["routing"].(map[string]any)
	routing["direct4_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "direct4.txt"))
	routing["cn_authority_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "cn-authority.txt"))
	routing["cn_zones_count"] = countLines(filepath.Join(s.cfg.StateDir, "chnroute", "cn-zones-matched.txt"))
	routing["exits"] = s.exitAddresses(r.Context())

	if s.role() == "cn-resolver" {
		for key, active := range s.routingServiceState(r) {
			routing[key] = active
		}
	}
	writeJSON(w, 200, out)
}

func helperOK(resp map[string]any) bool {
	value, _ := resp["ok"].(bool)
	if !value {
		return false
	}
	data, _ := resp["data"].(map[string]any)
	return numberValue(data["returncode"]) == 0
}
func helperStdout(resp map[string]any) string {
	data, _ := resp["data"].(map[string]any)
	value, _ := data["stdout"].(string)
	return value
}
func helperError(err error, resp map[string]any) string {
	if err != nil {
		return err.Error()
	}
	if value, ok := resp["message"].(string); ok && value != "" {
		return value
	}
	return "指标不可用"
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
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	db, err := s.openDB()
	if err != nil {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	defer db.Close()
	limit := parseInt(r.URL.Query().Get("limit"), 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := db.Query("SELECT id,ts,actor,operation,args,ok,message FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ts int64
		var actor, op, args, msg string
		var ok int
		_ = rows.Scan(&id, &ts, &actor, &op, &args, &ok, &msg)
		items = append(items, map[string]any{"id": id, "ts": ts, "actor": actor, "operation": op, "args": args, "ok": ok, "message": msg})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadAuth()
	clientID, _ := rec.OAuth["client_id"].(string)
	secret, _ := rec.OAuth["client_secret"].(string)
	oauth := map[string]any{"client_id": clientID, "secret_set": secret != "", "allowed_users": oauthUsers(rec), "verified_once": boolValue(rec.OAuth["verified_once"]), "ready": oauthReady(rec)}
	writeJSON(w, 200, map[string]any{"oauth": oauth, "password_disabled": ok && rec.PasswordDisabled, "totp_enabled": ok && rec.TOTP["enabled"] == true})
}

func helperCall(ctx context.Context, op string, args map[string]any) (map[string]any, error) {
	if _, ok := ctx.Deadline(); !ok {
		timeout := 30 * time.Second
		if spec, exists := operationSpecs[op]; exists {
			timeout = time.Duration(spec.Timeout) * time.Second
		}
		if op == "set_panel_password" {
			timeout = 45 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	socket := os.Getenv("DNS_STACK_HELPER_SOCK")
	if socket == "" {
		socket = "/run/dns-stack/helper.sock"
	}
	network, address := "unix", socket
	if strings.HasPrefix(socket, "unix://") {
		address = strings.TrimPrefix(socket, "unix://")
	}
	if strings.HasPrefix(socket, "tcp://") {
		network = "tcp"
		address = strings.TrimPrefix(socket, "tcp://")
		host, _, splitErr := net.SplitHostPort(address)
		parsedHost := net.ParseIP(host)
		if splitErr != nil || parsedHost == nil || !parsedHost.IsLoopback() {
			return nil, fmt.Errorf("helper TCP 地址必须是回环地址")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	if err = json.NewEncoder(conn).Encode(map[string]any{"op": op, "args": args}); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 8<<20)).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) dnsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		Domain  string   `json:"domain"`
		QType   string   `json:"qtype"`
		Server  string   `json:"server"`
		Servers []string `json:"servers"`
		Subnet  string   `json:"subnet"`
	}
	if json.NewDecoder(r.Body).Decode(&p) != nil || strings.TrimSpace(p.Domain) == "" {
		writeJSON(w, 400, map[string]any{"detail": "请输入要测试的域名"})
		return
	}
	p.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if !validDNSName(p.Domain) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不是合法 DNS 名"})
		return
	}
	p.QType = strings.ToUpper(strings.TrimSpace(p.QType))
	if p.QType == "" {
		p.QType = "A"
	}
	if !dnsTestQTypes[p.QType] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的查询类型"})
		return
	}
	if strings.TrimSpace(p.Subnet) == "" {
		p.Subnet = clientSubnet(r)
	} else if !validClientSubnet(p.Subnet) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "客户端子网必须是规范的全局 IPv4 /24 网段"})
		return
	}
	servers := p.Servers
	if len(servers) == 0 {
		if strings.TrimSpace(p.Server) != "" {
			servers = []string{strings.TrimSpace(p.Server)}
		} else {
			servers = []string{"local-unbound", "foreign-hk"}
		}
	}
	for _, server := range servers {
		if !dnsTestServers[server] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的测试目标"})
			return
		}
	}
	results := map[string]any{}
	type probeResult struct {
		server string
		parsed map[string]any
	}
	ch := make(chan probeResult, len(servers))
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			started := time.Now()
			parsed := dnsProbe(r.Context(), p.Domain, p.QType, server, strings.TrimSpace(p.Subnet))
			parsed["panel_elapsed_ms"] = time.Since(started).Milliseconds()
			ch <- probeResult{server: server, parsed: parsed}
		}(server)
	}
	wg.Wait()
	close(ch)
	for probe := range ch {
		if geoList := s.probeIPsGeo(r.Context(), probe.parsed); len(geoList) > 0 {
			probe.parsed["ips_geo"] = geoList
		}
		results[probe.server] = probe.parsed
	}

	routing, _ := s.routingInfo(r.Context(), p.Domain, strings.TrimSpace(p.Subnet), false)
	if p.Subnet != "" {
		routing["viewer_subnet"] = p.Subnet
	}
	if local, ok := results["local-unbound"].(map[string]any); ok {
		if ecs, ok := local["ecs"]; ok && ecs != nil {
			routing["ecs"] = ecs
		}

		var ips []string
		records, _ := local["records"].([]map[string]any)
		for _, record := range records {
			if record["type"] != "A" && record["type"] != "AAAA" {
				continue
			}
			if value, _ := record["value"].(string); value != "" {
				ips = append(ips, value)
			}
		}
		s.resultGeoFields(routing, ips)
	}
	writeJSON(w, 200, map[string]any{"domain": p.Domain, "qtype": p.QType, "results": results, "routing": routing})
}

var dnsTestServers = map[string]bool{
	"local-unbound": true,
	"foreign-hk":    true,
	"cn-unbound":    true,
}

var dnsTestQTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "HTTPS": true, "SVCB": true, "PTR": true,
}

func validClientSubnet(raw string) bool {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || ip.To4() == nil || !isPublicIP(ip) {
		return false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 24 || !ip.Equal(ip.Mask(network.Mask)) {
		return false
	}
	last := append(net.IP(nil), ip.To4()...)
	last[3] = 255
	return isPublicIP(last)
}

func (s *Server) probeIPsGeo(ctx context.Context, parsed map[string]any) []map[string]any {
	ips := parsedGlobalIPs(parsed)
	if len(ips) == 0 {
		return nil
	}
	limit := len(ips)
	if limit > 16 {
		limit = 16
	}
	type item struct {
		ip  string
		geo map[string]any
	}
	ch := make(chan item, limit)
	var wg sync.WaitGroup
	for _, ip := range ips[:limit] {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ch <- item{ip: ip, geo: s.geoLookupOnline(ctx, ip)}
		}(ip)
	}
	wg.Wait()
	close(ch)
	found := map[string]map[string]any{}
	for it := range ch {
		found[it.ip] = it.geo
	}
	out := make([]map[string]any, 0, limit)
	for _, ip := range ips[:limit] {
		out = append(out, map[string]any{"ip": ip, "geo": found[ip]})
	}
	return out
}

func parsedGlobalIPs(parsed map[string]any) []string {
	if parsed["error"] != nil || (parsed["status"] != nil && parsed["status"] != "NOERROR") {
		return nil
	}
	raw, ok := parsed["records"].([]map[string]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	ips := make([]string, 0, len(raw))
	for _, record := range raw {
		typ, _ := record["type"].(string)
		if typ != "A" && typ != "AAAA" {
			continue
		}
		value, _ := record["value"].(string)
		ip := net.ParseIP(value)
		if ip == nil || !isPublicIP(ip) || (typ == "A") != (ip.To4() != nil) || seen[value] {
			continue
		}
		seen[value] = true
		ips = append(ips, value)
	}
	return ips
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	address, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.Is4() || netip.MustParsePrefix("2000::/3").Contains(address)
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func compareDNSViews(results map[string]any) string {
	local, localOK := results["local-unbound"].(map[string]any)
	hk, hkOK := results["foreign-hk"].(map[string]any)
	if !localOK || !hkOK {
		return "incomplete"
	}
	localIPs := parsedGlobalIPs(local)
	hkIPs := parsedGlobalIPs(hk)
	if len(localIPs) == 0 || len(hkIPs) == 0 {
		return "no_final_global_address"
	}
	if sameStringSet(localIPs, hkIPs) {
		return "consistent"
	}
	return "geo_split"
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, value := range a {
		seen[value] = true
	}
	for _, value := range b {
		if !seen[value] {
			return false
		}
	}
	return true
}

func (s *Server) myLocation(w http.ResponseWriter, r *http.Request) {

	ip := clientIP(r)

	out := map[string]any{"client_ip": ip, "geo": s.geoLookup(ip)}
	subnet := clientSubnet(r)
	if subnet == "" {
		out["error"] = "只支持全局 IPv4 客户端"
		writeJSON(w, 200, out)
		return
	}
	out["ecs"] = subnet
	probes := [][2]string{{"淘宝", "www.taobao.com"}, {"京东", "www.jd.com"}, {"百度", "www.baidu.com"}, {"腾讯", "www.qq.com"}, {"抖音", "www.douyin.com"}, {"哔哩哔哩", "www.bilibili.com"}, {"微信", "res.wx.qq.com"}, {"网易", "www.163.com"}}
	type result struct {
		idx   int
		value map[string]any
	}
	ch := make(chan result, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(i int, name, domain string) {
			defer wg.Done()
			item := map[string]any{"name": name, "domain": domain}
			resp, err := helperCall(r.Context(), "dns_test", map[string]any{"domain": domain, "qtype": "A", "server": "local-unbound", "subnet": subnet})
			if err != nil {
				item["error"] = err.Error()
				ch <- result{i, item}
				return
			}

			data := helperData(resp)
			if !boolValue(resp["ok"]) || numberValue(data["returncode"]) != 0 {
				message, _ := resp["message"].(string)
				if message == "" {
					message = "查询失败"
				}
				item["error"] = message
				ch <- result{i, item}
				return
			}
			stdout, _ := data["stdout"].(string)
			parsed := parseDig(stdout)
			var ip string
			for _, raw := range parsed["records"].([]map[string]any) {
				if raw["type"] == "A" {
					ip, _ = raw["value"].(string)
					break
				}
			}

			item["ip"] = nil
			if ip != "" {
				item["ip"] = ip
			}
			item["geo"] = s.geoLookup(ip)
			item["ecs"] = parsed["ecs"]
			ch <- result{i, item}
		}(i, probe[0], probe[1])
	}
	wg.Wait()
	close(ch)
	nodes := make([]any, len(probes))
	for item := range ch {
		nodes[item.idx] = item.value
	}
	out["nodes"] = nodes
	writeJSON(w, 200, out)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func clientSubnet(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !isPublicIP(ip) {
		return ""
	}
	parts := strings.Split(host, ".")
	return strings.Join(parts[:3], ".") + ".0/24"
}

func parseDig(text string) map[string]any {
	out := map[string]any{"records": []any{}, "status": nil, "query_time_ms": nil, "ecs": nil}
	inAnswer := false
	records := []map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";; ->>HEADER<<-") {
			if i := strings.Index(line, "status:"); i >= 0 {
				v := strings.TrimSpace(strings.SplitN(line[i+7:], ",", 2)[0])
				out["status"] = v
			}
		} else if line == ";; ANSWER SECTION:" {
			inAnswer = true
		} else if strings.HasPrefix(line, ";;") {
			inAnswer = false
			if i := strings.Index(line, "Query time:"); i >= 0 {
				fields := strings.Fields(line[i+len("Query time:"):])
				if len(fields) > 0 {
					out["query_time_ms"] = parseInt(fields[0], 0)
				}
			}
		} else if strings.HasPrefix(line, "; CLIENT-SUBNET:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "; CLIENT-SUBNET:"))
			parts := strings.Split(v, "/")
			if len(parts) >= 3 {
				source := parseInt(parts[len(parts)-2], 0)
				scope := parseInt(parts[len(parts)-1], 0)
				out["ecs"] = map[string]any{"subnet": strings.Join(parts[:len(parts)-2], "/") + "/" + strconv.Itoa(source), "source": source, "scope": scope, "honored": scope > 0}
			}
		} else if inAnswer && line != "" && !strings.HasPrefix(line, ";") {
			f := strings.Fields(line)
			if len(f) >= 5 {
				if (f[3] == "A" || f[3] == "AAAA") && (!isPublicIP(net.ParseIP(f[4])) || (f[3] == "A") != (net.ParseIP(f[4]).To4() != nil)) {
					continue
				}
				records = append(records, map[string]any{"name": f[0], "ttl": parseInt(f[1], 0), "class": f[2], "type": f[3], "value": strings.Join(f[4:], " ")})
			}
		}
	}
	out["records"] = records
	return out
}
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	info := s.rulesInfo()
	cfg := s.readConfig()

	info["sources"] = map[string]string{
		"github_raw_base":   cfg["GITHUB_RAW_BASE"],
		"github_mirror_1":   cfg["GITHUB_MIRROR_1"],
		"github_mirror_2":   cfg["GITHUB_MIRROR_2"],
		"github_repository": cfg["GITHUB_REPOSITORY"],
		"github_branch":     cfg["GITHUB_BRANCH"],
	}
	writeJSON(w, 200, info)
}

func helperData(resp map[string]any) map[string]any {
	data, _ := resp["data"].(map[string]any)
	return data
}

func (s *Server) cert(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "cert_info", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"exists": false, "error": err.Error()})
		return
	}
	data := helperData(resp)
	if data["returncode"] != float64(0) {
		writeJSON(w, 200, map[string]any{"exists": false, "error": data["stderr"]})
		return
	}
	info := map[string]any{"exists": true}
	stdout, _ := data["stdout"].(string)
	for _, line := range strings.Split(stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (k == "notAfter" || k == "notBefore" || k == "issuer") {
			info[strings.ToLower(strings.ReplaceAll(k, "not", "not_"))] = v
		}
	}
	writeJSON(w, 200, info)
}

func (s *Server) cache(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "cache_info", nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	var out map[string]any
	if json.Unmarshal([]byte(stdout), &out) != nil {
		writeJSON(w, 503, map[string]any{"error": "缓存配置返回格式异常"})
		return
	}
	out["note"] = "Unbound 侧改动立即生效；mosproxy 的缓存配置只在启动时读取，改完需要重启 mosproxy 才会生效"
	writeJSON(w, 200, out)
}

func (s *Server) doh(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "doh_info", nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	out := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if out["doh_url"] == nil {
		writeJSON(w, 503, map[string]any{"error": "DoH 配置返回格式异常"})
		return
	}
	out["is_default"] = out["doh_path_is_default"] == "1"
	delete(out, "doh_path_is_default")
	writeJSON(w, 200, out)
}

func (s *Server) backups(w http.ResponseWriter, r *http.Request) {
	resp, err := helperCall(r.Context(), "list_backups", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"backups": []any{}, "exports": []any{}, "error": err.Error()})
		return
	}
	data := helperData(resp)
	stdout, _ := data["stdout"].(string)
	var out map[string]any
	if json.Unmarshal([]byte(stdout), &out) != nil {

		reason, _ := resp["message"].(string)
		if reason == "" {
			reason = "无法读取备份目录"
		}
		out = map[string]any{"backups": []any{}, "exports": []any{}, "error": reason}
	}
	writeJSON(w, 200, out)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "mosproxy"
	}

	if !s.watchedUnit(unit) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的服务: " + unit})
		return
	}
	lines := parseInt(r.URL.Query().Get("lines"), 200)
	if lines < 1 || lines > 2000 {
		lines = 200
	}
	args := map[string]any{"unit": unit, "lines": lines}
	if v := r.URL.Query().Get("priority"); v != "" {
		args["priority"] = v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		args["since"] = v
	}
	resp, err := helperCall(r.Context(), "logs", args)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error(), "lines": []string{}})
		return
	}
	if ok, _ := resp["ok"].(bool); !ok {
		writeJSON(w, 503, map[string]any{"error": resp["message"], "lines": []string{}})
		return
	}
	data, _ := resp["data"].(map[string]any)
	stdout, _ := data["stdout"].(string)
	if numberValue(data["returncode"]) != 0 && stdout == "" {
		message := "读取日志失败"
		if stderr, ok := data["stderr"].(string); ok && stderr != "" {
			message = stderr
		}
		writeJSON(w, 503, map[string]any{"error": message, "lines": []string{}})
		return
	}
	out := []string{}
	needle := strings.ToLower(r.URL.Query().Get("search"))
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) != "" && (needle == "" || strings.Contains(strings.ToLower(line), needle)) {
			out = append(out, line)
		}
	}
	writeJSON(w, 200, map[string]any{"unit": unit, "lines": out, "count": len(out)})
}

func (s *Server) logsStream(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "mosproxy"
	}

	if !s.watchedUnit(unit) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的服务: " + unit})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	priority := r.URL.Query().Get("priority")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	seen := map[string]bool{}
	order := []string{}
	first := true
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			args := map[string]any{"unit": unit, "lines": 100}
			if priority != "" {
				args["priority"] = priority
			}
			resp, err := helperCall(r.Context(), "logs", args)
			respOK := false
			if err == nil {
				respOK, _ = resp["ok"].(bool)
			}
			if err != nil || !respOK {
				var message any
				if err != nil {
					message = err.Error()
				} else {
					message = resp["message"]
				}
				payload, _ := json.Marshal(map[string]any{"error": message})
				_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
				fl.Flush()
				continue
			}
			data, _ := resp["data"].(map[string]any)
			stdout, _ := data["stdout"].(string)
			lines := []string{}
			for _, line := range strings.Split(stdout, "\n") {
				if strings.TrimSpace(line) != "" && !seen[line] {
					seen[line] = true
					order = append(order, line)
					lines = append(lines, line)
				}
			}

			if len(order) > 3000 {
				for _, old := range order[:len(order)-1500] {
					delete(seen, old)
				}
				order = append([]string{}, order[len(order)-1500:]...)
			}
			if len(lines) > 0 {

				if first && len(lines) > 100 {
					lines = lines[len(lines)-100:]
				}
				first = false
				payload, _ := json.Marshal(map[string]any{"lines": lines})
				_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
			} else {
				_, _ = w.Write([]byte(": keepalive\n\n"))
			}
			fl.Flush()
		}
	}
}
