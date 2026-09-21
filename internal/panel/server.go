package panel

import (
	"context"
	"github.com/dns-stack/dns-stack/internal/geoip"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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

	cdnHits cdnHitCache

	rates rateTracker

	exits    exitCache
	svcMu    sync.Mutex
	svcCache map[string]svcCacheEntry
	http     *http.Server
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
	mux.HandleFunc("/api/cdn-hit", s.cdnHit)
	mux.HandleFunc("/api/access", s.access)
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
