package panel

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/dns-stack/dns-stack/internal/config"
)

const (
	DefaultConfigPath  = "/etc/dns-stack/config.env"
	DefaultAuthPath    = "/etc/dns-stack/secrets/panel/auth.json"
	DefaultCertPath    = "/etc/dns-stack/secrets/panel/cert.pem"
	DefaultKeyPath     = "/etc/dns-stack/secrets/panel/key.pem"
	DefaultStateDir    = "/var/lib/dns-stack"
	DefaultDBPath      = "/var/lib/dns-stack/collector.db"
	DefaultECSConfPath = "/etc/unbound/unbound.conf.d/dns-stack-ecs.conf"
)

var (
	listenV6Re   = regexp.MustCompile(`^\[.+\]:[0-9]+$`)
	listenHostRe = regexp.MustCompile(`^[^:]+:[0-9]+$`)
)

func ResolveListen(flagAddr, configPath string) string {
	raw := flagAddr
	if raw == "" {
		raw = os.Getenv("PANEL_LISTEN")
	}
	cfg := map[string]string{}
	if raw == "" {
		cfg = readEnvKeys(configPath, "PANEL_LISTEN", "PANEL_PORT")
		raw = cfg["PANEL_LISTEN"]
	}
	if raw == "" {
		raw = "127.0.0.1:8080"
	}

	raw = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, raw)
	if listenV6Re.MatchString(raw) || listenHostRe.MatchString(raw) {
		return raw
	}

	if len(cfg) == 0 {
		cfg = readEnvKeys(configPath, "PANEL_PORT")
	}
	port := cfg["PANEL_PORT"]
	if port == "" {
		port = "8080"
	}
	if strings.Contains(raw, ":") {

		return "[" + raw + "]:" + port
	}
	return raw + ":" + port
}

func readEnvKeys(path string, keys ...string) map[string]string {
	if path == "" {
		path = DefaultConfigPath
	}
	return config.ReadKeys(path, keys...)
}

func isLoopbackListen(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}

func (s *Server) PreStartCheck() error {
	info, err := os.Stat(s.cfg.ConfigPath)
	if err != nil || info.IsDir() {
		return fmt.Errorf("找不到配置文件: %s", s.cfg.ConfigPath)
	}
	if _, err := os.ReadFile(s.cfg.ConfigPath); err != nil {
		return fmt.Errorf("读不到配置文件: %s（面板需要对它有读权限；拒绝在配置未知的情况下用默认值启动——那会让面板悄悄退回本机监听）", s.cfg.ConfigPath)
	}
	if isLoopbackListen(s.cfg.Addr) {

		return nil
	}
	if _, ok := s.loadAuth(); !ok {
		return fmt.Errorf("面板配置为监听 %s(非本机)，但尚未设置访问密码。请先执行: sudo dns-stack panel-password（拒绝以无密码状态对外监听）", s.cfg.Addr)
	}
	if _, err := os.ReadFile(s.cfg.CertPath); err != nil {
		return fmt.Errorf("面板配置为监听 %s，但读不到 TLS 证书副本: %s。请执行: sudo /opt/dns-stack/dns-stack/scripts/renew-cert.sh --sync-panel-cert（拒绝以明文 HTTP 对外监听，那会让密码在网络上裸奔）", s.cfg.Addr, s.cfg.CertPath)
	}
	if _, err := os.ReadFile(s.cfg.KeyPath); err != nil {
		return fmt.Errorf("面板配置为监听 %s，但读不到 TLS 私钥副本: %s。请执行: sudo /opt/dns-stack/dns-stack/scripts/renew-cert.sh --sync-panel-cert（拒绝以明文 HTTP 对外监听）", s.cfg.Addr, s.cfg.KeyPath)
	}
	return nil
}
