package pipeline

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/geoip"
)

type Config struct {
	StateDir     string
	ConfigFile   string
	TunnelIf     string
	TunnelAddr   string
	NFTTable     string
	DirectSet    string
	AuthoritySet string
	UnboundCtl   string
	Resolver     string
	ResolverPort int
	ECSConfPath  string
	Aggregate    int
	APNICURL     string
	values       map[string]string
}

const (
	DefaultStateDir   = "/var/lib/dns-stack"
	DefaultConfigFile = "/etc/dns-stack/config.env"
	DefaultECSConf    = "/etc/unbound/unbound.conf.d/dns-stack-ecs.conf"
	DefaultAPNICURL   = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
)

var configKeys = []string{
	"TUNNEL_IF", "TUNNEL_ADDR", "NFT_TABLE", "PUBLIC_IPV4",
	"ROUTE_TABLE", "FWMARK", "UNBOUND_USER", "WG_CONF",
	"TUNNEL_FAIL_MODE", "MIN_SET_ENTRIES", "NFT_ENDPOINT_SET",
	"CHNROUTE_MIN_ENTRIES", "CHNROUTE_MIN_ADDRESSES", "CHNROUTE_EXCLUDE_MAX_RATIO",
	"CN_AUTHORITY_AGGREGATE", "GEO_CROSS_MAX_AGE_SEC", "ECS_ACCUM_TTL_SEC",
	"SHARED_ANYCAST_MAX_AGE_SEC", "GUARD_MIN_RATIO", "APNIC_URL",
	"GEOIP_ENABLE_CITY", "GEOIP_RELEASE_REPO", "GEOIP_RELEASE_BASE", "GITHUB_REPOSITORY",
	"GEOIP_ASN_URL", "GEOIP_CITY_URL", "GEOIP_CNIP_URL",
	"GEOIP_DBIP_ASN_URL", "GEOIP_DBIP_CITY_URL",
	"CDN_RULES_BASE", "CDN_RULES_MIRROR_1", "CDN_RULES_MIRROR_2",
}

func LoadConfig(stateDir, configFile string) Config {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	if configFile == "" {
		configFile = DefaultConfigFile
	}
	values := config.ReadKeys(configFile, configKeys...)
	cfg := Config{
		StateDir:     stateDir,
		ConfigFile:   configFile,
		TunnelIf:     pick(values["TUNNEL_IF"], "wg0"),
		TunnelAddr:   pick(values["TUNNEL_ADDR"], "10.100.0.2"),
		NFTTable:     pick(values["NFT_TABLE"], "dns_route"),
		DirectSet:    "direct4",
		AuthoritySet: "cn_authority",
		UnboundCtl:   "unbound-control",
		Resolver:     "127.0.0.1",
		ResolverPort: 5335,
		ECSConfPath:  DefaultECSConf,
		Aggregate:    24,
		APNICURL:     pick(values["APNIC_URL"], DefaultAPNICURL),
		values:       values,
	}
	if n, err := strconv.Atoi(values["CN_AUTHORITY_AGGREGATE"]); err == nil && n >= 0 && n <= 32 {
		cfg.Aggregate = n
	}
	return cfg
}

func pick(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func (c Config) Value(key string) string { return c.values[key] }

func (c Config) Int(key string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(c.values[key])); err == nil && n > 0 {
		return n
	}
	return fallback
}

func (c Config) Float(key string, fallback float64) float64 {
	if n, err := strconv.ParseFloat(strings.TrimSpace(c.values[key]), 64); err == nil && n > 0 {
		return n
	}
	return fallback
}

func (c Config) Duration(key string, fallback time.Duration) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(c.values[key])); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return fallback
}

func (c Config) Path(parts ...string) string {
	return filepath.Join(append([]string{c.StateDir}, parts...)...)
}

func (c Config) Chnroute(name string) string { return c.Path("chnroute", name) }

func (c Config) GeoDir() string { return c.Path("geoip") }

type Runtime struct {
	Config  Config
	Out     io.Writer
	Preview bool

	geo    *geoip.GeoDB
	geoSet bool
}

func NewRuntime(cfg Config, out io.Writer) *Runtime {
	if out == nil {
		out = os.Stdout
	}
	return &Runtime{Config: cfg, Out: out}
}

func (r *Runtime) GeoDB() *geoip.GeoDB {
	if !r.geoSet {
		dir := r.Config.GeoDir()
		r.geo = geoip.NewGeoDB(
			filepath.Join(dir, "GeoLite2-ASN.mmdb"),
			filepath.Join(dir, "GeoLite2-City.mmdb"),
			filepath.Join(dir, "qqwry.ipdb"),
		)
		r.geoSet = true
	}
	return r.geo
}

func (r *Runtime) InvalidateGeoDB() {
	if r.geo != nil {
		r.geo = nil
	}
	r.geoSet = false
}

func (r *Runtime) Infof(format string, args ...any) {
	fmt.Fprintf(r.Out, "  "+format+"\n", args...)
}

func (r *Runtime) Warnf(format string, args ...any) {
	fmt.Fprintf(r.Out, "  [警告] "+format+"\n", args...)
}
