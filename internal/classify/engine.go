package classify

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

const (
	DefaultConfigPath  = "/etc/dns-stack/config.env"
	DefaultStateDir    = "/var/lib/dns-stack"
	DefaultDirect4Path = "/var/lib/dns-stack/chnroute/direct4.txt"
	DefaultCNResolver  = "10.100.0.2"
	DefaultDeployKey   = "/etc/dns-stack/secrets/github_deploy_key"
	DefaultPullKey     = "/etc/dns-stack/secrets/cn-pull-key"
)

type Config struct {
	DBPath      string
	StateDir    string
	Direct4Path string
	PSLPath     string

	CNResolver      string
	ForeignResolver string
	ResolverPort    int
	QueryTimeout    time.Duration

	ClassifyConcurrency  int
	AuthorityConcurrency int
	RecheckMaxAge        time.Duration
	PublishMaxStale      time.Duration

	Repository    string
	Branch        string
	CommitName    string
	CommitEmail   string
	DeployKeyPath string

	CNSSHUser   string
	CNSSHPort   int
	PullKeyPath string
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	env, err := readEnvFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Config{}, err
	}
	state := envOr(env, "STATE_DIR", DefaultStateDir)
	cfg := Config{
		DBPath:      envOr(env, "CLASSIFIER_DB", DefaultDBPath),
		StateDir:    state,
		Direct4Path: firstNonEmpty(os.Getenv("DNS_STACK_DIRECT4_FILE"), env["DIRECT4_FILE"], DefaultDirect4Path),
		PSLPath:     firstNonEmpty(os.Getenv("DNS_STACK_PSL_FILE"), env["PSL_FILE"]),

		CNResolver:      envOr(env, "CN_SERVER_WG_IP", DefaultCNResolver),
		ForeignResolver: firstNonEmpty(env["HK_DNS_WG_IP"], env["FOREIGN_DNS_WG_IP"]),
		ResolverPort:    envPositive(env, "UNBOUND_PORT", 5335),
		QueryTimeout:    time.Duration(envPositive(env, "QUERY_TIMEOUT_SEC", 15)) * time.Second,

		ClassifyConcurrency:  envPositive(env, "CLASSIFY_CONCURRENCY", 6),
		AuthorityConcurrency: envPositive(env, "AUTHORITY_CONCURRENCY", 8),
		RecheckMaxAge:        time.Duration(envPositive(env, "RULE_RECHECK_MAX_AGE_SEC", 6*3600)) * time.Second,
		PublishMaxStale:      time.Duration(envPositive(env, "RULE_PUBLISH_MAX_STALE_SEC", 86400)) * time.Second,

		Repository:    env["GITHUB_REPOSITORY"],
		Branch:        envOr(env, "GITHUB_BRANCH", "main"),
		CommitName:    envOr(env, "GIT_COMMIT_NAME", "dns-stack-bot"),
		CommitEmail:   envOr(env, "GIT_COMMIT_EMAIL", "dns-stack@localhost"),
		DeployKeyPath: envOr(env, "GITHUB_DEPLOY_KEY", DefaultDeployKey),

		CNSSHUser:   envOr(env, "CN_SERVER_SSH_USER", "root"),
		CNSSHPort:   envPositive(env, "CN_SERVER_SSH_PORT", 22),
		PullKeyPath: envOr(env, "CN_PULL_KEY", DefaultPullKey),
	}
	return cfg, nil
}

func readEnvFile(path string) (map[string]string, error) {
	out := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return out, sc.Err()
}

func envOr(env map[string]string, key, fallback string) string {
	if value := strings.TrimSpace(env[key]); value != "" {
		return value
	}
	return fallback
}

func envPositive(env map[string]string, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(env[key]))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			return v
		}
	}
	return ""
}

type Engine struct {
	Config Config
	Store  *Store

	now      func() time.Time
	direct4  *ipset.Set
	psl      *domain.PSL
	cn       *resolve.Client
	foreign  *resolve.Client
	polluted *cidrutil.Set
}

func Open(cfg Config, now func() time.Time) (*Engine, error) {
	if now == nil {
		now = time.Now
	}
	store, err := OpenStore(cfg.DBPath, now)
	if err != nil {
		return nil, err
	}
	return &Engine{Config: cfg, Store: store, now: now}, nil
}

func (e *Engine) Close() error { return e.Store.Close() }

func (e *Engine) Direct4() (*ipset.Set, error) {
	if e.direct4 != nil {
		return e.direct4, nil
	}
	file, err := os.Open(e.Config.Direct4Path)
	if err != nil {
		return nil, fmt.Errorf("缺少 direct4 快照 %s，双视角与权威判定都拿不到落点判据，拒绝以这种状态运行: %w",
			e.Config.Direct4Path, err)
	}
	defer file.Close()
	loaded, err := ipset.LoadReader(file, ipset.LoadOptions{GlobalOnly: true})
	if err != nil {
		return nil, err
	}
	if loaded.Set.Len() == 0 {
		return nil, fmt.Errorf("%s 里没有有效的全局 IPv4 网段，拒绝判定", e.Config.Direct4Path)
	}
	e.direct4 = loaded.Set
	return e.direct4, nil
}

func (e *Engine) Mainland() (Mainland, error) {
	set, err := e.Direct4()
	if err != nil {
		return nil, err
	}
	return direct4Matcher{set}, nil
}

type direct4Matcher struct{ set *ipset.Set }

func (m direct4Matcher) IsMainland(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.Is4() && ipset.IsGlobalAddr(addr) && m.set.Contains(addr)
}

func (e *Engine) PSL() (*domain.PSL, error) {
	if e.psl != nil {
		return e.psl, nil
	}
	var paths []string
	if e.Config.PSLPath != "" {
		paths = append([]string{e.Config.PSLPath}, domain.DefaultPSLPaths...)
	}
	psl, note := domain.LoadPSL(paths)
	if psl == nil {
		return nil, fmt.Errorf("缺少有效的 Public Suffix List，拒绝执行权威判定（%s）", note)
	}
	e.psl = psl
	return psl, nil
}

func (e *Engine) Resolvers() (cn, foreign *resolve.Client, err error) {
	if e.cn != nil && e.foreign != nil {
		return e.cn, e.foreign, nil
	}
	if e.Config.ForeignResolver == "" {
		return nil, nil, fmt.Errorf("缺少境外递归器地址（HK_DNS_WG_IP 或 FOREIGN_DNS_WG_IP），拒绝单视角分类")
	}
	e.cn, err = resolve.NewClient(e.Config.CNResolver, e.Config.ResolverPort, e.Config.QueryTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("国内视角解析器不可用: %w", err)
	}
	e.foreign, err = resolve.NewClient(e.Config.ForeignResolver, e.Config.ResolverPort, e.Config.QueryTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("境外视角解析器不可用: %w", err)
	}
	return e.cn, e.foreign, nil
}

func (e *Engine) Polluted() (*cidrutil.Set, error) {
	if e.polluted != nil {
		return e.polluted, nil
	}
	values, err := e.Store.ActiveCIDRs("polluted")
	if err != nil {
		return nil, err
	}
	set, _ := cidrutil.ParseSet(values)
	e.polluted = set
	return set, nil
}

func (e *Engine) invalidatePolluted() { e.polluted = nil }
