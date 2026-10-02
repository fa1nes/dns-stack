package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configWith(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(t.TempDir(), path)
}

func TestGeoIPBaseFallsBackToTheBinaryRepo(t *testing.T) {
	cfg := configWith(t, "DNS_STACK_BINARY_REPO=owner/dns-stack\nGITHUB_REPOSITORY=owner/some-rules-repo\n")
	got := geoipReleaseBase(cfg)
	want := "https://github.com/owner/dns-stack/releases/download/geoip-latest"
	if got != want {
		t.Fatalf("geoip 兜底仓库错了\n  got  %s\n  want %s\n"+
			"geoip-latest 与二进制同仓库；退回 GITHUB_REPOSITORY 会拼出 404 的地址", got, want)
	}
}

func TestGeoIPBasePrefersTheExplicitKeys(t *testing.T) {
	cfg := configWith(t, "GEOIP_RELEASE_REPO=owner/mirror\nDNS_STACK_BINARY_REPO=owner/dns-stack\n")
	if got := geoipReleaseBase(cfg); !strings.Contains(got, "owner/mirror") {
		t.Fatalf("显式的 GEOIP_RELEASE_REPO 应当优先，实际 %s", got)
	}
	cfg = configWith(t, "GEOIP_RELEASE_BASE=https://example.invalid/geo\nDNS_STACK_BINARY_REPO=owner/dns-stack\n")
	if got := geoipReleaseBase(cfg); got != "https://example.invalid/geo" {
		t.Fatalf("显式的 GEOIP_RELEASE_BASE 应当优先，实际 %s", got)
	}
}

func TestEveryKeyInConfigEnvReachesTheCallers(t *testing.T) {
	cfg := configWith(t, "ALERT_WEBHOOK=https://alert.invalid/k\nDOH_PORT=8443\nCHNROUTE_REVERSE_EXCLUDE=0\n")
	if got := cfg.Value("ALERT_WEBHOOK"); got != "https://alert.invalid/k" {
		t.Errorf("ALERT_WEBHOOK 读到 %q——它曾经因为不在白名单里永远是空，看门狗的告警一条都发不出去", got)
	}
	if got := cfg.Int("DOH_PORT", 443); got != 8443 {
		t.Errorf("DOH_PORT 读到 %d——访问控制会装在错误的端口上，真正的入口反而全开", got)
	}
	if got := cfg.Value("CHNROUTE_REVERSE_EXCLUDE"); got != "0" {
		t.Errorf("CHNROUTE_REVERSE_EXCLUDE 读到 %q", got)
	}
}

func TestEveryGeoDBPrefersOurOwnMirror(t *testing.T) {
	cfg := configWith(t, "DNS_STACK_BINARY_REPO=owner/dns-stack\nGEOIP_ENABLE_CITY=1\n")
	base := geoipReleaseBase(cfg)
	if base == "" {
		t.Fatal("兜底仓库算不出来")
	}
	for _, name := range []string{
		"GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb", "qqwry.ipdb",
		"dbip-asn.mmdb", "dbip-city.mmdb",
	} {
		if got := suffixURL(base, name); !strings.HasPrefix(got, base) {
			t.Errorf("%s 没走自家镜像: %s", name, got)
		}
	}
}
