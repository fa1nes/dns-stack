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

func TestConfigKeysCoverEveryKeyTheStepsRead(t *testing.T) {
	allowed := map[string]bool{}
	for _, key := range configKeys {
		allowed[key] = true
	}
	for _, key := range []string{
		"DNS_STACK_BINARY_REPO", "GEOIP_RELEASE_REPO", "GEOIP_RELEASE_BASE",
		"CDN_RULES_BASE", "CDN_RULES_MIRROR_1", "CDN_RULES_MIRROR_2",
	} {
		if !allowed[key] {
			t.Errorf("%s 被流水线读取，却不在 configKeys 白名单里——"+
				"config.env 里配了也读不到，是一条静默失效的配置", key)
		}
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

func TestNoGeoDBDefaultsToRawGithubusercontent(t *testing.T) {
	body, err := os.ReadFile("steps.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "raw.githubusercontent.com") {
		t.Fatal("归属库默认源不该用 raw.githubusercontent.com——" +
			"它在国内会超时，GeoLite2-City 就是这样 48 天没更新的")
	}
}
