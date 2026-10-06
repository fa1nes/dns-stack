package pipeline

import (
	"net/netip"
	"strings"
	"testing"
)

func aclFixture(t *testing.T, values ...string) ACLConfig {
	t.Helper()
	cfg := ACLConfig{DoHPort: 443, DoTPort: 853}
	for _, v := range values {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", v, err)
		}
		cfg.Prefixes = append(cfg.Prefixes, prefix)
	}
	return cfg
}

func TestACLRefusesToInstallAnEmptyWhitelist(t *testing.T) {
	if _, err := aclFixture(t).Render(); err == nil {
		t.Fatal("空白名单会把所有客户端挡在外面，必须拒绝下发而不是装一条 drop-all")
	}
}

func TestACLRefusesWhenNoPortIsProtected(t *testing.T) {
	cfg := aclFixture(t, "203.0.113.0/24")
	cfg.DoHPort, cfg.DoTPort = 0, 0
	if _, err := cfg.Render(); err == nil {
		t.Fatal("没有可保护的端口时应当报错，而不是装一条匹配不到任何东西的链")
	}
}

func TestACLAlwaysLetsLoopbackAndTunnelThrough(t *testing.T) {
	script, err := aclFixture(t, "203.0.113.0/24").Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iif lo accept",
		"ip saddr 10.100.0.0/24 accept",
		"ct state established,related accept",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("缺少 %q——本机自检的 DoH 探针走回环，挡掉它等于 selfcheck 永远红\n%s", want, script)
		}
	}
	if !strings.Contains(script, "th dport { 443, 853 } counter drop") {
		t.Errorf("缺少兜底 drop，白名单就形同虚设\n%s", script)
	}
	lo := strings.Index(script, "iif lo accept")
	drop := strings.Index(script, "counter drop")
	if lo < 0 || drop < 0 || lo > drop {
		t.Error("放行回环的规则必须排在兜底 drop 之前，否则顺序错了照样被拦")
	}
}

func TestACLKeepsFamiliesSeparate(t *testing.T) {
	script, err := aclFixture(t, "203.0.113.0/24", "2001:db8::/32").Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "ip saddr @"+aclSet4) {
		t.Error("缺少 v4 白名单匹配")
	}
	if !strings.Contains(script, "ip6 saddr @"+aclSet6) {
		t.Error("缺少 v6 白名单匹配")
	}
	if !strings.Contains(script, "add element inet dns_acl "+aclSet4+" { 203.0.113.0/24 }") {
		t.Error("v4 前缀没进 v4 集合")
	}
	if !strings.Contains(script, "add element inet dns_acl "+aclSet6+" { 2001:db8::/32 }") {
		t.Error("v6 前缀没进 v6 集合")
	}
}

func TestACLDropsDuplicatePorts(t *testing.T) {
	cfg := aclFixture(t, "203.0.113.0/24")
	cfg.DoTPort = cfg.DoHPort
	script, err := cfg.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "{ 443, 443 }") {
		t.Errorf("同一个端口不该出现两次\n%s", script)
	}
	if !strings.Contains(script, "th dport { 443 }") {
		t.Errorf("去重后应只剩一个端口\n%s", script)
	}
}

func TestACLLivesInItsOwnTableAndReplacesItAtomically(t *testing.T) {
	script, err := aclFixture(t, "203.0.113.0/24").Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "dns_route") {
		t.Errorf("访问控制不能放进分流的 dns_route 表：分流服务随 wg0 停止时会整表删除，"+
			"入口就在隧道断开的那一刻对全网敞开\n%s", script)
	}
	lines := strings.Split(strings.TrimSpace(script), "\n")
	if len(lines) < 3 || lines[0] != "add table inet dns_acl" || lines[1] != "delete table inet dns_acl" {
		t.Errorf("应当在同一个 nft 事务里先删后建，旧规则才不会和新规则叠加\n%s", script)
	}
}
