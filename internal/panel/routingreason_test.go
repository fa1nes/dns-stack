package panel

import "testing"

func TestAuthorityPathNeverClaimsWhatItDidNotCheck(t *testing.T) {
	hop := func(exit string) map[string]any { return map[string]any{"exit": exit} }
	cases := []struct {
		name  string
		rule  string
		hops  []map[string]any
		wants string
	}{
		{"权威没问到", "", nil, "unknown"},
		{"全部直连", "", []map[string]any{hop("direct"), hop("direct")}, "direct"},
		{"全部经香港", "", []map[string]any{hop("tunnel")}, "tunnel"},
		{"一半一半", "", []map[string]any{hop("direct"), hop("tunnel")}, "mixed"},
		{"香港名单压过权威位置", "hk", []map[string]any{hop("direct")}, "hongkong"},
		{"拦截的根本不发出去", "block", []map[string]any{hop("direct")}, "blocked"},
		{"国内名单仍按实际出口显示", "cn", []map[string]any{hop("direct")}, "direct"},
	}
	for _, c := range cases {
		if got := authorityPath(c.rule, c.hops); got != c.wants {
			t.Errorf("%s：得到 %q，期望 %q——没问到权威时说「经香港」等于替没查过的事下结论", c.name, got, c.wants)
		}
	}
}

func TestTheVerdictFollowsMosproxyRuleOrder(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		query string
		rule  string
		hit   string
	}{
		{"香港名单的父域压过国内名单的子域", map[string]string{"manual-gfw.txt": "example.com\n", "manual-cn-zones.txt": "a.example.com\n"},
			"www.a.example.com", "hk", "example.com"},
		{"排除之后回到本机，国内名单才起作用", map[string]string{"manual-gfw.txt": "example.com\n", "manual-exclude.txt": "a.example.com\n",
			"manual-cn-zones.txt": "a.example.com\n"}, "www.a.example.com", "cn", "a.example.com"},
		{"排除之后没进国内名单就是默认", map[string]string{"manual-gfw.txt": "example.com\n", "manual-exclude.txt": "a.example.com\n"},
			"a.example.com", "", ""},
		{"拦截排在最前", map[string]string{"blocklist.txt": "ads.example.com\n", "manual-cn-zones.txt": "example.com\n"},
			"x.ads.example.com", "block", "ads.example.com"},
	}
	for _, c := range cases {
		server := cnResolverServer(t, c.files)
		if rule, hit := server.manualRule(c.query); rule != c.rule || hit != c.hit {
			t.Errorf("%s：面板说 %q（%q），mosproxy 实际按 %q（%q）走", c.name, rule, hit, c.rule, c.hit)
		}
	}
}

func TestManualListsMatchSubdomainsAndExcludeWins(t *testing.T) {
	if got := matchesList("www.sb.sb", []string{"# 注释", "SB.sb."}); got != "sb.sb" {
		t.Errorf("子域应当命中名单里的父域，得到 %q", got)
	}
	if got := matchesList("www.sb.sb", []string{"sb.sb   # 按来源地区给地址"}); got != "sb.sb" {
		t.Errorf("写在后面的说明应当被忽略，得到 %q", got)
	}
	if got := matchesList("xsb.sb", []string{"sb.sb"}); got != "" {
		t.Errorf("xsb.sb 不是 sb.sb 的子域，却命中了 %q", got)
	}
}
