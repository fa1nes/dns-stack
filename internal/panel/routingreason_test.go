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
		{"国内名单仍按实际出口显示", "cn", []map[string]any{hop("direct")}, "direct"},
	}
	for _, c := range cases {
		if got := authorityPath(c.rule, c.hops); got != c.wants {
			t.Errorf("%s：得到 %q，期望 %q——没问到权威时说「经香港」等于替没查过的事下结论", c.name, got, c.wants)
		}
	}
}

func TestManualListsMatchSubdomainsAndExcludeWins(t *testing.T) {
	if got := matchesList("www.sb.sb", []string{"# 注释", "SB.sb."}); got != "sb.sb" {
		t.Errorf("子域应当命中名单里的父域，得到 %q", got)
	}
	if got := matchesList("xsb.sb", []string{"sb.sb"}); got != "" {
		t.Errorf("xsb.sb 不是 sb.sb 的子域，却命中了 %q", got)
	}
}
