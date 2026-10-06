package opsctl

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestTestDomainFollowsMosproxyRuleOrder(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		query string
		rule  manualRule
		hit   string
	}{
		{"香港名单的父域压过国内名单的子域", map[string]string{"manual-gfw.txt": "example.com\n", "manual-cn-zones.txt": "a.example.com\n"},
			"www.a.example.com", hkRule, "example.com"},
		{"排除之后回到本机，国内名单才起作用", map[string]string{"manual-gfw.txt": "example.com\n", "manual-exclude.txt": "a.example.com\n",
			"manual-cn-zones.txt": "a.example.com\n"}, "a.example.com", cnRule, "a.example.com"},
		{"只有排除", map[string]string{"manual-gfw.txt": "example.com\n", "manual-exclude.txt": "a.example.com\n"},
			"a.example.com", excludeRule, "a.example.com"},
		{"拦截排在最前", map[string]string{"blocklist.txt": "ads.example.com\n", "manual-cn-zones.txt": "example.com\n"},
			"x.ads.example.com", blockRule, "ads.example.com"},
		{"名单里写了大写", map[string]string{"manual-cn-zones.txt": "SB.SB.\n"}, "www.sb.sb", cnRule, "sb.sb"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		for file, body := range c.files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ctl := &Ctl{StateDir: dir, Out: io.Discard}
		if rule, hit := ctl.matchManualRule(c.query); rule != c.rule || hit != c.hit {
			t.Errorf("%s：dns-stack test 说 %q（%q），mosproxy 实际按 %q（%q）走", c.name, rule.label, hit, c.rule.label, c.hit)
		}
	}
}
