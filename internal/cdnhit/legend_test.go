package cdnhit

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var allVerdicts = []Verdict{
	VerdictMainland, VerdictNoSteering, VerdictNoNode,
	VerdictNoEcho, VerdictNotDelivered, VerdictUnresolved,
}

func TestEveryVerdictHasAStyleOnThePanel(t *testing.T) {
	body, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}
	script := string(body)
	start := strings.Index(script, "const CDN_VERDICT = {")
	if start < 0 {
		t.Fatal("panel.js 里没有 CDN_VERDICT 了")
	}
	end := strings.Index(script[start:], "};")
	styled := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z_]+):`).FindAllStringSubmatch(script[start:start+end], -1) {
		styled[m[1]] = true
	}
	for _, verdict := range allVerdicts {
		if !styled[string(verdict)] {
			t.Errorf("判定 %s 在面板上没有颜色，会落到默认的灰色，和「不分地区」看起来一样", verdict)
		}
		if verdict.Short() == "" || verdict.Label() == "" {
			t.Errorf("判定 %s 缺少文字", verdict)
		}
	}
	for key := range styled {
		known := false
		for _, verdict := range allVerdicts {
			known = known || string(verdict) == key
		}
		if !known {
			t.Errorf("CDN_VERDICT 里的 %s 后端从不产出", key)
		}
	}
}
