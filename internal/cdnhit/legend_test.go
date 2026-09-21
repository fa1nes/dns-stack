package cdnhit

import (
	"os"
	"strings"
	"testing"
)

var allVerdicts = []Verdict{
	VerdictMainland, VerdictNoSteering, VerdictNoNode,
	VerdictNoEcho, VerdictNotDelivered, VerdictUnresolved,
}

func TestEveryVerdictIsExplainedOnThePanel(t *testing.T) {
	body, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}
	script := string(body)
	start := strings.Index(script, "<b>命中大陆节点</b>")
	if start < 0 {
		t.Skip("panel.js 里找不到判定图例")
	}
	legend := script[start:]
	if end := strings.Index(legend, "</div>"); end > 0 {
		legend = legend[:end]
	}
	for _, verdict := range allVerdicts {
		short := verdict.Short()
		if !strings.Contains(legend, short) {
			t.Errorf("判定 %s 会显示成「%s」，图例里却没有解释它——"+
				"用户看到一个没人解释的词，只能猜", verdict, short)
		}
	}
}
