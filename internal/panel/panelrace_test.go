package panel

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var loaderStart = regexp.MustCompile(`(?m)^(?:async )?function ([A-Za-z0-9_]+)\(`)

// 这些加载函数都由用户可以连点的控件驱动（标签页、下拉框、输入框）。
// 两次请求的回包会乱序，晚发早回的那个会被后到的旧回包整个盖掉，
// 于是标题、计数和表格各来自不同的一次请求。
var mustGuardAgainstOutOfOrderResponses = []string{
	"loadQueries", "loadDomains", "loadDomainSummary",
	"loadLogs", "loadCdnHit", "loadIpLookup",
}

func panelScript(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}
	return string(body)
}

func functionBodies(script string) map[string]string {
	starts := loaderStart.FindAllStringSubmatchIndex(script, -1)
	bodies := map[string]string{}
	for i, m := range starts {
		name := script[m[2]:m[3]]
		end := len(script)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		bodies[name] = script[m[0]:end]
	}
	return bodies
}

func TestSwitchableLoadersIgnoreStaleResponses(t *testing.T) {
	bodies := functionBodies(panelScript(t))
	for _, name := range mustGuardAgainstOutOfOrderResponses {
		body, found := bodies[name]
		if !found {
			t.Errorf("panel.js 里没有 %s 了——这份清单要跟着改", name)
			continue
		}
		if !strings.Contains(body, "latestOnly(") {
			t.Errorf("%s 会被用户连点触发多次，却没有 latestOnly() 守卫——"+
				"先发的请求后回来时会把新结果盖掉，页面上的数字和标题就对不上了", name)
		}
	}
}

func TestLatestOnlyGuardStillExists(t *testing.T) {
	script := panelScript(t)
	if !strings.Contains(script, "function latestOnly(") {
		t.Fatal("latestOnly 没了，上面那条守卫检查会全部变成空转")
	}
}
