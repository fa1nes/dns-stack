package panel

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var loaderStart = regexp.MustCompile(`(?m)^(?:async )?function ([A-Za-z0-9_]+)\(`)

var dynamicGet = regexp.MustCompile(`await api(?:Cached)?\([^\n]*`)

var mustGuardAgainstOutOfOrderResponses = []string{
	"loadQueries", "loadDomains", "loadDomainSummary",
	"loadLogs", "loadCdnHit", "loadIpLookup",
	"loadTimeseries", "showDomain",
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

func buildsRequestFromChangingParams(body string) bool {
	for _, call := range dynamicGet.FindAllString(body, -1) {
		if strings.Contains(call, "method") {
			continue
		}
		if strings.Contains(call, "+") || strings.Contains(call, "${") {
			return true
		}
	}
	return false
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

func TestEveryLoaderWithAChangingPathIsOnTheGuardList(t *testing.T) {
	listed := map[string]bool{}
	for _, name := range mustGuardAgainstOutOfOrderResponses {
		listed[name] = true
	}
	for name, body := range functionBodies(panelScript(t)) {
		if !buildsRequestFromChangingParams(body) || listed[name] {
			continue
		}
		t.Errorf("%s 把会变的参数拼进了 GET 路径，却既不在守卫清单里也没有 latestOnly()——"+
			"上面那条检查只认手写清单，新加的 loader 漏进来时它不会报警", name)
	}
}

func TestGuardListDoesNotOutliveTheCriterionThatFeedsIt(t *testing.T) {
	bodies := functionBodies(panelScript(t))
	matched := 0
	for _, body := range bodies {
		if buildsRequestFromChangingParams(body) {
			matched++
		}
	}
	if matched == 0 {
		t.Fatal("判据一个 loader 都没匹配上，说明 panel.js 的请求写法变了，" +
			"上面那条补漏检查已经变成空转")
	}
}

func TestLatestOnlyGuardStillExists(t *testing.T) {
	script := panelScript(t)
	if !strings.Contains(script, "function latestOnly(") {
		t.Fatal("latestOnly 没了，上面那条守卫检查会全部变成空转")
	}
}

func TestOverviewPollLoopCannotBeStartedTwice(t *testing.T) {
	body, found := functionBodies(panelScript(t))["startOverview"]
	if !found {
		t.Fatal("panel.js 里没有 startOverview 了")
	}
	if !strings.Contains(body, "latestOnly(") {
		t.Error("startOverview 没有代号守卫——切出 overview 再切回来会让上一轮 tick 在 " +
			"await 之后重新发现 page==='overview' 并自己续上定时器，两条 5 秒轮询同时跑")
	}
	if strings.Contains(body, "clearInterval") {
		t.Error("startOverview 的句柄来自 setTimeout，却用 clearInterval 去取消，读代码的人会误判它是间隔定时器")
	}
}
