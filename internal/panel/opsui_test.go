package panel

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var opButtonRe = regexp.MustCompile(`data-op="([a-z_]+)"`)

func panelMarkup(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, path := range []string{"../../web/index.html", "../../web/assets/panel.js"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("读不到面板资源 %s: %v", path, err)
		}
		all.Write(body)
		all.WriteByte('\n')
	}
	return all.String()
}

func TestEveryOperationHasAButtonOrADedicatedControl(t *testing.T) {
	markup := panelMarkup(t)
	wired := map[string]bool{}
	for _, m := range opButtonRe.FindAllStringSubmatch(markup, -1) {
		wired[m[1]] = true
	}
	drivenByDedicatedControl := []string{"set_cache_ttl", "set_min_ttl", "flush_cache",
		"import", "refresh_routing",
		"delete_query", "delete_domain", "delete_audit"}
	for _, op := range drivenByDedicatedControl {
		wired[op] = true
	}
	for _, op := range operationOrder {
		if !wired[op] {
			t.Errorf("%s 注册了却没有任何面板入口——加了等于点不到", op)
		}
	}
}

func TestEveryButtonPointsAtARegisteredOperation(t *testing.T) {
	markup := panelMarkup(t)
	for _, m := range opButtonRe.FindAllStringSubmatch(markup, -1) {
		if _, ok := operationSpecs[m[1]]; !ok {
			t.Errorf("面板上有 %s 的按钮，但它不在 operationSpecs 里——点下去只会拿到「不支持的操作」", m[1])
		}
	}
}

func TestModuleCountsLineShowsEveryState(t *testing.T) {
	markup := panelMarkup(t)
	line := ""
	for _, candidate := range strings.Split(markup, "\n") {
		if strings.Contains(candidate, "sys-counts") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Skip("panel.js 里找不到模块计数行")
	}
	window := markup[strings.Index(markup, line):]
	if len(window) > 400 {
		window = window[:400]
	}
	for _, state := range []string{"ok", "warn", "down", "unknown"} {
		if !strings.Contains(window, "c."+state) {
			t.Errorf("模块计数行没有渲染 counts.%s——"+
				"少一类就会出现「10 个模块」却只数出 9 个的自相矛盾", state)
		}
	}
}

func TestDangerousOperationsRenderAsDangerButtons(t *testing.T) {
	markup := panelMarkup(t)
	for _, line := range strings.Split(markup, "\n") {
		m := opButtonRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		spec, ok := operationSpecs[m[1]]
		if !ok || !spec.Dangerous {
			continue
		}
		if !strings.Contains(line, "danger") {
			t.Errorf("%s 是危险操作，但按钮没有 danger 样式——用户看不出它需要二次确认\n  %s",
				m[1], strings.TrimSpace(line))
		}
	}
}
