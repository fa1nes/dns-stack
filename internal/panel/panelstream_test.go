package panel

import (
	"regexp"
	"strings"
	"testing"
)

var errorHandler = regexp.MustCompile(`(?s)\bes\.onerror\s*=\s*\(\)\s*=>\s*\{(.*?)\n  \};`)

var accumulating = []string{"toast(", "push(", "concat(", "appendHtml(", "prependHtml("}

func TestStreamErrorHandlersStayIdempotent(t *testing.T) {
	script := panelScript(t)
	handlers := errorHandler.FindAllStringSubmatch(script, -1)
	if len(handlers) == 0 {
		t.Fatal("找不到任何 es.onerror 处理器，判据已失效——" +
			"panel.js 里 EventSource 的错误处理写法变了，下面的检查会全部空转")
	}
	for _, handler := range handlers {
		for _, call := range accumulating {
			if strings.Contains(handler[1], call) {
				t.Errorf("EventSource 的 onerror 里出现了会累积的 %s——"+
					"onerror 不是「失败一次」而是「每次重连尝试都触发」，"+
					"浏览器默认约 3 秒重试一次，而 err 类 toast 存活 12 秒；"+
					"断流后界面会被永不停止的提示埋掉。onerror 只能做幂等的状态表达", call)
			}
		}
	}
}

func TestEveryControlInTheStreamUrlRestartsTheStream(t *testing.T) {
	script := panelScript(t)
	body, found := functionBodies(script)["startLogFollow"]
	if !found {
		t.Fatal("panel.js 里没有 startLogFollow 了")
	}
	open := strings.Index(body, "new EventSource(")
	if open < 0 {
		t.Fatal("startLogFollow 里找不到 new EventSource，判据已失效")
	}
	controls := regexp.MustCompile(`\$\('#([A-Za-z0-9_-]+)'\)\.value`).FindAllStringSubmatch(body[:open], -1)
	if len(controls) == 0 {
		t.Fatal("startLogFollow 建流前不再从控件读值，判据已失效")
	}
	seen := map[string]bool{}
	for _, control := range controls {
		id := control[1]
		if seen[id] {
			continue
		}
		seen[id] = true
		handler := changeHandlerFor(script, id)
		if handler == "" {
			t.Errorf("#%s 的取值进了日志流的 URL，却找不到它的 change 处理器", id)
			continue
		}
		if !strings.Contains(handler, "startLogFollow") {
			t.Errorf("#%s 的取值决定了实时流请求什么，但改动它时没有重建流——"+
				"历史那一段会按新条件重新拉取，实时推来的新行仍按旧条件，"+
				"控件显示的筛选和用户看到的新内容对不上", id)
		}
	}
}

func changeHandlerFor(script, id string) string {
	anchor := "$('#" + id + "').addEventListener('change'"
	start := strings.Index(script, anchor)
	if start < 0 {
		return ""
	}
	rest := script[start+strings.Index(script[start:], ".addEventListener("):]
	depth := 0
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
