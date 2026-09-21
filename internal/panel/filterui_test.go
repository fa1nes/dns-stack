package panel

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var selectIDRe = regexp.MustCompile(`<select id="(f[A-Za-z]+)"`)
var extraFiltersRe = regexp.MustCompile(`const EXTRA_FILTERS = \[([^\]]*)\]`)

func TestCollapsedFiltersAreAllCounted(t *testing.T) {
	html, err := os.ReadFile("../../web/index.html")
	if err != nil {
		t.Skipf("读不到 index.html: %v", err)
	}
	js, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}

	markup := string(html)
	start := strings.Index(markup, `id="filterMore"`)
	if start < 0 {
		t.Skip("index.html 里没有折叠筛选区")
	}
	end := strings.Index(markup[start:], `id="btnReset"`)
	if end < 0 {
		t.Fatal("折叠筛选区里找不到重置按钮，无法界定范围")
	}
	collapsed := []string{}
	for _, m := range selectIDRe.FindAllStringSubmatch(markup[start:start+end], -1) {
		collapsed = append(collapsed, "#"+m[1])
	}

	counted := []string{}
	if m := extraFiltersRe.FindStringSubmatch(string(js)); m != nil {
		for _, raw := range strings.Split(m[1], ",") {
			if id := strings.Trim(strings.TrimSpace(raw), "'\""); id != "" {
				counted = append(counted, id)
			}
		}
	}
	sort.Strings(collapsed)
	sort.Strings(counted)
	if strings.Join(collapsed, ",") != strings.Join(counted, ",") {
		t.Errorf("折叠区里的筛选器是 %v，EXTRA_FILTERS 数的是 %v——"+
			"对不上的那个会被收起来、角标又不算它，用户看着没有任何筛选，"+
			"列表却是空的，找不到原因", collapsed, counted)
	}
	if len(collapsed) == 0 {
		t.Error("折叠区里一个筛选器都没有，这个测试已经失去意义")
	}
}
