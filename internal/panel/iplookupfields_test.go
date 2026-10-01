package panel

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"testing"
)

func TestIPLookupShipsOnlyWhatItsRendererReads(t *testing.T) {
	dir := t.TempDir()
	server := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath: filepath.Join(dir, "auth.json"), DBPath: filepath.Join(dir, "collector.db")})
	response := exportRequest(t, server, "/api/ip-lookup?ip=192.0.2.1")
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("ip-lookup 返回 %d：%s", response.Code, response.Body.String())
	}
	if len(body) < 4 {
		t.Fatalf("ip-lookup 只返回了 %v，测试没打到真正的结果分支", body)
	}
	renderer, found := functionBodies(panelScript(t))["renderIpLookup"]
	if !found {
		t.Fatal("panel.js 里没有 renderIpLookup 了")
	}
	for key := range body {
		if !regexp.MustCompile(`\bd\.` + regexp.QuoteMeta(key) + `\b`).MatchString(renderer) {
			t.Errorf("/api/ip-lookup 返回 %s，renderIpLookup 却不读它——"+
				"整个前端里按字面搜索会被别的接口里的同名字段蒙过去，所以这里只看这个接口自己的渲染函数", key)
		}
	}
}
