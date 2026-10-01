package panel

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var mockOp = regexp.MustCompile(`\['([a-z_]+)',\s*'([^']*)',\s*(true|false)\]`)

func TestMockOperationListMatchesTheBackendRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../web/mock-api.js")
	if err != nil {
		t.Skipf("读不到 mock-api.js: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "const OPS = [")
	if start < 0 {
		t.Fatal("mock-api.js 里没有 OPS 了")
	}
	end := strings.Index(text[start:], "];")
	mocked := map[string]bool{}
	for _, m := range mockOp.FindAllStringSubmatch(text[start:start+end], -1) {
		op, label, dangerous := m[1], m[2], m[3] == "true"
		mocked[op] = true
		spec, ok := operationSpecs[op]
		if !ok {
			t.Errorf("mock 列了后端不存在的操作 %s，开发面板上点它必然失败", op)
			continue
		}
		if spec.Label != label || spec.Dangerous != dangerous {
			t.Errorf("%s：mock 是 %q/危险=%v，后端是 %q/危险=%v", op, label, dangerous, spec.Label, spec.Dangerous)
		}
	}
	for op, spec := range operationSpecs {
		if !mocked[op] {
			t.Errorf("后端有 %s（%s），mock 里没有——面板靠 /api/ops 判断哪些操作要二次确认，"+
				"开发时缺了它，危险操作会不弹确认框，和生产表现不一致", op, spec.Label)
		}
	}
}
