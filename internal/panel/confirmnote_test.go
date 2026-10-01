package panel

import (
	"regexp"
	"strings"
	"testing"
)

var confirmNoteKey = regexp.MustCompile(`(?m)^\s{2}([a-z_]+):\s`)

func TestEveryDangerousOperationExplainsItsConsequence(t *testing.T) {
	script := panelScript(t)
	start := strings.Index(script, "const CONFIRM_NOTE = {")
	if start < 0 {
		t.Fatal("panel.js 里没有 CONFIRM_NOTE 了")
	}
	end := strings.Index(script[start:], "\n};")
	notes := map[string]bool{}
	for _, m := range confirmNoteKey.FindAllStringSubmatch(script[start:start+end], -1) {
		notes[m[1]] = true
	}
	if len(notes) < 3 {
		t.Fatalf("只从 CONFIRM_NOTE 里抽到 %d 个键，抽取规则失效了", len(notes))
	}
	dangerous := 0
	for op, spec := range operationSpecs {
		if !spec.Dangerous || op == "import" {
			continue
		}
		dangerous++
		if !notes[op] {
			t.Errorf("「%s」(%s) 是危险操作，确认框却只会弹一句「可能中断服务或覆盖数据」——"+
				"用户看不出点下去会删掉什么，就只能凭标签猜；而标签往往比实际做的事窄", spec.Label, op)
		}
	}
	if dangerous == 0 {
		t.Fatal("后端注册表里一个危险操作都没找到，这条检查已经空转")
	}
	for op := range notes {
		if spec, ok := operationSpecs[op]; !ok || !spec.Dangerous {
			t.Errorf("CONFIRM_NOTE 里的 %s 不是后端注册的危险操作，这条说明永远不会弹出", op)
		}
	}
}
