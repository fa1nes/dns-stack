package panel

import (
	"os"
	"strings"
	"testing"
)

func TestPanelStylesheetHasNoUnclosedBlocks(t *testing.T) {
	raw, err := os.ReadFile("../../web/assets/panel.css")
	if err != nil {
		t.Skipf("读不到 panel.css: %v", err)
	}
	depth := 0
	inString := byte(0)
	for i, line := range strings.Split(string(raw), "\n") {
		for j := 0; j < len(line); j++ {
			c := line[j]
			switch {
			case inString != 0:
				if c == inString {
					inString = 0
				}
			case c == '\'' || c == '"':
				inString = c
			case c == '{':
				depth++
			case c == '}':
				depth--
				if depth < 0 {
					t.Fatalf("第 %d 行多了一个 }", i+1)
				}
			}
		}
	}
	if depth != 0 {
		t.Fatalf("panel.css 有 %d 个块没有闭合——浏览器会把后面的所有规则都吞进这个块里，"+
			"整个面板的样式当场乱掉，而 Go 测试和 node --check 都看不出来", depth)
	}
}
