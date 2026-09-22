package panel

import (
	"os"
	"strings"
	"testing"
)

func TestSelfQueryResultCarriesItsCaveatWhereItIsSeen(t *testing.T) {
	body, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}
	script := string(body)
	start := strings.Index(script, "★ 最终命中")
	if start < 0 {
		t.Skip("panel.js 里找不到解析结果那一行")
	}
	window := script[start:]
	if len(window) > 900 {
		window = window[:900]
	}
	if !strings.Contains(window, "viewer_subnet") {
		t.Error("「最终命中」这一行没有按有没有客户端子网区分——" +
			"面板自查不带 ECS，按位置调度的域名会回隧道出口那一侧的节点，" +
			"这一行会把一个正常的系统显示成「解析到境外」")
	}
	if !strings.Contains(window, "不等于你的设备拿到的地址") {
		t.Error("没带 ECS 时缺少显眼的说明——" +
			"说明藏在折叠的「更多判定细节」里等于没有，" +
			"看到的人只会得出「分流坏了」的结论")
	}
}
