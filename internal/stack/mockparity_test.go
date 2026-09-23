package stack

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var mockUnitRe = regexp.MustCompile(`'(dns-stack-[a-z-]+|mosproxy|unbound|wg-quick@wg0)'`)

func TestMockPanelListsTheSameModulesAsTheRegistry(t *testing.T) {
	body, err := os.ReadFile("../../web/mock-api.js")
	if err != nil {
		t.Skipf("读不到 mock-api.js: %v", err)
	}
	block := string(body)
	start := strings.Index(block, "const MODULES = [")
	if start < 0 {
		t.Skip("mock-api.js 里没有 MODULES 清单")
	}
	end := strings.Index(block[start:], "];")
	if end < 0 {
		t.Fatal("MODULES 清单没有结束括号")
	}
	block = block[start : start+end]

	real := map[string]bool{}
	for _, m := range ForRole(RoleCNResolver) {
		real[m.Unit] = true
	}
	mocked := map[string]bool{}
	for _, match := range mockUnitRe.FindAllStringSubmatch(block, -1) {
		mocked[match[1]] = true
	}
	for unit := range mocked {
		if !real[unit] {
			t.Errorf("mock 面板还在展示 %s，但 cn-resolver 的模块注册表里没有它——"+
				"面板只跑在国内节点，预览里多出一个它看不到的模块，"+
				"照着它调前端就会给一个不存在的东西写界面", unit)
		}
	}
	for unit := range real {
		if !mocked[unit] {
			t.Errorf("cn-resolver 的模块注册表里有 %s，mock 面板却不展示它——"+
				"前端预览会看不到这一块，样式问题要等上生产才暴露", unit)
		}
	}
}

func TestMockNamesNoUnitOutsideTheRegistry(t *testing.T) {
	body, err := os.ReadFile("../../web/mock-api.js")
	if err != nil {
		t.Skipf("读不到 mock-api.js: %v", err)
	}
	for _, match := range mockUnitRe.FindAllStringSubmatch(string(body), -1) {
		unit := match[1]
		if _, found := Lookup(unit); !found {
			t.Errorf("mock-api.js 里还写着 %s，模块注册表里没有这个单元——"+
				"MODULES 清单之外的地方（状态注记、图表、示例数据）同样会腐烂，"+
				"而且不会被前端预览显示成错误，只是那一段永远不生效", unit)
		}
	}
}
