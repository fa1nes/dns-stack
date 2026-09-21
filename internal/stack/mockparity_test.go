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
	for _, m := range All() {
		real[m.Unit] = true
	}
	mocked := map[string]bool{}
	for _, match := range mockUnitRe.FindAllStringSubmatch(block, -1) {
		mocked[match[1]] = true
	}
	for unit := range mocked {
		if !real[unit] {
			t.Errorf("mock 面板还在展示 %s，但模块注册表里已经没有它了——"+
				"删掉一个模块之后，预览用的假数据最容易留在原地，"+
				"照着它调前端就会给一个不存在的东西写界面", unit)
		}
	}
	for unit := range real {
		if !mocked[unit] {
			t.Errorf("模块注册表里有 %s，mock 面板却不展示它——"+
				"前端预览会看不到这一块，样式问题要等上生产才暴露", unit)
		}
	}
}
