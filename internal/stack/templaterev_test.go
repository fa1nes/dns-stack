package stack

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMosproxyTemplateCarriesTheRevisionTheInstallerCompares(t *testing.T) {
	installer, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Skipf("读不到 install.sh: %v", err)
	}
	if !strings.Contains(string(installer), "template-rev") {
		t.Skip("install.sh 已不再按 template-rev 决定是否重新渲染 mosproxy 配置")
	}
	template, err := os.ReadFile("../../mosproxy/config.template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rev := regexp.MustCompile(`(?m)^# template-rev:[[:space:]]*([0-9]+)`).FindSubmatch(template)
	if rev == nil || string(rev[1]) == "0" {
		t.Fatal("mosproxy 模板里没有 template-rev。install.sh 读不到版本号就按 0 处理，" +
			"每次重装都会重新渲染生产配置。2026-10-01 发现它在全库清注释时被当成注释删掉了——" +
			"这一行是安装脚本的输入，不是注释")
	}
}
