package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouteListsOnlyChangeOnTheDomesticNode(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "config.env")
	if err := os.WriteFile(conf, []byte("ROLE=offshore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE_DIR", dir)
	t.Setenv("CONFIG_FILE", conf)
	if err := cmdRoute([]string{"add", "cn", "sb.sb", "--no-apply"}); err == nil {
		t.Fatal("香港节点上改了国内名单——随后的流水线会改写香港 Unbound 的 ECS 配置")
	}
	if _, err := os.Stat(filepath.Join(dir, "manual-cn-zones.txt")); err == nil {
		t.Fatal("被拒绝的请求仍然写了名单文件")
	}
	if err := cmdRoute(nil); err != nil {
		t.Fatalf("只是列出名单不该受角色限制：%v", err)
	}
}

func TestRouteNoApplyWorksAfterTheDomains(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "config.env")
	if err := os.WriteFile(conf, []byte("ROLE=cn-resolver\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE_DIR", dir)
	t.Setenv("CONFIG_FILE", conf)
	if err := cmdRoute([]string{"add", "cn", "sb.sb", "--no-apply"}); err != nil {
		t.Fatalf("用法里写的是「<域名>... [--no-apply]」，放在域名后面却报错：%v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "manual-cn-zones.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "\nsb.sb\n") || strings.Contains(string(body), "no-apply") {
		t.Fatalf("名单写成了：\n%s", body)
	}
}
