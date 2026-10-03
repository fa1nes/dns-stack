package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouteNoApplyWorksAfterTheDomains(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIR", dir)
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
