package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) Store {
	t.Helper()
	return Store{StateDir: t.TempDir()}
}

func TestEnsureFilesCreatesWhatMosproxyNeedsToStart(t *testing.T) {
	s := newStore(t)
	if missing := s.MissingFiles(); len(missing) == 0 {
		t.Fatal("空目录下应报告 blocklist.txt 缺失——它缺了 mosproxy 起不来")
	}
	if err := s.EnsureFiles(); err != nil {
		t.Fatal(err)
	}
	if missing := s.MissingFiles(); len(missing) != 0 {
		t.Fatalf("EnsureFiles 之后不该还有缺失: %v", missing)
	}
	for _, name := range []string{BlocklistFile, ACLFile} {
		if _, err := os.Stat(filepath.Join(s.StateDir, name)); err != nil {
			t.Errorf("%s 未创建: %v", name, err)
		}
	}
	entries, err := s.Blocklist()
	if err != nil || len(entries) != 0 {
		t.Fatalf("新建的黑名单应为空集而不是解析失败: %v %v", entries, err)
	}
}

func TestBlocklistRefusesToSwallowAWholeTLD(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{"com", "cn", "net"} {
		if _, err := s.AddBlocked([]string{bad}); err == nil {
			t.Errorf("拉黑顶级域 %q 必须被拒绝——它会连带屏蔽该 TLD 下的一切", bad)
		}
	}
	if _, err := s.AddBlocked([]string{"not a domain"}); err == nil {
		t.Error("非法域名必须被拒绝")
	}
	if entries, _ := s.Blocklist(); len(entries) != 0 {
		t.Fatalf("被拒绝的条目不该落盘，实得 %v", entries)
	}
}

func TestBlocklistAddIsIdempotentAndSorted(t *testing.T) {
	s := newStore(t)
	added, err := s.AddBlocked([]string{"ads.example.com", "Tracker.Example.NET.", "ads.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("同一轮里的重复应被去掉，实得 %v", added)
	}
	again, err := s.AddBlocked([]string{"ads.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("已存在的域名不该重复写入，实得 %v", again)
	}
	entries, _ := s.Blocklist()
	if strings.Join(entries, ",") != "ads.example.com,tracker.example.net" {
		t.Fatalf("应规范化为小写无尾点并排序，实得 %v", entries)
	}
}

func TestBlocklistRemove(t *testing.T) {
	s := newStore(t)
	if _, err := s.AddBlocked([]string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}
	removed, err := s.RemoveBlocked([]string{"A.example.com."})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "a.example.com" {
		t.Fatalf("移除应做同样的规范化，实得 %v", removed)
	}
	entries, _ := s.Blocklist()
	if len(entries) != 1 || entries[0] != "b.example.com" {
		t.Fatalf("剩余条目 %v", entries)
	}
}

func TestACLCollapsesAndRejectsGarbage(t *testing.T) {
	s := newStore(t)
	if _, err := s.SetACL([]string{"203.0.113.0/25", "203.0.113.128/25", "198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ACL()
	if err != nil {
		t.Fatal(err)
	}
	var rendered []string
	for _, p := range entries {
		rendered = append(rendered, p.String())
	}
	joined := strings.Join(rendered, ",")
	if !strings.Contains(joined, "203.0.113.0/24") {
		t.Fatalf("相邻的两个 /25 应合并成 /24，实得 %s", joined)
	}
	if !strings.Contains(joined, "198.51.100.7/32") {
		t.Fatalf("单个地址应变成 /32，实得 %s", joined)
	}
	if _, err := s.SetACL([]string{"not-a-cidr"}); err == nil {
		t.Error("非法 CIDR 必须被拒绝")
	}
}

func TestACLRemoveCarvesOutTheRange(t *testing.T) {
	s := newStore(t)
	if _, err := s.SetACL([]string{"10.0.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveACL([]string{"10.0.0.128/25"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.ACL()
	if len(entries) != 1 || entries[0].String() != "10.0.0.0/25" {
		t.Fatalf("挖掉后半段应剩 10.0.0.0/25，实得 %v", entries)
	}
}
