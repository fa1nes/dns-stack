package panel

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serverWithACL(t *testing.T, entries ...string) *Server {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acl.txt"), []byte(strings.Join(entries, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath: filepath.Join(dir, "auth.json"), DBPath: filepath.Join(dir, "collector.db")})
}

func TestACLLockoutGuardOnAPubliclyBoundPanel(t *testing.T) {
	server := serverWithACL(t, "198.51.100.0/24", "203.0.113.0/24")
	remote := httptest.NewRequest("POST", "/api/access", nil)
	remote.RemoteAddr = "198.51.100.7:40000"

	for _, tc := range []struct {
		name    string
		action  string
		entries []string
		blocked bool
		reason  string
	}{
		{"删掉自己所在网段", "acl_remove", []string{"198.51.100.0/24"}, true, "锁在门外"},
		{"删掉别人的网段", "acl_remove", []string{"203.0.113.0/24"}, false, ""},
		{"删到一条不剩", "acl_remove", []string{"198.51.100.0/24", "203.0.113.0/24"}, true, "全网开放"},
		{"加一条不含自己的网段", "acl_add", []string{"192.0.2.0/24"}, false, ""},
		{"非法条目", "acl_add", []string{"not-a-cidr"}, true, "非法条目"},
	} {
		got := server.aclLockoutCheck(remote, tc.action, tc.entries)
		if blocked := got != ""; blocked != tc.blocked {
			t.Errorf("%s: 拦截=%v，期望 %v（消息 %q）", tc.name, blocked, tc.blocked, got)
			continue
		}
		if tc.reason != "" && !strings.Contains(got, tc.reason) {
			t.Errorf("%s: 消息 %q 里应当说明「%s」", tc.name, got, tc.reason)
		}
	}
}

func TestEmptyWhitelistIsDescribedAsOpenNotAsLockedOut(t *testing.T) {
	server := serverWithACL(t, "198.51.100.0/24")
	remote := httptest.NewRequest("POST", "/api/access", nil)
	remote.RemoteAddr = "198.51.100.7:40000"
	got := server.aclLockoutCheck(remote, "acl_remove", []string{"198.51.100.0/24"})
	if strings.Contains(got, "挡在外面") {
		t.Errorf("消息 %q 说空白名单会挡住所有人——可 acl.txt 的约定和 dns-stack acl apply 的实际行为都是"+
			"「空文件 = 不启用访问控制（全网可查）」，这句提示描述的是一个不会发生的后果", got)
	}
}
