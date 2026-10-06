package helper

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUsernamesAreNormalisedAndValidated(t *testing.T) {
	for raw, want := range map[string]string{" Alice ": "alice", "ops.team-1": "ops.team-1", "x_y": "x_y"} {
		if got, err := NormalizeUsername(raw); err != nil || got != want {
			t.Errorf("NormalizeUsername(%q) = %q, %v；期望 %q", raw, got, err, want)
		}
	}
	for _, bad := range []string{"", "a", "-lead", ".dot", "has space", "名字", "a/b", strings.Repeat("x", 33)} {
		if _, err := NormalizeUsername(bad); err == nil {
			t.Errorf("用户名 %q 应当被拒绝", bad)
		}
	}
}

func TestSettingTheUsernameKeepsEverythingElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := SetPanelUsername(path, "alice"); err == nil {
		t.Fatal("还没设密码时不该凭空生成一份认证记录")
	}
	writeRecord(t, path, map[string]any{
		"hash": "h", "session_key": "k",
		"totp": map[string]any{"secret": "S", "enabled": true},
	})
	if err := SetPanelUsername(path, "Alice"); err != nil {
		t.Fatal(err)
	}
	got := loadAuthRecord(path)
	if got["username"] != "alice" {
		t.Fatalf("用户名应当按小写保存，实际 %v", got["username"])
	}
	if got["hash"] != "h" || got["session_key"] != "k" || !truthy(objectValue(got["totp"])["enabled"]) {
		t.Fatalf("改用户名不该动密码、会话或二次认证：%v", got)
	}
	if err := SetPanelUsername(path, "has space"); err == nil {
		t.Fatal("非法用户名应当报错")
	}
	if loadAuthRecord(path)["username"] != "alice" {
		t.Fatal("被拒绝的用户名不该写进文件")
	}
}

func TestServerSidePasswordResetSetsOrKeepsTheUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := SetPanelPassword(path, "Admin", "a-long-enough-password"); err != nil {
		t.Fatal(err)
	}
	if got := loadAuthRecord(path)["username"]; got != "admin" {
		t.Fatalf("panel-password 带了用户名却没写进去：%v", got)
	}
	if err := SetPanelPassword(path, "", "another-long-password"); err != nil {
		t.Fatal(err)
	}
	if got := loadAuthRecord(path)["username"]; got != "admin" {
		t.Fatalf("用户名留空应当保留原来的，实际 %v——救急改密码之后登录会突然认不出账号", got)
	}
}
