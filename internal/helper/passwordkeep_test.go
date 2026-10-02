package helper

import (
	"path/filepath"
	"testing"
)

func TestChangingThePasswordKeepsTheOtherFactors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	seed := map[string]any{
		"hash": "old", "session_key": "old", "username": "owner",
		"totp":              map[string]any{"secret": "JBSWY3DPEHPK3PXP", "enabled": true},
		"oauth":             map[string]any{"client_id": "cid", "allowed_users": []any{"owner"}},
		"password_disabled": true,
	}
	if err := writeAuthRecord(path, seed, false, 0o600); err != nil {
		t.Fatal(err)
	}

	fromPanel, err := passwordRecord(path, "a-new-password-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if !truthy(objectValue(fromPanel["totp"])["enabled"]) || len(objectValue(fromPanel["oauth"])) == 0 {
		t.Fatalf("面板里改密码之后二次认证或 GitHub 登录没了：%v——"+
			"管理员以为两步验证还开着，实际只凭密码就能登录", fromPanel)
	}
	if fromPanel["username"] != "owner" {
		t.Errorf("改密码把用户名弄丢了：%v——之后登录要的用户名突然变成「不需要」", fromPanel["username"])
	}
	if !truthy(fromPanel["password_disabled"]) {
		t.Error("面板里改密码不该顺手重新打开已关闭的密码登录")
	}
	if fromPanel["session_key"] == "old" || fromPanel["hash"] == "old" {
		t.Error("新密码必须轮换哈希与会话密钥，让其它设备上的会话失效")
	}

	fromServer, err := passwordRecord(path, "a-new-password-123", true)
	if err != nil {
		t.Fatal(err)
	}
	if truthy(fromServer["password_disabled"]) {
		t.Error("dns-stack panel-password 是 GitHub 登录坏掉时的救急入口，必须重新启用密码登录")
	}
	if !truthy(objectValue(fromServer["totp"])["enabled"]) {
		t.Error("救急改密码也不该关掉二次认证——丢了验证器用 panel-2fa-reset")
	}
}
