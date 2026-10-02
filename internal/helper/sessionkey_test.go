package helper

import (
	"path/filepath"
	"testing"
)

func TestRotatingTheSessionKeyKeepsEverythingElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := RotateSessionKey(path); err == nil {
		t.Fatal("还没设密码时不该凭空生成一份认证记录")
	}
	seed := map[string]any{
		"hash": "h", "salt": "s", "session_key": "old",
		"totp":  map[string]any{"secret": "S", "enabled": true},
		"oauth": map[string]any{"client_id": "cid"},
	}
	if err := writeAuthRecord(path, seed, false, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RotateSessionKey(path); err != nil {
		t.Fatal(err)
	}
	got := loadAuthRecord(path)
	if got["session_key"] == "old" || got["session_key"] == "" {
		t.Fatalf("会话密钥没有换掉：%v——其它设备上的令牌会继续有效", got["session_key"])
	}
	if got["hash"] != "h" || !truthy(objectValue(got["totp"])["enabled"]) || objectValue(got["oauth"])["client_id"] != "cid" {
		t.Fatalf("轮换会话密钥不该动密码、二次认证或 GitHub 配置：%v", got)
	}
}

func TestRemovingAnAllowedUserForgetsItsBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeRecord(t, path, map[string]any{"oauth": map[string]any{
		"client_id": "cid", "allowed_users": []any{"alice", "bob"},
		"bound_ids": map[string]any{"alice": "1", "bob": "2"},
	}})
	merged := MergeAuthUpdate(path, map[string]any{"oauth": map[string]any{
		"client_id": "cid", "allowed_users": []any{"Alice"},
	}})
	bound := objectValue(objectValue(merged["oauth"])["bound_ids"])
	if bound["alice"] != "1" {
		t.Errorf("仍然允许的账号应当保留绑定：%v", bound)
	}
	if _, kept := bound["bob"]; kept {
		t.Errorf("移出允许列表的账号还留着 ID 绑定：%v——之后把这个用户名加回来（哪怕是换了账号），"+
			"登录会一直被「已不是当初绑定的那个账号」挡住", bound)
	}

	untouched := MergeAuthUpdate(path, map[string]any{"oauth": map[string]any{"verified_once": true}})
	if len(objectValue(objectValue(untouched["oauth"])["bound_ids"])) != 2 {
		t.Error("没改允许列表的更新不该动绑定")
	}
}
