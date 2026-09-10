package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func equal(t *testing.T, label string, got, want any) {
	t.Helper()
	gotText, wantText := jsonText(got), jsonText(want)
	if gotText != wantText {
		t.Fatalf("%s: got %s, want %s", label, gotText, wantText)
	}
}

func jsonText(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "<unmarshalable>"
	}
	return string(encoded)
}

func newTestHelper(t *testing.T) *Helper {
	t.Helper()
	root := t.TempDir()
	config := filepath.Join(root, "config.env")
	if err := os.WriteFile(config, []byte("ROLE=cn-resolver\nDOH_PATH=/qX7pLm2v9Kd4Rt8w/dns-query\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(Config{
		SocketPath: filepath.Join(root, "helper.sock"),
		LogPath:    filepath.Join(root, "helper.log"),
		ConfigPath: config,
		StackRoot:  root,
		AuthPath:   filepath.Join(root, "secrets", "auth.json"),
	})
	t.Cleanup(func() { h.Close() })
	return h
}

func TestSanitizeRemovesCredentialsAndClientAddresses(t *testing.T) {
	h := newTestHelper(t)
	cases := []struct{ name, input, wantAbsent, wantPresent string }{
		{"bearer token", `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload`, "eyJhbGciOiJIUzI1NiJ9", "[已脱敏]"},
		{"json cookie", `{"cookie":"session=abc123def456"}`, "abc123def456", "[已脱敏]"},
		{"client address", `remote 203.0.113.45:5555 failed`, "203.0.113.45", "203.0.x.x"},
		{"infra address kept", `upstream 10.100.0.3:5335 timeout`, "10.100.0.x", "10.100.0.3"},
		{"loopback kept", `listen 127.0.0.1:5335`, "127.0.x.x", "127.0.0.1"},
		{"doh path", `GET /qX7pLm2v9Kd4Rt8w/dns-query`, "qX7pLm2v9Kd4Rt8w", "[已脱敏DoH路径]"},
	}
	for _, item := range cases {
		got := Sanitize(item.input, h.configPath)
		if strings.Contains(got, item.wantAbsent) {
			t.Fatalf("%s: %q 仍出现在 %q", item.name, item.wantAbsent, got)
		}
		if !strings.Contains(got, item.wantPresent) {
			t.Fatalf("%s: 期望包含 %q，实际 %q", item.name, item.wantPresent, got)
		}
	}
}

func TestSanitizeDropsPrivateKeyBlock(t *testing.T) {
	h := newTestHelper(t)
	got := Sanitize("head\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\ntail", h.configPath)
	if strings.Contains(got, "MIIEvQIBADAN") {
		t.Fatalf("私钥正文未被移除: %q", got)
	}
	equal(t, "私钥两侧的正文保留", strings.Contains(got, "head") && strings.Contains(got, "tail"), true)
}

func TestSafeDomainRejectsNonDomains(t *testing.T) {
	for _, bad := range []string{"", "localhost", "1.2.3.4", "-lead.example.com", "trail-.example.com",
		"a..b.com", "例子.中国", strings.Repeat("a", 64) + ".com", "no-dot"} {
		if _, err := SafeDomain(bad); err == nil {
			t.Fatalf("应当拒绝 %q", bad)
		}
	}
	for input, want := range map[string]string{
		"  WWW.QQ.com.  ": "www.qq.com",
		"_dmarc.a.com":    "_dmarc.a.com",
		"a-b.example.org": "a-b.example.org",
	} {
		got, err := SafeDomain(input)
		if err != nil {
			t.Fatalf("%q 应当通过: %v", input, err)
		}
		equal(t, "规范化 "+input, got, want)
	}
}

func TestSafeClientSubnetAcceptsOnlyCanonicalGlobalSlash24(t *testing.T) {
	for _, bad := range []string{"", "116.1.2.0/25", "116.1.2.3/24", "10.0.0.0/24",
		"127.0.0.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/24",
		"2400::/24", "notanip/24", "116.1.2.0"} {
		if _, ok := SafeClientSubnet(bad); ok {
			t.Fatalf("应当拒绝 %q", bad)
		}
	}
	got, ok := SafeClientSubnet(" 116.1.2.0/24 ")
	equal(t, "接受全局 /24", []any{got, ok}, []any{"116.1.2.0/24", true})
}

func TestDangerousOpsRequireConfirmBeforeRunning(t *testing.T) {
	h := newTestHelper(t)
	ran := false
	h.ops = map[string]func(map[string]any) result{
		"restart_mosproxy": func(map[string]any) result {
			ran = true
			return result{"ok": true, "returncode": 0}
		},
	}
	resp := h.Dispatch("restart_mosproxy", map[string]any{})
	equal(t, "缺少确认时拒绝", resp["ok"], false)
	equal(t, "拒绝时未执行", ran, false)
	if !strings.Contains(resp["message"].(string), "二次确认") {
		t.Fatalf("错误信息应说明需要确认: %v", resp["message"])
	}

	resp = h.Dispatch("restart_mosproxy", map[string]any{"confirm": true})
	equal(t, "带确认时执行", []any{resp["ok"], ran}, []any{true, true})
}

func TestUnknownOperationIsRejected(t *testing.T) {
	h := newTestHelper(t)
	resp := h.Dispatch("rm_rf_slash", map[string]any{})
	equal(t, "未知操作被拒", resp["ok"], false)
	if _, leaked := resp["data"]; leaked {
		t.Fatal("未知操作不应返回 data")
	}
}

func TestRejectionAndOperationErrorUseDifferentChannels(t *testing.T) {
	h := newTestHelper(t)
	h.ops = map[string]func(map[string]any) result{
		"reject": func(map[string]any) result { return rejectResult("参数非法") },
		"refuse": func(map[string]any) result { return errorResult("目标不支持") },
	}
	rejected := h.Dispatch("reject", map[string]any{})
	equal(t, "拒绝走信封", []any{rejected["ok"], rejected["message"]}, []any{false, "参数非法"})
	if _, present := rejected["data"]; present {
		t.Fatal("拒绝不应带 data")
	}
	refused := h.Dispatch("refuse", map[string]any{})
	equal(t, "拒办走 data", refused["ok"], true)
	equal(t, "data 里标记失败", refused["data"].(map[string]any)["ok"], false)
}

func TestRedactArgsHidesSecretsAndDropsConfirm(t *testing.T) {
	got := redactArgs(map[string]any{"password": "hunter2hunter2", "confirm": true, "unit": "mosproxy"})
	if strings.Contains(got, "hunter2hunter2") {
		t.Fatalf("明文密码进了日志: %s", got)
	}
	if strings.Contains(got, "confirm") {
		t.Fatalf("confirm 是协议噪音，不该进日志: %s", got)
	}
	if !strings.Contains(got, "mosproxy") {
		t.Fatalf("普通参数应保留: %s", got)
	}
}

func TestOperationSetMatchesDangerousList(t *testing.T) {
	h := newTestHelper(t)
	for op := range DangerousOps {
		if _, ok := h.ops[op]; !ok {
			t.Fatalf("危险操作 %s 不在操作表里，这条闸门永远不会被触发", op)
		}
	}
	equal(t, "操作总数", len(h.ops), 44)
}

func writeRecord(t *testing.T, path string, record map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMergeAuthUpdateRefusesCredentialFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeRecord(t, path, map[string]any{
		"hash": "original", "salt": "originalsalt", "session_key": "originalkey",
	})
	merged := MergeAuthUpdate(path, map[string]any{
		"hash": "attacker", "salt": "attacker", "session_key": "attacker",
		"password_disabled": true,
	})
	equal(t, "hash 不可写", merged["hash"], "original")
	equal(t, "salt 不可写", merged["salt"], "originalsalt")
	equal(t, "session_key 不可写", merged["session_key"], "originalkey")
	equal(t, "白名单字段可写", merged["password_disabled"], true)
}

func TestMergeAuthUpdateOAuthSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeRecord(t, path, map[string]any{"oauth": map[string]any{
		"client_id": "old", "client_secret": "kept", "verified_once": true,
	}})
	merged := MergeAuthUpdate(path, map[string]any{"oauth": map[string]any{
		"client_id": "new", "client_secret": "   ", "verified_once": false,
		"allowed_users": []any{"someone"},
	}})
	oauth := merged["oauth"].(map[string]any)
	equal(t, "client_id 更新", oauth["client_id"], "new")
	equal(t, "空 client_secret 表示不改动", oauth["client_secret"], "kept")
	equal(t, "verified_once 不可被前端清除", oauth["verified_once"], true)
	equal(t, "allowed_users 可写", oauth["allowed_users"], []any{"someone"})
}

func TestMergeAuthUpdateTOTPRemovalAndWhitelist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeRecord(t, path, map[string]any{"totp": map[string]any{"secret": "S1", "enabled": true}})
	merged := MergeAuthUpdate(path, map[string]any{"totp": map[string]any{
		"secret": "S2", "enabled": false, "attempts": 99,
	}})
	totp := merged["totp"].(map[string]any)
	equal(t, "secret 可写", totp["secret"], "S2")
	equal(t, "enabled 归一为布尔", totp["enabled"], false)
	if _, leaked := totp["attempts"]; leaked {
		t.Fatal("白名单外的字段不该被写入")
	}

	removed := MergeAuthUpdate(path, map[string]any{"totp": nil})
	if _, present := removed["totp"]; present {
		t.Fatal("传空表示停用，应当整块删除而不是留一个可被窃取的 secret")
	}
}

func TestHashPasswordProducesVerifiableRecordWithFreshSessionKey(t *testing.T) {
	first, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, "算法标记", first["algo"], "scrypt")
	equal(t, "scrypt 参数", []any{first["n"], first["r"], first["p"]}, []any{scryptN, scryptR, scryptP})
	second, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if first["hash"] == second["hash"] {
		t.Fatal("相同密码必须因随机 salt 得到不同哈希")
	}
	if first["session_key"] == second["session_key"] {
		t.Fatal("改密码必须换会话密钥，否则旧会话不会失效")
	}
}

func TestWriteAuthRecordIsAtomicAndKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := writeAuthRecord(path, map[string]any{"hash": "x"}, true, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeSupportsUnixMode() {
		equal(t, "权限", info.Mode().Perm(), os.FileMode(0o600))
	}
	if _, err := os.Stat(strings.TrimSuffix(path, ".json") + ".tmp"); err == nil {
		t.Fatal("临时文件应当在 rename 后消失")
	}
}

func runtimeSupportsUnixMode() bool { return os.PathSeparator == '/' }

func TestTailRunesKeepsSuffixWithoutSplittingRunes(t *testing.T) {
	text := strings.Repeat("中", 10)
	equal(t, "短于上限时原样", tailRunes(text, 20), text)
	equal(t, "截取末尾", tailRunes(text, 3), "中中中")
}
