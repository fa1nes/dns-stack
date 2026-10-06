package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestTheOnlyRemainingLoginCannotBeEmptied(t *testing.T) {
	server := serverWithPassword(t)
	body, _ := os.ReadFile(server.cfg.AuthPath)
	var record map[string]any
	_ = json.Unmarshal(body, &record)
	record["password_disabled"] = true
	updated, _ := json.Marshal(record)
	_ = os.WriteFile(server.cfg.AuthPath, updated, 0o600)

	calls := fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0}}
	})
	for _, payload := range []string{
		`{"client_id":"cid","client_secret":"","allowed_users":[]}`,
		`{"client_id":"","client_secret":"","allowed_users":["alice"]}`,
	} {
		response := httptest.NewRecorder()
		server.authOAuth(response, httptest.NewRequest("POST", "/api/auth/oauth", strings.NewReader(payload)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("密码登录已关闭时提交 %s 得到 %d——保存下去就再也没有人能登录", payload, response.Code)
		}
	}
	if len(calls()) != 0 {
		t.Fatal("被拒绝的更新不该写到 helper")
	}
}

func TestSignOutEverywhereKeepsOnlyThisDevice(t *testing.T) {
	server := serverWithPassword(t)
	login := serve(server, loginRequest(testPassword))
	if login.Code != http.StatusOK {
		t.Fatalf("登录失败 %d", login.Code)
	}
	oldCookie := login.Result().Cookies()[0]

	calls := fakeHelper(t, func(request map[string]any) map[string]any {
		body, _ := os.ReadFile(server.cfg.AuthPath)
		var record map[string]any
		_ = json.Unmarshal(body, &record)
		record["session_key"] = "bmV3LXNlc3Npb24ta2V5LTAxMjM0NTY3ODlhYmNkZWY="
		updated, _ := json.Marshal(record)
		_ = os.WriteFile(server.cfg.AuthPath, updated, 0o600)
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0}}
	})

	request := localRequest("POST", "/api/auth/sessions/revoke")
	request.AddCookie(oldCookie)
	response := serve(server, request)
	if response.Code != http.StatusOK {
		t.Fatalf("退出其它设备失败 %d %s", response.Code, response.Body.String())
	}
	if got := calls(); len(got) != 1 || got[0]["op"] != "rotate_session_key" {
		t.Fatalf("应当让 helper 轮换会话密钥，实际调用 %v", got)
	}

	authed := func(c *http.Cookie) int {
		r := localRequest("GET", "/api/auth/config")
		r.AddCookie(c)
		return serve(server, r).Code
	}
	if authed(oldCookie) != http.StatusUnauthorized {
		t.Error("其它设备手里的旧令牌在密钥轮换后仍然有效")
	}
	fresh := response.Result().Cookies()
	if len(fresh) == 0 || authed(fresh[0]) != http.StatusOK {
		t.Error("发起操作的这台设备应当拿到新令牌、继续保持登录")
	}

	cfg := localRequest("GET", "/api/auth/config")
	cfg.AddCookie(fresh[0])
	var out map[string]any
	_ = json.Unmarshal(serve(server, cfg).Body.Bytes(), &out)
	if exp, _ := out["session_expires_at"].(float64); exp <= 0 {
		t.Errorf("auth/config 没带本次会话的到期时间：%v", out["session_expires_at"])
	}
}
