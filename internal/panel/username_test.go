package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func serverWithUsername(t *testing.T, username string) *Server {
	t.Helper()
	server := serverWithPassword(t)
	body, _ := os.ReadFile(server.cfg.AuthPath)
	var record map[string]any
	_ = json.Unmarshal(body, &record)
	record["username"] = username
	writeAuthRecord(t, server.cfg.AuthPath, record)
	return server
}

func TestOnceAUsernameIsSetLoginNeedsIt(t *testing.T) {
	server := serverWithUsername(t, "alice")
	login := func(user string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("POST", "/api/login",
			strings.NewReader(`{"username":"`+user+`","password":"`+testPassword+`"}`))
		request.RemoteAddr = "203.0.113.9:5000"
		return serve(server, request)
	}
	wrong := login("mallory")
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("用户名不对、密码对，得到 %d——用户名形同虚设", wrong.Code)
	}
	if !strings.Contains(wrong.Body.String(), "用户名或密码错误") {
		t.Errorf("失败提示不该透露到底是哪一项错了：%s", wrong.Body.String())
	}
	if got := serve(server, loginRequest(testPassword)).Code; got != http.StatusUnauthorized {
		t.Fatalf("设了用户名之后只给密码也能登录（%d）", got)
	}
	if got := login(" Alice ").Code; got != http.StatusOK {
		t.Fatalf("用户名大小写和首尾空格不该影响登录，得到 %d", got)
	}

	var boot map[string]any
	_ = json.Unmarshal(serve(server, localRequest("GET", "/api/bootstrap")).Body.Bytes(), &boot)
	if boot["username_required"] != true {
		t.Errorf("登录页要靠 bootstrap 的 username_required 决定显不显示用户名框：%v", boot)
	}
}

func TestWithoutAUsernamePasswordAloneStillWorks(t *testing.T) {
	server := serverWithPassword(t)
	if got := serve(server, loginRequest(testPassword)).Code; got != http.StatusOK {
		t.Fatalf("还没设用户名的老部署只凭密码登录得到 %d——升级之后就进不去了", got)
	}
}

func TestChangingTheUsernameNeedsTheCurrentPassword(t *testing.T) {
	server := serverWithPassword(t)
	calls := fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0}}
	})
	post := func(body string) int {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("POST", "/api/auth/username", strings.NewReader(body))
		request.RemoteAddr = "203.0.113.9:5000"
		server.authUsername(response, request)
		return response.Code
	}
	if got := post(`{"username":"alice","password":"wrong-password"}`); got != http.StatusUnauthorized {
		t.Fatalf("当前密码不对也改了用户名（%d）", got)
	}
	if len(calls()) != 0 {
		t.Fatal("密码不对时不该写到 helper")
	}
	if got := post(`{"username":"alice","password":"` + testPassword + `"}`); got != http.StatusOK {
		t.Fatalf("改用户名失败 %d", got)
	}
	got := calls()
	args, _ := got[0]["args"].(map[string]any)
	if len(got) != 1 || got[0]["op"] != "set_panel_username" || args["username"] != "alice" {
		t.Fatalf("应当交给 helper 的 set_panel_username，实际 %v", got)
	}
}
