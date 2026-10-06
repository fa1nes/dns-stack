package panel

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

const testPassword = "correct horse battery"

func serverWithPassword(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	salt := []byte("0123456789abcdef")
	hash, err := scrypt.Key([]byte(testPassword), salt, 16, 1, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dir, "auth.json")
	writeAuthRecord(t, authPath, map[string]any{
		"salt": base64.StdEncoding.EncodeToString(salt), "hash": base64.StdEncoding.EncodeToString(hash),
		"n": 16, "r": 1, "p": 1, "session_key": base64.StdEncoding.EncodeToString([]byte("k-0123456789abcdef0123456789abc")),
	})
	return New(Config{ConfigPath: filepath.Join(dir, "config.env"), AuthPath: authPath, DBPath: filepath.Join(dir, "collector.db")})
}

func loginRequest(password string) *http.Request {
	request := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"`+password+`"}`))
	request.RemoteAddr = "203.0.113.9:5000"
	return request
}

func TestWithoutAPasswordOnlyLoopbackHostNamesAreServed(t *testing.T) {
	server := newOpenServer(t)
	rebound := localRequest("POST", "/api/action/restart_unbound")
	rebound.Host = "evil.example:8899"
	rebound.Header.Set("Origin", "http://evil.example:8899")
	if got := serve(server, rebound).Code; got != http.StatusForbidden {
		t.Fatalf("回环来源 + 外部域名 Host 得到 %d——DNS 重绑定的网页经 SSH 隧道就能操作没设密码的面板", got)
	}
	if got := serve(server, localRequest("GET", "/api/bootstrap")).Code; got != http.StatusOK {
		t.Fatalf("经 127.0.0.1 访问没设密码的面板应当放行，得到 %d", got)
	}
}

func TestLogoutRevokesTheTokenItself(t *testing.T) {
	server := serverWithPassword(t)
	login := serve(server, loginRequest(testPassword))
	if login.Code != http.StatusOK {
		t.Fatalf("登录失败 %d %s", login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	authed := func() int {
		request := localRequest("GET", "/api/overview")
		request.AddCookie(cookie)
		return serve(server, request).Code
	}
	if got := authed(); got == http.StatusUnauthorized {
		t.Fatal("刚登录的会话被拒绝")
	}
	logout := localRequest("POST", "/api/logout")
	logout.AddCookie(cookie)
	serve(server, logout)
	if got := authed(); got != http.StatusUnauthorized {
		t.Fatalf("登出后旧令牌仍然有效（%d）——被抄走的 cookie 在 12 小时内照样能用", got)
	}
}

func TestScryptRunsAtMostTwiceAtOnceAndEveryAttemptCountsOnce(t *testing.T) {
	server := serverWithPassword(t)
	for i := 0; i < cap(scryptSlots); i++ {
		scryptSlots <- struct{}{}
	}
	busy := serve(server, loginRequest("wrong-password"))
	for i := 0; i < cap(scryptSlots); i++ {
		<-scryptSlots
	}
	if busy.Code != http.StatusTooManyRequests {
		t.Fatalf("scrypt 名额被占满时得到 %d——每次校验要 32MB，未登录的并发请求能把整机内存打爆", busy.Code)
	}
	if server.authWait("203.0.113.9") != 0 {
		t.Fatal("因为忙被拒的请求不该算一次失败")
	}

	for i := 0; i < 4; i++ {
		serve(server, loginRequest("wrong-password"))
	}
	if server.authWait("203.0.113.9") != 0 {
		t.Fatal("4 次失败就开始退避了——同一次失败被记了两次")
	}
	serve(server, loginRequest("wrong-password"))
	if server.authWait("203.0.113.9") == 0 {
		t.Fatal("第 5 次失败之后应当开始退避")
	}
}

func TestResponsesForbidFramingAndSniffing(t *testing.T) {
	response := serve(newOpenServer(t), localRequest("GET", "/"))
	for header, want := range map[string]string{
		"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q，期望 %q", header, got, want)
		}
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("缺少 frame-ancestors，面板能被别的网站嵌进 iframe 做点击劫持")
	}
}
