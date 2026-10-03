package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func rememberLogin(remember bool) *http.Request {
	body := `{"password":"` + testPassword + `"}`
	if remember {
		body = `{"password":"` + testPassword + `","remember":true}`
	}
	request := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	request.RemoteAddr = "203.0.113.9:5000"
	return request
}

func TestRememberMeLastsAWeekAndItsLogoutOutlivesTwelveHours(t *testing.T) {
	server := serverWithPassword(t)
	short := serve(server, rememberLogin(false)).Result().Cookies()[0]
	long := serve(server, rememberLogin(true)).Result().Cookies()[0]
	if short.MaxAge != int(sessionTTL.Seconds()) || long.MaxAge != int(rememberTTL.Seconds()) {
		t.Fatalf("cookie 有效期：不勾选 %ds，勾选 %ds", short.MaxAge, long.MaxAge)
	}

	check := localRequest("GET", "/api/auth/config")
	check.AddCookie(long)
	if exp := sessionExpiry(check); exp < time.Now().Add(6*24*time.Hour).Unix() {
		t.Fatalf("勾选「记住」后令牌只到 %d，浏览器留着 cookie、服务端却已经不认了", exp)
	}

	logout := localRequest("POST", "/api/logout")
	logout.AddCookie(long)
	serve(server, logout)
	until, ok := server.revoked.Load(long.Value)
	if !ok || until.(time.Time).Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("七天的令牌只吊销到 %v——过了这个时间，被偷走的 cookie 又能用了", until)
	}
}
