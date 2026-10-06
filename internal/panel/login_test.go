package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loginPage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.json")
	writeAuthFile(t, auth)
	server := New(Config{
		ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath:   auth,
		DBPath:     filepath.Join(dir, "collector.db"),
	})
	response := serve(server, localRequest("GET", "/"))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("无会话访问面板 = %d，期望 401 并回登录页", response.Code)
	}
	return response.Body.String()
}

func TestLoginPageCollectsEveryFactorTheBackendCanDemand(t *testing.T) {
	page := loginPage(t)
	if !strings.Contains(page, `id="totp"`) {
		t.Error("启用 TOTP 后 /api/login 会校验 totp_code，登录页却没有输入框——" +
			"在面板里开二次验证等于把自己锁在门外，只能 SSH 上去跑 panel-2fa-reset")
	}
	if !strings.Contains(page, "/api/oauth/github/start") {
		t.Error("登录页没有任何地方跳到 /api/oauth/github/start——" +
			"GitHub 登录永远走不通，oauth.verified_once 也就永远为假，" +
			"「关闭密码登录」会被后端一直拒绝，整个 OAuth 功能是死的")
	}
}

func TestTOTPSetupStaysUnlockedOnlyWhileTheLoginPageCanCollectCodes(t *testing.T) {
	page := loginPage(t)
	markup, err := os.ReadFile("../../web/index.html")
	if err != nil {
		t.Skipf("读不到 index.html: %v", err)
	}
	collectable := strings.Contains(page, `id="totp"`)
	var locked bool
	for _, line := range strings.Split(string(markup), "\n") {
		if strings.Contains(line, `id="btnTotpSetup"`) && strings.Contains(line, "disabled") {
			locked = true
		}
	}
	if collectable && locked {
		t.Error("登录页已经能收验证码了，「启用二次认证」却还是禁用的——" +
			"当初禁用它就是因为登录页收不了，原因没了闸门要一起撤")
	}
	if !collectable && !locked {
		t.Error("登录页收不了验证码，却允许启用二次认证——点下去就把自己锁在门外了")
	}
}

func writeAuthRecord(t *testing.T, path string, rec map[string]any) {
	t.Helper()
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapTellsTheLoginPageWhichMethodsAreLive(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	writeAuthRecord(t, authPath, map[string]any{
		"salt": "c2FsdA", "hash": "aGFzaA", "n": 16384, "r": 8, "p": 1,
		"session_key":       "a2V5",
		"password_disabled": true,
		"totp":              map[string]any{"secret": "JBSWY3DPEHPK3PXP", "enabled": true},
		"oauth": map[string]any{
			"client_id": "cid", "client_secret": "sec",
			"allowed_users": []any{"fa1nes"},
		},
	})
	server := New(Config{
		ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath:   authPath,
		DBPath:     filepath.Join(dir, "collector.db"),
	})

	response := serve(server, localRequest("GET", "/api/bootstrap"))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/bootstrap = %d", response.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{
		"auth_enabled": true, "totp_enabled": true,
		"oauth_enabled": true, "password_disabled": true,
	} {
		if got, _ := out[key].(bool); got != want {
			t.Errorf("bootstrap.%s = %v，期望 %v；未登录时拿不到这些开关，"+
				"登录页就没法决定要不要显示验证码框和 GitHub 按钮", key, out[key], want)
		}
	}
	if _, leaked := out["log_units"]; leaked {
		t.Error("未登录的 bootstrap 泄露了 log_units")
	}
}

func TestBootstrapKeepsQuietWhenNoAuthIsConfigured(t *testing.T) {
	response := serve(newOpenServer(t), localRequest("GET", "/api/bootstrap"))
	var out map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"auth_enabled", "totp_enabled", "oauth_enabled", "password_disabled"} {
		if got, _ := out[key].(bool); got {
			t.Errorf("还没设置密码时 bootstrap.%s 不应为真", key)
		}
	}
	if _, ok := out["role"]; !ok {
		t.Error("没设密码的面板是开放的，bootstrap 却不返回 role——" +
			"panel.js 靠 PANEL_ROLE 做分支，拿不到值会当成「不是这个角色」，" +
			"整块功能凭空消失还不报错")
	}
}
