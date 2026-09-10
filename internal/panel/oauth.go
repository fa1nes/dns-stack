package panel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func oauthUsers(rec authRecord) []string {
	users := []string{}
	if values, ok := rec.OAuth["allowed_users"].([]any); ok {
		for _, value := range values {
			if user, ok := value.(string); ok && user != "" {
				users = append(users, user)
			}
		}
	}
	return users
}

func oauthReady(rec authRecord) bool {
	id, _ := rec.OAuth["client_id"].(string)
	secret, _ := rec.OAuth["client_secret"].(string)
	return id != "" && secret != "" && len(oauthUsers(rec)) > 0
}

func setSessionCookie(w http.ResponseWriter, token string) {
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(os.Getenv("PANEL_COOKIE_SAMESITE")) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{Name: "dns_stack_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: true, SameSite: sameSite})
}

func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
		return
	}
	rec, _ := s.loadAuth()
	if !oauthReady(rec) {
		writeJSON(w, 400, map[string]any{"ok": false, "message": "尚未配置 GitHub OAuth"})
		return
	}
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "message": "生成授权状态失败"})
		return
	}
	state := base64.RawURLEncoding.EncodeToString(bytes)
	s.pendingMu.Lock()
	if s.oauthStates == nil {
		s.oauthStates = map[string]time.Time{}
	}
	for key, created := range s.oauthStates {
		if time.Since(created) > 10*time.Minute {
			delete(s.oauthStates, key)
		}
	}
	s.oauthStates[state] = time.Now()
	s.pendingMu.Unlock()
	id, _ := rec.OAuth["client_id"].(string)
	query := url.Values{"client_id": {id}, "scope": {"read:user"}, "state": {state}, "allow_signup": {"false"}}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+query.Encode(), http.StatusFound)
}

func (s *Server) consumeOAuthState(state string) bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	created, exists := s.oauthStates[state]
	delete(s.oauthStates, state)
	return exists && time.Since(created) <= 10*time.Minute
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(message string) { http.Redirect(w, r, "/login?err="+url.QueryEscape(message), http.StatusFound) }
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
		return
	}
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	if code == "" || state == "" || !s.consumeOAuthState(state) {
		fail("授权状态校验失败，请重新登录")
		return
	}
	rec, _ := s.loadAuth()
	id, _ := rec.OAuth["client_id"].(string)
	secret, _ := rec.OAuth["client_secret"].(string)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	fetch := func(endpoint, token string, form url.Values) (map[string]any, error) {
		method := http.MethodGet
		var body io.Reader
		if form != nil {
			method = http.MethodPost
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(r.Context(), method, endpoint, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "dns-stack-panel")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data := map[string]any{}
		if resp.StatusCode != http.StatusOK {
			return data, nil
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data)
		return data, err
	}
	data, err := fetch("https://github.com/login/oauth/access_token", "", url.Values{"client_id": {id}, "client_secret": {secret}, "code": {code}})
	if err != nil {
		fail("访问 GitHub 失败")
		return
	}
	token, _ := data["access_token"].(string)
	if token == "" {
		fail("GitHub 未返回访问令牌或用户信息")
		return
	}
	data, err = fetch("https://api.github.com/user", token, nil)
	if err != nil {
		fail("访问 GitHub 失败")
		return
	}
	login, _ := data["login"].(string)
	if login == "" {
		fail("GitHub 未返回访问令牌或用户信息")
		return
	}
	rec, _ = s.loadAuth()
	allowed := false
	for _, user := range oauthUsers(rec) {
		if strings.ToLower(strings.TrimSpace(login)) == user {
			allowed = true
		}
	}
	if !allowed {
		fail("GitHub 账号 " + login + " 不在允许列表内")
		return
	}
	if !boolValue(rec.OAuth["verified_once"]) {
		s.commitAuthUpdateRaw(r.Context(), map[string]any{"oauth": map[string]any{"verified_once": true}}, "mark_oauth_verified")
	}
	rec, configured := s.loadAuth()
	if !configured {
		fail("面板认证数据缺失")
		return
	}
	session, err := issueSession(rec)
	if err != nil {
		fail("会话创建失败")
		return
	}
	setSessionCookie(w, session)
	http.Redirect(w, r, "/", http.StatusFound)
}
