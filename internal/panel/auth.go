package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	_ "modernc.org/sqlite"
)

type authRecord struct {
	Salt             string         `json:"salt"`
	Hash             string         `json:"hash"`
	N                int            `json:"n"`
	R                int            `json:"r"`
	P                int            `json:"p"`
	SessionKey       string         `json:"session_key"`
	Username         string         `json:"username"`
	PasswordDisabled bool           `json:"password_disabled"`
	TOTP             map[string]any `json:"totp"`
	OAuth            map[string]any `json:"oauth"`
}

func isLocal(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func (s *Server) loadAuth() (authRecord, bool) {
	b, err := os.ReadFile(s.cfg.AuthPath)
	if err != nil {
		return authRecord{}, false
	}
	var rec authRecord
	if json.Unmarshal(b, &rec) != nil {
		return authRecord{}, false
	}
	return rec, rec.Hash != ""
}

func (s *Server) validSession(r *http.Request, rec authRecord) bool {
	c, err := r.Cookie("dns_stack_session")
	if err != nil {
		return false
	}
	if _, gone := s.revoked.Load(c.Value); gone {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(rec.SessionKey)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	sig := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(parts[1])) {
		return false
	}
	var p struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(body, &p) != nil {
		return false
	}
	return p.Exp > time.Now().Unix()
}

func sessionExpiry(r *http.Request) int64 {
	c, err := r.Cookie("dns_stack_session")
	if err != nil {
		return 0
	}
	body, _, _ := strings.Cut(c.Value, ".")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return 0
	}
	var p struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return 0
	}
	return p.Exp
}

func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if _, ok := s.loadAuth(); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "面板尚未设置密码，没有会话可以作废"})
		return
	}
	resp, err := helperCall(r.Context(), "rotate_session_key", map[string]any{})
	if status, message := helperOutcome(resp, err, "作废会话失败"); status != 0 {
		s.writeAudit("revoke_sessions", nil, false, message)
		writeJSON(w, status, map[string]any{"ok": false, "message": message})
		return
	}
	s.writeAudit("revoke_sessions", nil, true, "其它设备上的登录已全部失效")
	rec, _ := s.loadAuth()
	if token, err := issueSession(rec); err == nil {
		setSessionCookie(w, token)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "其它设备上的登录已全部失效，这台设备已续上新的会话"})
}

func issueSession(rec authRecord) (string, error) {
	key, err := base64.StdEncoding.DecodeString(rec.SessionKey)
	if err != nil {
		return "", err
	}
	body := []byte(fmt.Sprintf(`{"exp": %d}`, time.Now().Add(12*time.Hour).Unix()))
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func verifyPassword(password string, rec authRecord) bool {
	salt, e1 := base64.StdEncoding.DecodeString(rec.Salt)
	expected, e2 := base64.StdEncoding.DecodeString(rec.Hash)
	if e1 != nil || e2 != nil || len(expected) != 32 || len(salt) == 0 {
		return false
	}
	n, r, p := rec.N, rec.R, rec.P
	if n == 0 {
		n = 32768
	}
	if r == 0 {
		r = 8
	}
	if p == 0 {
		p = 1
	}
	if n < 2 || n > 1<<20 || r < 1 || r > 32 || p < 1 || p > 16 || int64(n)*int64(r)*128 > 128<<20 {
		return false
	}
	derived, err := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	return err == nil && hmac.Equal(derived, expected)
}

var scryptSlots = make(chan struct{}, 2)

func (s *Server) verifyGuarded(ip, password string, rec authRecord) (bool, int) {
	if wait := s.authWait(ip); wait > 0 {
		return false, wait
	}
	select {
	case scryptSlots <- struct{}{}:
	default:
		return false, 1
	}
	defer func() { <-scryptSlots }()
	s.authFailure(ip)
	return verifyPassword(password, rec), 0
}

func writeThrottled(w http.ResponseWriter, wait int) {
	w.Header().Set("Retry-After", strconv.Itoa(wait))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false,
		"message": fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", wait), "retry_after": wait})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	rec, ok := s.loadAuth()
	if !ok {
		writeJSON(w, 400, map[string]any{"ok": false, "message": "面板尚未设置密码"})
		return
	}
	if rec.PasswordDisabled {
		writeJSON(w, 403, map[string]any{"ok": false, "message": "密码登录已关闭，请使用 GitHub 登录"})
		return
	}
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"totp_code"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&p) != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	ip := remoteIP(r)
	passwordOK, wait := s.verifyGuarded(ip, p.Password, rec)
	if wait > 0 {
		writeThrottled(w, wait)
		return
	}
	userOK := rec.Username == "" ||
		subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(p.Username))), []byte(rec.Username)) == 1
	totpOK := true
	if boolValue(rec.TOTP["enabled"]) {
		secret, _ := rec.TOTP["secret"].(string)
		totpOK = s.checkTOTPCode(p.Code, secret, true)
	}
	if !userOK || !passwordOK || !totpOK {
		writeJSON(w, 401, map[string]any{"ok": false, "message": loginFailure(rec)})
		return
	}
	s.authSuccess(ip)
	token, err := issueSession(rec)
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "message": "会话创建失败"})
		return
	}
	setSessionCookie(w, token)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func loginFailure(rec authRecord) string {
	fields := []string{"密码"}
	if rec.Username != "" {
		fields = []string{"用户名", "密码"}
	}
	if boolValue(rec.TOTP["enabled"]) {
		fields = append(fields, "动态验证码")
	}
	last := len(fields) - 1
	if last == 0 {
		return fields[0] + "错误"
	}
	return strings.Join(fields[:last], "、") + "或" + fields[last] + "错误"
}

func helperOutcome(resp map[string]any, err error, fallback string) (int, string) {
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	if message, _ := resp["message"].(string); message != "" {
		return http.StatusBadRequest, message
	}
	data := helperData(resp)
	if boolValue(resp["ok"]) && numberValue(data["returncode"]) == 0 {
		return 0, ""
	}
	if stderr, _ := data["stderr"].(string); stderr != "" {
		return http.StatusInternalServerError, stderr
	}
	return http.StatusInternalServerError, fallback
}

func (s *Server) authUsername(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	rec, ok := s.loadAuth()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "面板尚未设置密码"})
		return
	}
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&p) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	ip := remoteIP(r)
	passwordOK, wait := s.verifyGuarded(ip, p.Password, rec)
	if wait > 0 {
		writeThrottled(w, wait)
		return
	}
	if !passwordOK {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "当前密码不正确"})
		return
	}
	s.authSuccess(ip)
	resp, err := helperCall(r.Context(), "set_panel_username", map[string]any{"username": p.Username})
	if status, message := helperOutcome(resp, err, "写入用户名失败"); status != 0 {
		s.writeAudit("set_panel_username", nil, false, message)
		writeJSON(w, status, map[string]any{"ok": false, "message": message})
		return
	}
	s.writeAudit("set_panel_username", nil, true, "面板用户名已更新")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "用户名已更新，下次登录时和密码一起填"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
		return
	}
	if c, err := r.Cookie("dns_stack_session"); err == nil && c.Value != "" {
		now := time.Now()
		s.revoked.Range(func(key, value any) bool {
			if value.(time.Time).Before(now) {
				s.revoked.Delete(key)
			}
			return true
		})
		s.revoked.Store(c.Value, now.Add(13*time.Hour))
	}
	http.SetCookie(w, &http.Cookie{Name: "dns_stack_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "role": s.role(), "ts": time.Now().Unix()})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	rec, configured := s.loadAuth()
	out := map[string]any{
		"auth_enabled":      configured,
		"username_required": configured && rec.Username != "",
		"totp_enabled":      configured && rec.TOTP["enabled"] == true,
		"oauth_enabled":     configured && oauthReady(rec),
		"password_disabled": configured && rec.PasswordDisabled,
	}
	if configured && !s.validSession(r, rec) {
		writeJSON(w, 200, out)
		return
	}
	out["role"] = s.role()

	roleName := "香港境外出口"
	if s.role() == "cn-resolver" {
		roleName = "国内 DNS 服务器"
	}
	out["role_name"] = roleName
	out["log_units"] = s.watchedUnits()
	writeJSON(w, 200, out)
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.loadAuth()
	clientID, _ := rec.OAuth["client_id"].(string)
	secret, _ := rec.OAuth["client_secret"].(string)
	oauth := map[string]any{"client_id": clientID, "secret_set": secret != "", "allowed_users": oauthUsers(rec), "verified_once": boolValue(rec.OAuth["verified_once"]), "ready": oauthReady(rec)}
	writeJSON(w, 200, map[string]any{"oauth": oauth, "password_disabled": ok && rec.PasswordDisabled,
		"totp_enabled": ok && rec.TOTP["enabled"] == true, "auth_enabled": ok, "username": rec.Username,
		"session_expires_at": sessionExpiry(r)})
}
