package panel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/dns-stack/dns-stack/internal/domain"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type operationSpec struct {
	Label     string
	Dangerous bool
	Timeout   int
	Role      string
}

var operationOrder = []string{
	"sync_rules", "rollback_rules", "collect_polluted_ip", "rotate_doh_path",
	"set_cache_ttl", "reload_mosproxy", "restart_mosproxy", "restart_unbound",
	"healthcheck", "cert_check", "cert_renew", "backup", "purge_legacy",
	"clear_audit", "vacuum_logs", "clear_domains", "clear_domains_all",
	"set_arch_epoch", "export", "import", "pull_candidates", "classify_start",
	"classify_domain", "classify_authority", "build_rules", "rebuild_rules",
	"refresh_routing", "publish_github", "update_reference_data",
	"set_rule_sources",
}

var operationSpecs = map[string]operationSpec{
	"sync_rules":            {Label: "同步四文件规则", Timeout: 120},
	"rollback_rules":        {Label: "回滚上一版规则", Dangerous: true, Timeout: 120},
	"collect_polluted_ip":   {Label: "采集污染 IP", Timeout: 300},
	"rotate_doh_path":       {Label: "轮换 DoH 私密路径", Dangerous: true, Timeout: 90},
	"set_cache_ttl":         {Label: "调整乐观缓存时长", Timeout: 30},
	"reload_mosproxy":       {Label: "重载 mosproxy 域名表", Timeout: 30},
	"restart_mosproxy":      {Label: "重启 mosproxy", Dangerous: true, Timeout: 60},
	"restart_unbound":       {Label: "重启 Unbound", Dangerous: true, Timeout: 60},
	"healthcheck":           {Label: "执行健康检查", Timeout: 60},
	"cert_check":            {Label: "检查证书", Timeout: 60},
	"cert_renew":            {Label: "续签证书", Dangerous: true, Timeout: 180},
	"backup":                {Label: "立即备份", Timeout: 300},
	"purge_legacy":          {Label: "清理旧架构数据", Dangerous: true, Timeout: 300},
	"clear_audit":           {Label: "清空审计记录", Dangerous: true, Timeout: 60},
	"vacuum_logs":           {Label: "清理系统日志(保留7天)", Dangerous: true, Timeout: 150},
	"clear_domains":         {Label: "清理陈旧域名(7天未出现)", Dangerous: true, Timeout: 300},
	"clear_domains_all":     {Label: "清空全部域名统计", Dangerous: true, Timeout: 300},
	"set_arch_epoch":        {Label: "重设统计起点", Dangerous: true, Timeout: 30},
	"export":                {Label: "导出迁移包", Timeout: 300},
	"import":                {Label: "导入迁移包", Dangerous: true, Timeout: 600},
	"pull_candidates":       {Label: "拉取候选域名", Timeout: 120, Role: "global-builder"},
	"classify_start":        {Label: "立即执行分类", Timeout: 300, Role: "global-builder"},
	"classify_domain":       {Label: "分类指定域名", Timeout: 60, Role: "global-builder"},
	"classify_authority":    {Label: "按权威位置分类", Timeout: 1860, Role: "global-builder"},
	"build_rules":           {Label: "生成四文件规则", Timeout: 660, Role: "global-builder"},
	"rebuild_rules":         {Label: "一键重建规则", Timeout: 4500, Role: "global-builder"},
	"refresh_routing":       {Label: "刷新递归分流数据", Timeout: 2220, Role: "cn-resolver"},
	"publish_github":        {Label: "发布规则到 GitHub", Dangerous: true, Timeout: 120, Role: "global-builder"},
	"update_reference_data": {Label: "更新 Public Suffix List", Timeout: 120, Role: "global-builder"},
	"set_rule_sources":      {Label: "调整规则同步来源", Dangerous: true, Timeout: 30},
}

type authFailure struct {
	Count int
	Last  time.Time
}

type authLimiter struct {
	mu sync.Mutex
	m  map[string]authFailure
}

func (s *Server) authWait(ip string) int {
	s.authLimit.mu.Lock()
	defer s.authLimit.mu.Unlock()
	item := s.authLimit.m[ip]
	if item.Count < 5 {
		return 0
	}
	wait := 30 * time.Second
	for i := 5; i < item.Count; i++ {
		wait *= 2
		if wait >= time.Hour {
			wait = time.Hour
			break
		}
	}
	left := int(time.Until(item.Last.Add(wait)).Seconds())
	if left < 0 {
		return 0
	}
	return left
}

func (s *Server) authFailure(ip string) {
	s.authLimit.mu.Lock()
	if s.authLimit.m == nil {
		s.authLimit.m = map[string]authFailure{}
	}
	item := s.authLimit.m[ip]
	item.Count++
	item.Last = time.Now()
	s.authLimit.m[ip] = item
	if len(s.authLimit.m) > 4096 {
		cutoff := time.Now().Add(-time.Hour)
		for key, value := range s.authLimit.m {
			if value.Last.Before(cutoff) {
				delete(s.authLimit.m, key)
			}
		}
	}
	s.authLimit.mu.Unlock()
}

func (s *Server) authSuccess(ip string) {
	s.authLimit.mu.Lock()
	delete(s.authLimit.m, ip)
	s.authLimit.mu.Unlock()
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	op := strings.TrimPrefix(r.URL.Path, "/api/action/")
	if strings.Contains(op, "/") || op == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的操作"})
		return
	}
	spec, ok := operationSpecs[op]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "不支持的操作: " + op})
		return
	}
	args := map[string]any{}
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
		if err := dec.Decode(&args); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求参数不是合法 JSON 对象"})
			return
		}
	}
	if spec.Role != "" && s.role() != spec.Role {
		message := fmt.Sprintf("拒绝：当前角色 %s 不允许该操作，需要 %s", s.role(), spec.Role)
		s.writeAudit(op, args, false, message)
		writeJSON(w, http.StatusForbidden, map[string]any{"detail": fmt.Sprintf("当前角色 %s 不允许该操作，需要 %s", s.role(), spec.Role)})
		return
	}
	if spec.Dangerous && !boolValue(args["confirm"]) {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"ok": false, "need_confirm": true, "message": "「" + spec.Label + "」是危险操作，请确认后再执行"})
		return
	}
	ctx := r.Context()
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = withTimeout(ctx, time.Duration(spec.Timeout)*time.Second)
		defer cancel()
	}
	resp, err := helperCall(ctx, op, args)
	data := helperData(resp)
	if !boolValue(resp["ok"]) {
		data = nil
	}
	resultOK := err == nil && boolValue(resp["ok"]) && numberValue(data["returncode"]) == 0
	stdout, _ := data["stdout"].(string)
	stderr, _ := data["stderr"].(string)
	message := strings.TrimSpace(stdout)
	if message == "" {
		message = strings.TrimSpace(stderr)
	}
	if message == "" && err != nil {
		message = err.Error()
	}
	if message == "" {
		if raw, _ := resp["message"].(string); raw != "" {
			message = raw
		} else if resultOK {
			message = "执行成功"
		} else {
			message = "执行失败"
		}
	}
	s.writeAudit(op, args, resultOK, message)
	writeJSON(w, http.StatusOK, map[string]any{"ok": resultOK, "operation": op, "label": spec.Label, "message": message, "stdout": stdout, "stderr": stderr})
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

func boolValue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func numberValue(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return -1
	}
}

func (s *Server) opsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	role := s.role()
	items := make([]map[string]any, 0, len(operationOrder))
	for _, name := range operationOrder {
		spec := operationSpecs[name]
		if spec.Role != "" && spec.Role != role {
			continue
		}
		items = append(items, map[string]any{"op": name, "label": spec.Label, "dangerous": spec.Dangerous, "timeout": spec.Timeout})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ops": items, "role": role})
}

func (s *Server) openRW() (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(s.dbPath()) + "?_pragma=busy_timeout(5000)"
	return sql.Open("sqlite", dsn)
}

func safeAuditArgs(args map[string]any) string {
	clean := map[string]any{}
	for k, v := range args {
		if k == "confirm" || k == "password" || k == "old_password" || k == "new_password" || k == "client_secret" || k == "secret" {
			continue
		}
		clean[k] = v
	}
	b, _ := json.Marshal(clean)
	return string(b)[:minInt(len(b), 500)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) writeAudit(operation string, args map[string]any, ok bool, message string) {
	db, err := s.openRW()
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT 'panel', operation TEXT NOT NULL, args TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '')")
	flag := 0
	if ok {
		flag = 1
	}
	_, _ = db.Exec("INSERT INTO audit_log(ts,actor,operation,args,ok,message) VALUES (?,?,?,?,?,?)", time.Now().Unix(), "panel", operation, safeAuditArgs(args), flag, message[:minInt(len(message), 500)])
}

func (s *Server) passwordChange(w http.ResponseWriter, r *http.Request) {
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
		Old string `json:"old_password"`
		New string `json:"new_password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&p) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	ip := remoteIP(r)
	if wait := s.authWait(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "message": fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", wait), "retry_after": wait})
		return
	}
	if !verifyPassword(p.Old, rec) {
		s.authFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "当前密码不正确"})
		return
	}
	s.authSuccess(ip)
	if len([]rune(p.New)) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "新密码至少 12 位"})
		return
	}
	if p.New == p.Old {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "新密码不能与当前密码相同"})
		return
	}
	resp, err := helperCall(r.Context(), "set_panel_password", map[string]any{"password": p.New})
	data := helperData(resp)
	if err != nil || !boolValue(resp["ok"]) || numberValue(data["returncode"]) != 0 {
		message := "写入密码失败"
		if raw, ok := resp["message"].(string); ok && raw != "" {
			message = raw
		} else if raw, ok := data["stderr"].(string); ok && raw != "" {
			message = raw
		}
		if err != nil {
			message = err.Error()
		}
		s.writeAudit("set_panel_password", nil, false, message)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": message})
		return
	}
	s.writeAudit("set_panel_password", nil, true, "面板访问密码已更新")
	newRec, _ := s.loadAuth()
	respBody := map[string]any{"ok": true, "message": "密码已更新，其它设备上的会话已全部失效"}
	if token, e := issueSession(newRec); e == nil {
		setSessionCookie(w, token)
	}
	writeJSON(w, http.StatusOK, respBody)
}

func (s *Server) authOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var p struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Allowed      any    `json:"allowed_users"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&p) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	users := []string{}
	switch v := p.Allowed.(type) {
	case string:
		users = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	case []any:
		for _, x := range v {
			if value, ok := x.(string); ok {
				users = append(users, value)
			}
		}
	}
	for i := range users {
		users[i] = strings.ToLower(strings.TrimSpace(users[i]))
	}
	update := map[string]any{"oauth": map[string]any{"client_id": strings.TrimSpace(p.ClientID), "client_secret": strings.TrimSpace(p.ClientSecret), "allowed_users": users}}
	s.commitAuthUpdate(w, r, update, "set_oauth_config", "已保存 GitHub OAuth 配置")
}

func (s *Server) passwordToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var p struct {
		Disabled bool `json:"disabled"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&p) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数无效"})
		return
	}
	rec, configured := s.loadAuth()
	if !configured {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "面板尚未设置密码"})
		return
	}
	if p.Disabled {
		clientID, _ := rec.OAuth["client_id"].(string)
		secret, _ := rec.OAuth["client_secret"].(string)
		users, _ := rec.OAuth["allowed_users"].([]any)
		verified := boolValue(rec.OAuth["verified_once"])
		if strings.TrimSpace(clientID) == "" || strings.TrimSpace(secret) == "" || len(users) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "OAuth 尚未配置完整(需要 Client ID / Secret / 允许的用户)"})
			return
		}
		if !verified {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请先用 GitHub 成功登录一次，确认通路可用后再关闭密码登录"})
			return
		}
	}
	message := "已重新启用密码登录"
	if p.Disabled {
		message = "已关闭密码登录"
	}
	s.commitAuthUpdate(w, r, map[string]any{"password_disabled": p.Disabled}, "set_password_disabled", message)
}

func (s *Server) commitAuthUpdate(w http.ResponseWriter, r *http.Request, update map[string]any, operation, success string) {
	resp, err := helperCall(r.Context(), "update_panel_auth", map[string]any{"update": update})
	data := helperData(resp)
	if err != nil || !boolValue(resp["ok"]) || numberValue(data["returncode"]) != 0 {
		message := "写入认证配置失败"
		if raw, ok := resp["message"].(string); ok && raw != "" {
			message = raw
		} else if raw, ok := data["stderr"].(string); ok && raw != "" {
			message = raw
		}
		if err != nil {
			message = err.Error()
		}
		s.writeAudit(operation, nil, false, message)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": message})
		return
	}
	s.writeAudit(operation, nil, true, "认证配置已更新")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": success})
}

func randomTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), "="), nil
}

func hotp(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(secret), "="))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	if _, err := m.Write(msg[:]); err != nil {
		return "", err
	}
	digest := m.Sum(nil)
	off := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	rec, configured := s.loadAuth()
	if configured && boolValue(rec.TOTP["enabled"]) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "已启用二次认证，如需更换请先停用"})
		return
	}
	secret, err := randomTOTPSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "生成密钥失败"})
		return
	}
	s.pendingMu.Lock()
	s.pendingTOTP = secret
	s.pendingAt = time.Now()
	s.pendingMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "secret": secret, "uri": "otpauth://totp/dns-stack%3Apanel?secret=" + secret + "&issuer=dns-stack&algorithm=SHA1&digits=6&period=30", "message": "请用验证器扫码或手工输入密钥，再填入一次验证码完成启用"})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var p struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&p)
	s.pendingMu.Lock()
	secret, at := s.pendingTOTP, s.pendingAt
	s.pendingMu.Unlock()
	if secret == "" || time.Since(at) > 10*time.Minute {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "密钥已过期，请重新生成"})
		return
	}
	if !s.checkTOTPCode(p.Code, secret, true) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "验证码不正确，请确认验证器时间是否准确"})
		return
	}
	if s.commitAuthUpdateRaw(r.Context(), map[string]any{"totp": map[string]any{"secret": secret, "enabled": true}}, "enable_totp") {
		s.pendingMu.Lock()
		s.pendingTOTP = ""
		s.pendingMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "二次认证已启用，下次登录需要输入动态验证码"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "写入认证配置失败"})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var p struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&p)
	rec, ok := s.loadAuth()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "面板尚未设置密码"})
		return
	}
	ip := remoteIP(r)
	if wait := s.authWait(ip); wait > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "message": fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", wait), "retry_after": wait})
		return
	}
	if !verifyPassword(p.Password, rec) {
		s.authFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "密码不正确"})
		return
	}
	s.authSuccess(ip)
	if s.commitAuthUpdateRaw(r.Context(), map[string]any{"totp": nil}, "disable_totp") {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "二次认证已停用"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "写入认证配置失败"})
}

func (s *Server) commitAuthUpdateRaw(ctx context.Context, update map[string]any, operation string) bool {
	resp, err := helperCall(ctx, "update_panel_auth", map[string]any{"update": update})
	data := helperData(resp)
	ok := err == nil && boolValue(resp["ok"]) && numberValue(data["returncode"]) == 0
	s.writeAudit(operation, nil, ok, map[bool]string{true: "认证配置已更新", false: "写入认证配置失败"}[ok])
	return ok
}

func (s *Server) checkTOTPCode(code, secret string, consume bool) bool {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix() / 30
	for drift := int64(-1); drift <= 1; drift++ {
		value, err := hotp(secret, now+drift)
		if err == nil && hmacEqual(value, code) {
			if consume {
				s.pendingMu.Lock()
				if content, err := os.ReadFile(s.cfg.TOTPStepPath); err == nil {
					if floor, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64); err == nil && floor > s.totpLastStep {
						s.totpLastStep = floor
					}
				}
				if now+drift <= s.totpLastStep {
					s.pendingMu.Unlock()
					return false
				}
				s.totpLastStep = now + drift
				if temporary, err := os.CreateTemp(filepath.Dir(s.cfg.TOTPStepPath), ".totp-step-*"); err == nil {
					_, writeErr := temporary.WriteString(strconv.FormatInt(s.totpLastStep, 10))
					closeErr := temporary.Close()
					if writeErr == nil && closeErr == nil {
						_ = os.Rename(temporary.Name(), s.cfg.TOTPStepPath)
					}
					_ = os.Remove(temporary.Name())
				}
				s.pendingMu.Unlock()
			}
			return true
		}
	}
	return false
}

func hmacEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") || strings.Contains(name, "..") || net.ParseIP(name) != nil {
		return false
	}
	return domain.IsWellFormed(strings.ToLower(name))
}
