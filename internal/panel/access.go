package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/stack"
)

var accessActions = map[string]string{
	"blocklist_add":    "加入域名黑名单",
	"blocklist_remove": "移出域名黑名单",
	"acl_add":          "放行网段",
	"acl_remove":       "收回网段",
	"acl_apply":        "下发访问控制",
	"acl_disable":      "关闭访问控制",
}

var dedicatedOpRoles = map[string]string{
	"blocklist_add":    stack.RoleCNResolver,
	"blocklist_remove": stack.RoleCNResolver,
	"acl_add":          stack.RoleCNResolver,
	"acl_remove":       stack.RoleCNResolver,
	"acl_apply":        stack.RoleCNResolver,
	"acl_disable":      stack.RoleCNResolver,
	"acl_status":       stack.RoleCNResolver,
}

func (s *Server) accessStore() access.Store {
	return access.Store{StateDir: s.cfg.StateDir}
}

func (s *Server) aclInstalled(r *http.Request) (bool, string) {
	resp, err := helperCall(r.Context(), "acl_status", nil)
	if err != nil || !boolValue(resp["ok"]) {
		return false, ""
	}
	var parsed struct {
		Installed bool   `json:"installed"`
		Table     string `json:"table"`
	}
	text, _ := helperData(resp)["stdout"].(string)
	if json.Unmarshal([]byte(text), &parsed) != nil {
		return false, ""
	}
	return parsed.Installed, parsed.Table
}

func renderPrefixes(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.accessList(w, r)
	case http.MethodPost:
		s.accessMutate(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) accessList(w http.ResponseWriter, r *http.Request) {
	store := s.accessStore()
	out := map[string]any{
		"role":      s.role(),
		"blocklist": []string{},
		"acl":       []string{},
		"client_ip": remoteIP(r),
	}
	if s.role() != stack.RoleCNResolver {
		out["note"] = "域名黑名单与访问控制只作用在承载 DoH/DoT 入口的国内节点上，本机不是"
		writeJSON(w, http.StatusOK, out)
		return
	}
	blocked, err := store.Blocklist()
	if err != nil {
		out["blocklist_error"] = err.Error()
	} else if blocked != nil {
		out["blocklist"] = blocked
	}
	prefixes, err := store.ACL()
	if err != nil {
		out["acl_error"] = err.Error()
	} else {
		out["acl"] = renderPrefixes(prefixes)
	}
	installed, _ := s.aclInstalled(r)
	out["acl_installed"] = installed
	out["client_loopback"] = clientIsLoopback(r)
	out["client_covered"] = len(prefixes) > 0 && cidrutil.NewSet(prefixes).Contains(parseClient(r))
	writeJSON(w, http.StatusOK, out)
}

func parseClient(r *http.Request) netip.Addr {
	addr, err := netip.ParseAddr(remoteIP(r))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func clientIsLoopback(r *http.Request) bool {
	addr := parseClient(r)
	return !addr.IsValid() || addr.IsLoopback()
}

func (s *Server) accessMutate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action   string   `json:"action"`
		Domains  []string `json:"domains"`
		Prefixes []string `json:"prefixes"`
		Confirm  bool     `json:"confirm"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 128*1024)).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数不是合法 JSON"})
		return
	}
	label, known := accessActions[body.Action]
	if !known {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "不支持的操作"})
		return
	}
	if want := dedicatedOpRoles[body.Action]; want != "" && s.role() != want {
		s.writeAudit(body.Action, nil, false, "角色不匹配，拒绝执行")
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
			"message": "只有承载 DoH/DoT 入口的国内节点才有黑名单与访问控制，本机角色是 " + s.role()})
		return
	}

	args := map[string]any{"confirm": true}
	if strings.HasPrefix(body.Action, "blocklist_") {
		if len(body.Domains) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "没有给出任何域名"})
			return
		}
		args["domains"] = body.Domains
	} else if body.Action == "acl_add" || body.Action == "acl_remove" {
		if len(body.Prefixes) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "没有给出任何网段"})
			return
		}
		args["prefixes"] = body.Prefixes
	}

	if strings.HasPrefix(body.Action, "acl_") && body.Action != "acl_disable" {
		if message := s.aclLockoutCheck(r, body.Action, body.Prefixes); message != "" {
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "message": message})
			return
		}
	}
	if strings.HasPrefix(body.Action, "acl_") && !body.Confirm {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"ok": false, "need_confirm": true,
			"message": "「" + label + "」会即时改变谁能查询这台 DNS，请确认后再执行"})
		return
	}

	resp, err := helperCall(r.Context(), body.Action, args)
	data := helperData(resp)
	ok := err == nil && boolValue(resp["ok"]) && numberValue(data["returncode"]) == 0
	stdout, _ := data["stdout"].(string)
	stderr, _ := data["stderr"].(string)
	message := strings.TrimSpace(stdout)
	if message == "" {
		message = strings.TrimSpace(stderr)
	}
	if message == "" {
		if raw, _ := resp["message"].(string); raw != "" {
			message = raw
		} else if err != nil {
			message = err.Error()
		} else if ok {
			message = label + "：执行成功"
		} else {
			message = label + "：执行失败"
		}
	}
	s.writeAudit(body.Action, args, ok, message)
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "label": label, "message": message})
}

func (s *Server) aclLockoutCheck(r *http.Request, action string, entries []string) string {
	if clientIsLoopback(r) {
		return ""
	}
	client := parseClient(r)
	if !client.IsValid() {
		return ""
	}
	current, err := s.accessStore().ACL()
	if err != nil {
		return "读不到当前授权网段，拒绝在看不清现状时改访问控制: " + err.Error()
	}
	parsed, bad := cidrutil.ParseSet(entries)
	if len(bad) > 0 {
		return "非法条目: " + strings.Join(bad, " ")
	}
	var final []netip.Prefix
	switch action {
	case "acl_add":
		final = cidrutil.CollapsePrefixes(append(append([]netip.Prefix{}, current...), parsed.Prefixes()...))
	case "acl_remove":
		final = cidrutil.Subtract(current, parsed.Prefixes())
	default:
		final = current
	}
	if len(final) == 0 {
		return "结果是空白名单——空的白名单会把所有客户端挡在外面，拒绝下发"
	}
	if !cidrutil.NewSet(final).Contains(client) {
		return "拒绝：改完之后你自己（" + client.String() + "）就不在授权网段里了，" +
			"这一下会把你锁在门外。要么先把自己的网段加进去，要么改用 SSH 执行 dns-stack acl"
	}
	return ""
}
