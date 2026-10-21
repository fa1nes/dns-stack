package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

const (
	mosproxyBuildIDPath = "/opt/dns-stack/bin/mosproxy.build-id"
	upgradeCheckTimeout = 310 * time.Second
	upgradeLogLines     = 40
)

func lastUpgradeResult(text string) (map[string]any, []string) {
	var last map[string]any
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, payload, found := strings.Cut(line, stack.UpgradeResultPrefix); found {
			var parsed map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(payload)), &parsed) == nil {
				last = parsed
			}
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) > upgradeLogLines {
		lines = lines[len(lines)-upgradeLogLines:]
	}
	return last, lines
}

func (s *Server) mosproxyVersion() string {
	data, err := os.ReadFile(mosproxyBuildIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	supported := s.role() == stack.RoleCNResolver
	switch r.Method {
	case http.MethodGet:
		out := map[string]any{"supported": supported, "version": s.cfg.Version, "mosproxy_version": s.mosproxyVersion(),
			"running": false, "last": nil, "log": []string{}}
		if !supported {
			writeJSON(w, http.StatusOK, out)
			return
		}
		resp, err := helperCall(r.Context(), "upgrade_status", nil)
		if err != nil {
			out["error"] = err.Error()
			writeJSON(w, http.StatusOK, out)
			return
		}
		stdout, _ := helperData(resp)["stdout"].(string)
		var status struct {
			Running bool   `json:"running"`
			Log     string `json:"log"`
		}
		_ = json.Unmarshal([]byte(stdout), &status)
		last, lines := lastUpgradeResult(status.Log)
		out["running"], out["last"], out["log"] = status.Running, last, lines
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		if !supported {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "message": "香港节点不走在线升级：重新运行 install-hk.sh 就是升级"})
			return
		}
		var body struct {
			Action  string `json:"action"`
			Target  string `json:"target"`
			Confirm bool   `json:"confirm"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数不是合法 JSON 对象"})
			return
		}
		if body.Target != "dns-stack" && body.Target != "mosproxy" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "target 只能是 dns-stack 或 mosproxy"})
			return
		}
		args := map[string]any{"target": body.Target}
		switch body.Action {
		case "check":
			ctx, cancel := context.WithTimeout(r.Context(), upgradeCheckTimeout)
			defer cancel()
			resp, err := helperCall(ctx, "upgrade_check", args)
			data := helperData(resp)
			stdout, _ := data["stdout"].(string)
			stderr, _ := data["stderr"].(string)
			last, lines := lastUpgradeResult(stdout + "\n" + stderr)
			ok := err == nil && last != nil && last["error"] == nil
			message := ""
			if err != nil {
				message = err.Error()
			} else if last == nil {
				message = strings.TrimSpace(stderr)
			} else if text, _ := last["error"].(string); text != "" {
				message = text
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "result": last, "log": lines, "message": message})
		case "apply":
			if !body.Confirm {
				writeJSON(w, http.StatusPreconditionRequired, map[string]any{"ok": false, "need_confirm": true,
					"message": "升级会替换二进制并重启服务，请确认后再执行"})
				return
			}
			args["confirm"] = true
			resp, err := helperCall(r.Context(), "upgrade_apply", args)
			data := helperData(resp)
			ok := err == nil && boolValue(resp["ok"]) && numberValue(data["returncode"]) == 0
			message, _ := data["stdout"].(string)
			if !ok {
				message, _ = data["stderr"].(string)
				if message == "" && err != nil {
					message = err.Error()
				}
			}
			s.writeAudit("upgrade_apply", args, ok, message)
			writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "message": strings.TrimSpace(message)})
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "action 只能是 check 或 apply"})
		}
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}
