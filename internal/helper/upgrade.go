package helper

import (
	"encoding/json"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

const upgradeLogKeep = 12000

func upgradeCommand(goBin string, args map[string]any, check bool) ([]string, string, bool) {
	target := stringArg(args, "target")
	command := []string{goBin, "upgrade", "--json"}
	switch target {
	case "", "dns-stack":
		target = "dns-stack"
	case "mosproxy":
		command = append(command, "--mosproxy")
	default:
		return nil, "", false
	}
	if check {
		command = append(command, "--check")
	}
	return command, target, true
}

func (h *Helper) upgradeRunning() bool {
	r := h.run([]string{"systemctl", "is-active", "--quiet", stack.UpgradeUnit + ".service"}, 10*time.Second, false)
	return r["ok"] == true
}

func (h *Helper) opUpgradeCheck(args map[string]any) result {
	command, _, ok := upgradeCommand(h.goBin, args, true)
	if !ok {
		return failure("target 只能是 dns-stack 或 mosproxy")
	}
	return h.run(command, 300*time.Second, true)
}

func (h *Helper) opUpgradeApply(args map[string]any) result {
	command, target, ok := upgradeCommand(h.goBin, args, false)
	if !ok {
		return failure("target 只能是 dns-stack 或 mosproxy")
	}
	if h.onRun == nil && h.upgradeRunning() {
		return failure("已有一次升级正在进行，等它结束再试")
	}
	argv := append([]string{"systemd-run", "--collect", "--quiet", "-p", "MemoryMax=512M",
		"--unit", stack.UpgradeUnit}, command...)
	r := h.run(argv, 30*time.Second, true)
	if r["ok"] == true {
		r["stdout"] = "已在后台开始升级 " + target + "，面板和管理助手会重启，稍等片刻自动刷新"
		h.log("开始升级 " + target)
	}
	return r
}

func (h *Helper) opUpgradeStatus(map[string]any) result {
	running := h.upgradeRunning()
	logs := h.runKeep([]string{"journalctl", "--since", "-24h", "-n", "120", "-o", "short-iso", "--no-pager",
		"-u", stack.UpgradeUnit + ".service"}, 15*time.Second, true, upgradeLogKeep)
	stdout, _ := logs["stdout"].(string)
	encoded, _ := json.Marshal(map[string]any{"running": running, "log": stdout})
	return result{"ok": true, "returncode": 0, "stdout": string(encoded), "stderr": ""}
}
