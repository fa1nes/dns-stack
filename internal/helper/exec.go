package helper

import (
	"context"
	"os/exec"
	"time"
)

const (
	stdoutKeepRunes = 20000
	stderrKeepRunes = 8000
)

type result map[string]any

func tailRunes(text string, keep int) string {
	runes := []rune(text)
	if len(runes) <= keep {
		return text
	}
	return string(runes[len(runes)-keep:])
}

func failure(message string) result {
	return result{"ok": false, "returncode": -1, "stdout": "", "stderr": message}
}

func (h *Helper) run(args []string, timeout time.Duration, sanitize bool) result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr []byte
	stdoutPipe, stderrPipe := &captureBuffer{}, &captureBuffer{}
	cmd.Stdout, cmd.Stderr = stdoutPipe, stderrPipe
	err := cmd.Run()
	stdout, stderr = stdoutPipe.Bytes(), stderrPipe.Bytes()

	if ctx.Err() == context.DeadlineExceeded {
		return failure("操作超时")
	}

	if err != nil && cmd.ProcessState == nil {
		return failure("命令不存在: " + err.Error())
	}
	code := cmd.ProcessState.ExitCode()
	out, errText := tailRunes(string(stdout), stdoutKeepRunes), tailRunes(string(stderr), stderrKeepRunes)
	if sanitize {
		out, errText = Sanitize(out, h.configPath), Sanitize(errText, h.configPath)
	}
	return result{"ok": code == 0, "returncode": code, "stdout": out, "stderr": errText}
}

type step struct {
	label   string
	command []string
	timeout time.Duration
}

func (h *Helper) runSteps(steps []step) result {
	var stdout, stderr []string
	for _, s := range steps {
		r := h.run(s.command, s.timeout, true)
		if text, _ := r["stdout"].(string); text != "" {
			stdout = append(stdout, "["+s.label+"]\n"+text)
		}
		if text, _ := r["stderr"].(string); text != "" {
			stderr = append(stderr, "["+s.label+"]\n"+text)
		}
		if ok, _ := r["ok"].(bool); !ok {
			code, _ := r["returncode"].(int)
			return result{"ok": false, "returncode": code,
				"stdout": joinLines(stdout), "stderr": joinLines(stderr)}
		}
	}
	return result{"ok": true, "returncode": 0,
		"stdout": joinLines(stdout), "stderr": joinLines(stderr)}
}

func joinLines(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += "\n"
		}
		out += part
	}
	return out
}

type captureBuffer struct{ data []byte }

func (b *captureBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *captureBuffer) Bytes() []byte { return b.data }
