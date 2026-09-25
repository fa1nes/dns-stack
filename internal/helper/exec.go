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
	if h.onRun != nil {
		h.onRun(args)
		return result{"ok": true, "returncode": 0, "stdout": "", "stderr": ""}
	}
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

type captureBuffer struct{ data []byte }

func (b *captureBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *captureBuffer) Bytes() []byte { return b.data }
