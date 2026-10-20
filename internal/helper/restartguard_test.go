package helper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRestartUnboundRefusesWhenConfigFailsCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("用 shell 脚本冒充 unbound-checkconf / systemctl")
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "restarted")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("systemctl", ": > "+marker)
	t.Setenv("PATH", bin)
	h := newTestHelper(t)

	write("unbound-checkconf", "echo 'syntax error line 12' >&2; exit 1")
	r := h.opRestartUnbound(nil)
	if r["ok"] == true {
		t.Fatalf("配置校验失败时不该报成功: %v", r)
	}
	if stderr, _ := r["stderr"].(string); !strings.Contains(stderr, "syntax error line 12") {
		t.Errorf("失败原因要带上 checkconf 的输出，好知道哪一行错了: %q", stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("配置坏了还是执行了 systemctl restart：Unbound 会停下来再也起不来")
	}

	write("unbound-checkconf", "exit 0")
	if r := h.opRestartUnbound(nil); r["ok"] != true {
		t.Fatalf("校验通过后应当照常重启: %v", r)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("校验通过了却没有重启")
	}
}
