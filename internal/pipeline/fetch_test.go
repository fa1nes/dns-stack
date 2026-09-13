package pipeline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlowTrickleIsAbandonedInsteadOfHangingToTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 200; i++ {
			w.Write([]byte("x"))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(30 * time.Millisecond)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	rt := NewRuntime(Config{StateDir: dir}, io.Discard)
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, err := rt.Fetch(ctx, fetchSpec{
		Kind: "slow", URL: server.URL, Dest: filepath.Join(dir, "slow.bin"), MinBytes: 1_000_000,
	})
	if err == nil {
		t.Fatal("慢速涓流应当被放弃")
	}
	if took := time.Since(started); took > 80*time.Second {
		t.Errorf("放弃用了 %s，速度下限保护没生效（原 shell 是 20 秒窗口）", took)
	}
}

func TestGithubURLsTryTheTunnelFirst(t *testing.T) {
	for _, url := range []string{
		"https://github.com/x/y/releases/latest/download/z.ipdb",
		"https://objects.githubusercontent.com/a/b",
		"https://raw.githubusercontent.com/a/b",
	} {
		if !prefersTunnel(url) {
			t.Errorf("%s 在大陆直连不通，应当优先走隧道", url)
		}
	}
	for _, url := range []string{
		"https://cdn.jsdelivr.net/gh/a/b.mmdb",
		"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
	} {
		if prefersTunnel(url) {
			t.Errorf("%s 直连可用，不该浪费一次隧道尝试", url)
		}
	}
}

func TestTruncatedDownloadIsRejectedAndKeepsTheOldFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("too small"))
	}))
	defer server.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dest, []byte(strings.Repeat("old", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := NewRuntime(Config{StateDir: dir}, io.Discard)
	if _, err := rt.Fetch(context.Background(), fetchSpec{
		Kind: "db", URL: server.URL, Dest: dest, MinBytes: 1_000_000,
	}); err == nil {
		t.Fatal("残缺下载应当被拒绝")
	}
	data, err := os.ReadFile(dest)
	if err != nil || !strings.HasPrefix(string(data), "old") {
		t.Error("残缺下载不该覆盖现有的库文件")
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Error("失败后不该留下 .part 临时文件")
	}
}
