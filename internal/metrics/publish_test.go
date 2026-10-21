package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceAndReloadKeepsWhatMosproxyCanStillStartWith(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecs-fanout.txt")
	if err := os.WriteFile(path, []byte("bj-cu,111.198.122.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := ReplaceAndReload(path, []byte("broken\n"), "并发清单", func() int {
		calls++
		if calls == 1 {
			return 500
		}
		return 200
	})
	if err == nil || !strings.Contains(err.Error(), "已回滚") {
		t.Fatalf("mosproxy 拒绝新清单时应当回滚并报错，err=%v", err)
	}
	if body, _ := os.ReadFile(path); string(body) != "bj-cu,111.198.122.0/24\n" {
		t.Fatalf("留在盘上的必须是上一版，否则 mosproxy 下次重启会读到坏文件起不来: %q", body)
	}
	message, err := ReplaceAndReload(path, []byte("bj-ct,1.203.88.0/24\n"), "并发清单", func() int { return 200 })
	if err != nil || !strings.Contains(message, "并发清单") {
		t.Fatalf("热加载成功应当返回说明，message=%q err=%v", message, err)
	}
}
