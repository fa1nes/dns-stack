package ecszone

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishRollsBackToTheContentItReplaced(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ecs-ip-zone.txt")
	rows := []Row{{Lo: 0x01000000, Hi: 0x010000ff, Zone: "bj-ct"}}
	if err := os.WriteFile(out, []byte("previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out+".prev", []byte("stale from last week\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := Publish(out, rows, func() int {
		calls++
		if calls == 1 {
			return 500
		}
		return 200
	})
	if err == nil {
		t.Fatal("mosproxy 拒绝了新分片表，Publish 却报成功")
	}
	if body, _ := os.ReadFile(out); string(body) != "previous\n" {
		t.Fatalf("应当回滚到这次覆盖掉的内容，实际 %q——旧实现回滚到磁盘上的 .prev，而它可能是更早一代的", body)
	}

	fresh := filepath.Join(t.TempDir(), "ecs-ip-zone.txt")
	if _, err := Publish(fresh, rows, func() int { return 500 }); err == nil {
		t.Fatal("首次生成就被拒绝时应当报错")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("首次生成失败时不该留下一份 mosproxy 读不了的文件")
	}

	message, err := Publish(fresh, rows, func() int { return 0 })
	if err != nil || message == "" {
		t.Fatalf("mosproxy 没在运行时应当照常落盘并说明下次启动生效，err=%v", err)
	}
}
