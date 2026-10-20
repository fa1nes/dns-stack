package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeECS(t *testing.T, dir, name string, prefixes ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("server:\n")
	for _, prefix := range prefixes {
		b.WriteString("    send-client-subnet: " + prefix + "\n")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestECSOnlyGrewSeesMergesAsGrowthAndDropsAsChange(t *testing.T) {
	dir := t.TempDir()
	live := writeECS(t, dir, "live", "43.134.249.21/32", "205.251.194.0/24", "1.2.3.0/24")
	grown := writeECS(t, dir, "grown", "43.134.249.20/31", "205.251.194.0/23", "1.2.3.0/24", "47.89.91.0/24", "52.46.180.215/32")
	if added, ok := ecsOnlyGrew(live, grown); !ok || added != 4 {
		t.Fatalf("CN 23:01 那一轮只有新增和合并变宽，应当算只增不减：added=%d ok=%v", added, ok)
	}
	dropped := writeECS(t, dir, "dropped", "43.134.249.20/31", "205.251.194.0/23", "47.89.91.0/24")
	if _, ok := ecsOnlyGrew(live, dropped); ok {
		t.Fatal("1.2.3.0/24 被删了，必须立即重载，不能攒")
	}
	same := writeECS(t, dir, "same", "1.2.3.0/24", "43.134.249.21/32", "205.251.194.0/24")
	if _, ok := ecsOnlyGrew(live, same); ok {
		t.Fatal("没有新增就不是增长")
	}
}
