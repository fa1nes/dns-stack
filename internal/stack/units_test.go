package stack

import (
	"os"
	"path/filepath"
	"testing"
)

func systemdDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "systemd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("找不到 systemd 目录: %v", err)
	}
	return dir
}

func TestEveryModuleHasAUnitFile(t *testing.T) {
	dir := systemdDir(t)
	for _, m := range All() {
		if m.Impl == ImplExternal {
			continue
		}
		service := filepath.Join(dir, m.Unit+".service")
		if _, err := os.Stat(service); err != nil {
			t.Errorf("%s(%s) 在清单里，但仓库没有 %s.service，面板会永远显示未运行",
				m.Name, m.Unit, m.Unit)
			continue
		}
		if m.Kind != KindJob {
			continue
		}
		timer := filepath.Join(dir, m.Unit+".timer")
		if _, err := os.Stat(timer); err != nil {
			t.Errorf("%s(%s) 声明为定时任务却没有 %s.timer，它永远不会自己运行",
				m.Name, m.Unit, m.Unit)
		}
	}
}

func TestEveryShippedUnitIsInTheRegistry(t *testing.T) {
	dir := systemdDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		unit, ok := cutSuffix(name, ".service")
		if !ok || unit == "mosproxy" {
			continue
		}
		seen++
		if _, found := Lookup(unit); !found {
			t.Errorf("仓库里有 %s 但清单没收录，它不会出现在面板和 dns-stack status 里", name)
		}
	}
	if seen == 0 {
		t.Fatal("一个 .service 都没扫到，这条判据本身失效了")
	}
}

func cutSuffix(value, suffix string) (string, bool) {
	if len(value) <= len(suffix) || value[len(value)-len(suffix):] != suffix {
		return "", false
	}
	return value[:len(value)-len(suffix)], true
}
