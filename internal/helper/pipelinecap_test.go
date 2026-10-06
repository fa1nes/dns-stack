package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPipelineRunsFromThePanelKeepTheUnitMemoryCap(t *testing.T) {
	unit, err := os.ReadFile("../../systemd/dns-stack-routing-data.service")
	if err != nil {
		t.Skipf("读不到 routing-data 单元: %v", err)
	}
	for _, property := range pipelineMemoryCap {
		if !strings.Contains(string(unit), "\n"+property+"\n") {
			t.Errorf("面板触发的流水线限额 %s 和 dns-stack-routing-data.service 不一致", property)
		}
	}

	data := t.TempDir()
	for _, name := range []string{"psl.dat", "qqwry.ipdb"} {
		if err := os.WriteFile(filepath.Join(data, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PSL_FILE", filepath.Join(data, "psl.dat"))
	t.Setenv("CNIP_DB", filepath.Join(data, "qqwry.ipdb"))
	h := newTestHelper(t)
	var seen [][]string
	h.onRun = func(argv []string) { seen = append(seen, argv) }
	args := map[string]any{"confirm": true, "list": "cn", "domains": "sb.sb"}
	for _, op := range []string{"refresh_routing", "route_add", "route_remove"} {
		seen = nil
		h.operations()[op](args)
		if len(seen) != 1 || seen[0][0] != "systemd-run" {
			t.Errorf("%s 直接在助手里跑流水线，没有内存上限——助手单元本身不限内存，失控会拖垮整机：%v", op, seen)
		}
	}
}
