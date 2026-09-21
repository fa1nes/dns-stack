package panel

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fileLineBudget = 700

func TestNoPanelFileGrowsBackIntoADumpingGround(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if lines := bytes.Count(body, []byte("\n")); lines > fileLineBudget {
			t.Errorf("%s 有 %d 行，超过 %d 行的预算——"+
				"server.go 曾经涨到 1830 行、装下了生命周期、认证、查询、诊断和六个代理端点，"+
				"按职责拆成同包内的多个文件，不要新开子包", path, lines, fileLineBudget)
		}
	}
}
