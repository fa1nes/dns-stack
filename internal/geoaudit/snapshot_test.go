package geoaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotsKeepTheLastGoodVersionWhenTheCriterionCannotSpeak(t *testing.T) {
	dir := t.TempDir()
	disputed, promoted := filepath.Join(dir, "geo-disputed.txt"), filepath.Join(dir, "geo-promoted.txt")
	for _, path := range []string{disputed, promoted} {
		if err := os.WriteFile(path, []byte("good\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name                string
		report              Report
		keepDisp, keepPromo bool
	}{
		{"fail-open", Report{FailOpen: "可用源不足 2 个"}, true, true},
		{"争议骤降", Report{DisputeRejected: "争议段骤降"}, true, false},
		{"晋级骤降", Report{PromoteRejected: "晋级段骤增"}, false, true},
	}
	for _, c := range cases {
		for _, path := range []string{disputed, promoted} {
			_ = os.WriteFile(path, []byte("good\n"), 0o644)
		}
		kept, err := WriteSnapshots(disputed, promoted, c.report)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(kept) == 0 {
			t.Errorf("%s: 没有说明哪份清单没更新", c.name)
		}
		for path, keep := range map[string]bool{disputed: c.keepDisp, promoted: c.keepPromo} {
			body, _ := os.ReadFile(path)
			if (string(body) == "good\n") != keep {
				t.Errorf("%s: %s 保留=%v，期望 %v——判据没能力发言时写一份空清单配新时间戳，"+
					"陈旧告警就永远不会响", c.name, filepath.Base(path), string(body) == "good\n", keep)
			}
		}
	}
}
