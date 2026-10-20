package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepStaleTempsOnlyTakesOldLeftovers(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	write := func(name string, mtime time.Time) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	write("direct4.txt", old)
	write(".direct4.txt.123456", old)
	write(".direct4.txt.999", now)
	write(".gone.txt.4242", old)
	write(".stats.Ab12Cd", old)
	write(".route-lists.lock", old)
	write("notes.123", old)

	removed, err := SweepStaleTemps([]string{dir, filepath.Join(dir, "missing")}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{".direct4.txt.123456": true, ".stats.Ab12Cd": true}
	if len(removed) != len(want) {
		t.Fatalf("删了 %v，只该删 %v", removed, want)
	}
	for _, path := range removed {
		if !want[filepath.Base(path)] {
			t.Errorf("不该删 %s", path)
		}
	}
	for _, keep := range []string{"direct4.txt", ".direct4.txt.999", ".gone.txt.4242", ".route-lists.lock", "notes.123"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s 被误删", keep)
		}
	}
}
