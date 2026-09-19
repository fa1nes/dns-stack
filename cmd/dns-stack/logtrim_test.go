package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrimDirectoryKeepsOnlyTailOfOversizedLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipeline.log")
	content := strings.Repeat("a", 64) + strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	result, err := trimDirectory(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result.Trimmed != 1 {
		t.Fatalf("trimmed=%d, want 1", result.Trimmed)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.Repeat("b", 64) {
		t.Fatalf("kept content=%q, want final 64 bytes", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%o, want 640", info.Mode().Perm())
	}
}

func TestTrimDirectoryIgnoresSmallAndNonLogFiles(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "verify.log")
	other := filepath.Join(dir, "state.db")
	if err := os.WriteFile(small, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte(strings.Repeat("x", 128)), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := trimDirectory(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result.Trimmed != 0 {
		t.Fatalf("trimmed=%d, want 0", result.Trimmed)
	}
	got, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 128 {
		t.Fatalf("non-log file changed: size=%d", len(got))
	}
}
