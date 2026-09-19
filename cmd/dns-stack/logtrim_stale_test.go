package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLog(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDropStaleLogsSparesLiveAndRecentFiles(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, dir, "helper.log", 90*24*time.Hour)
	writeLog(t, dir, "pipeline.log", 90*24*time.Hour)
	writeLog(t, dir, "unbound.log", time.Hour)
	writeLog(t, dir, "notes.txt", 90*24*time.Hour)

	removed, _, err := dropStaleLogs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "pipeline.log" {
		t.Fatalf("只有既不在模块清单、又长期没人写的日志才该被删，实际删了 %v", removed)
	}
	for _, keep := range []string{"helper.log", "unbound.log", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s 不该被删: %v", keep, err)
		}
	}
}

func TestDropStaleLogsKeepsRecentlyWrittenUnknownLogs(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, dir, "mystery.log", 2*24*time.Hour)
	removed, _, err := dropStaleLogs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("两天前还在写的日志不算僵尸，实际删了 %v——"+
			"「不在模块清单里」不等于「没人在写」", removed)
	}
}
