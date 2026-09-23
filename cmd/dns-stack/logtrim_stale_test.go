package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
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
	writeLog(t, dir, "unbound.log", 90*24*time.Hour)
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

func TestDropStaleLogsRefusesWhenNoModuleDeclaresALogFile(t *testing.T) {
	declared := 0
	for _, module := range stack.All() {
		if module.LogFile != "" {
			declared++
		}
	}
	if declared == 0 {
		t.Fatal("没有任何模块声明 LogFile——dropStaleLogs 的「活着的日志」集合会是空的，" +
			"于是它会删掉目录里每一份超过 14 天没人写的 .log，包括还在用的那些")
	}

	dir := t.TempDir()
	writeLog(t, dir, "unbound.log", 90*24*time.Hour)
	removed, _, err := dropStaleLogs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("模块清单里声明过的日志不该被当成僵尸，实际删了 %v", removed)
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
