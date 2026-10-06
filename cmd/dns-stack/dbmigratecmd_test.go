package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDBMigrateRejectsUnsupportedRoleBeforeSystemChanges(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	if err := os.WriteFile(configPath, []byte("ROLE=offshore\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := cmdDBMigrate([]string{
		"--config", configPath,
		"--state", filepath.Join(dir, "state"),
		"--backup-dir", filepath.Join(dir, "backups"),
	})
	if err == nil || !strings.Contains(err.Error(), "仅适用于国内解析节点") {
		t.Fatalf("offshore db-migrate error = %v, want role rejection", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "backups")); !os.IsNotExist(err) {
		t.Fatalf("unsupported role caused filesystem changes before rejection: %v", err)
	}
}
