package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupStepFollowsTheConfiguredInterval(t *testing.T) {
	dir := t.TempDir()
	for raw, want := range map[string]time.Duration{
		"": 24 * time.Hour, "72": 72 * time.Hour, "168": 168 * time.Hour, "0": 0, "abc": 24 * time.Hour,
	} {
		conf := filepath.Join(dir, "config.env")
		if err := os.WriteFile(conf, []byte("BACKUP_INTERVAL_HOURS="+raw+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := LoadConfig(dir, conf)
		if got := BackupInterval(cfg); got != want {
			t.Errorf("BACKUP_INTERVAL_HOURS=%q 得到 %v，期望 %v", raw, got, want)
		}
		for _, step := range MaintenanceSteps(cfg) {
			if step.Name == "backup" && want > 0 && step.Every != want {
				t.Errorf("BACKUP_INTERVAL_HOURS=%q 时备份步骤每 %v 跑一次，面板上设的是 %v", raw, step.Every, want)
			}
		}
	}
}
