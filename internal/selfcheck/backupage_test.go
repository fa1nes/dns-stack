package selfcheck

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupAgeFollowsTheConfiguredInterval(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		interval string
		age      time.Duration
		want     string
	}{
		{"", 30 * time.Hour, "ok"},
		{"", 50 * time.Hour, "warn"},
		{"72", 50 * time.Hour, "ok"},
		{"72", 100 * time.Hour, "warn"},
		{"0", 400 * time.Hour, "skip"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		conf := filepath.Join(dir, "config.env")
		body := "ROLE=cn-resolver\n"
		if c.interval != "" {
			body += "BACKUP_INTERVAL_HOURS=" + c.interval + "\n"
		}
		if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		backups := filepath.Join(dir, "backups")
		if err := os.Mkdir(backups, 0o700); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(backups, "daily-1.tar.zst")
		if err := os.WriteFile(archive, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-c.age)
		if err := os.Chtimes(archive, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		report := &Report{}
		judgeBackupAge(&checker{report: report, group: "运维与恢复"},
			Options{StateDir: dir, ConfigFile: conf, BackupDir: backups}, now)
		got := report.Results[len(report.Results)-1]
		if string(got.Level) != c.want {
			t.Errorf("间隔 %q、备份 %v 前：判成 %s（%s），期望 %s——面板上改成每 3 天备份后，自检不该天天报警",
				c.interval, c.age, got.Level, got.Detail, c.want)
		}
	}
}
