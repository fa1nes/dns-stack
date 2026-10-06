package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWeeklyArchivesDoNotDependOnLandingOnASunday(t *testing.T) {
	now := time.Date(2026, 10, 7, 3, 0, 0, 0, time.Local)
	dir := t.TempDir()
	c := Config{BackupDir: dir}
	if got := c.archivePrefix(now, true); got != "weekly" {
		t.Fatalf("一份周备份都没有时，第一份自动备份应当当作周备份，得到 %s", got)
	}
	if got := c.archivePrefix(now, false); got != "daily" {
		t.Fatalf("手动备份不该占用周备份名额，得到 %s", got)
	}
	weekly := filepath.Join(dir, "weekly-20261004030000.tar.zst")
	if err := os.WriteFile(weekly, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c2 := range []struct {
		age  time.Duration
		want string
	}{
		{3 * 24 * time.Hour, "daily"},
		{7 * 24 * time.Hour, "weekly"},
		{30 * 24 * time.Hour, "weekly"},
	} {
		stamp := now.Add(-c2.age)
		if err := os.Chtimes(weekly, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if got := c.archivePrefix(now, true); got != c2.want {
			t.Errorf("上一份周备份 %v 前，这次应当是 %s，得到 %s——每 3 天或每周备份一次时永远碰不上周日", c2.age, c2.want, got)
		}
	}
}
