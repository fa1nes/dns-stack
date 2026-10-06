package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpsertReplacesInPlaceAndAppendsTheRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	original := "# 注释 BACKUP_RETENTION_DAILY=9\nROLE=cn-resolver\nBACKUP_RETENTION_DAILY=3\n\nPUBLIC_IPV4=203.0.113.1\n"
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Upsert(path, map[string]string{"BACKUP_RETENTION_DAILY": "7", "BACKUP_INTERVAL_HOURS": "72"}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	want := "# 注释 BACKUP_RETENTION_DAILY=9\nROLE=cn-resolver\nBACKUP_RETENTION_DAILY=7\n\nPUBLIC_IPV4=203.0.113.1\nBACKUP_INTERVAL_HOURS=72\n"
	if string(body) != want {
		t.Fatalf("改写结果：\n%s\n期望：\n%s", body, want)
	}
	if got := Read(path); got["ROLE"] != "cn-resolver" || got["BACKUP_INTERVAL_HOURS"] != "72" {
		t.Fatalf("其它键被动了：%v", got)
	}
}
