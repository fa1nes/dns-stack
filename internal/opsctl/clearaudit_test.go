package opsctl

import (
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"testing"
	"time"
)

func TestClearAuditLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT 'panel', operation TEXT NOT NULL, args TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"backup", "healthcheck"} {
		if _, err := db.Exec(`INSERT INTO audit_log(ts,operation) VALUES (1, ?)`, op); err != nil {
			t.Fatal(err)
		}
	}
	ctl := &Ctl{StateDir: dir, Out: io.Discard, AssumeYes: true, Now: time.Now}
	if err := ctl.ClearAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("清空之后还剩 %d 条——清空这个动作本身又被记了一条", left)
	}
}
