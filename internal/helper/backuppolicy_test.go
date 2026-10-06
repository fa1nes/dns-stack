package helper

import (
	"os"
	"strings"
	"testing"
)

func TestBackupPolicyAcceptsEveryValueTheBackupItselfAccepts(t *testing.T) {
	h := newTestHelper(t)
	res := h.opSetBackupPolicy(map[string]any{"interval_hours": float64(24), "keep_daily": float64(90), "keep_weekly": float64(104)})
	if res["ok"] != true {
		t.Fatalf("备份本身接受保留 90 份日备份、104 份周备份，面板却改不了：%v", res)
	}
	body, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(body), "BACKUP_RETENTION_DAILY=90\n") || !strings.Contains(string(body), "BACKUP_RETENTION_WEEKLY=104\n") {
		t.Fatalf("没写进 config.env：\n%s", body)
	}
	for _, bad := range []map[string]any{
		{"interval_hours": float64(24), "keep_daily": float64(0), "keep_weekly": float64(2)},
		{"interval_hours": float64(24), "keep_daily": float64(366), "keep_weekly": float64(2)},
		{"interval_hours": float64(-1), "keep_daily": float64(3), "keep_weekly": float64(2)},
	} {
		if res := h.opSetBackupPolicy(bad); res["ok"] == true {
			t.Errorf("越界的策略被接受了：%v", bad)
		}
	}
}
