package cnauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManualZonesIgnoreNotesAfterTheDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual-cn-zones.txt")
	body := "# 说明\napple.com\nSB.SB.  # 按来源地区给地址\niqiyi.com#权威在境外\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadManual(path)
	for _, zone := range []string{"apple.com", "sb.sb", "iqiyi.com"} {
		if _, ok := got[zone]; !ok {
			t.Errorf("%s 没被当成人工区域——写在后面的说明把这一行废掉了：%v", zone, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("多出了条目：%v", got)
	}
}
