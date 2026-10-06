package pipeline

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestManualZonesReadNotesTheWayMosproxyDoes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual-cn-zones.txt")
	body := "# Apple 的说明\napple.com\nSB.SB.  # 按来源地区给地址\niqiyi.com#权威在境外\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := manualZones(path); !reflect.DeepEqual(got, []string{"apple.com", "sb.sb", "iqiyi.com"}) {
		t.Fatalf("写在域名后面的说明被当成了域名的一部分，这一行等于没写：%q", got)
	}
}
