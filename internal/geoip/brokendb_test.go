package geoip

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestABrokenDatabaseIsReportedUnavailableAndSafeUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	cnip := filepath.Join(dir, "qqwry.ipdb")
	for _, path := range []string{asn, cnip} {
		if err := os.WriteFile(path, []byte("not a database at all"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	db := NewGeoDBExact(asn, filepath.Join(dir, "missing-city.mmdb"), cnip)
	if db.HasASN() {
		t.Fatal("ASN 库是坏的，HasASN 却说可用——读者是带类型的 nil，接口值不等于 nil")
	}
	status := db.Status()
	if status["available"].(bool) {
		t.Fatalf("三个库都不可用，Status 却报可用: %v", status)
	}
	if msg, _ := status["asn"].(map[string]any)["error"].(string); msg == "" {
		t.Error("坏库应当带上打开失败的原因")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				db.Status()
				db.Sources("1.1.1.1")
				db.Lookup("8.8.8.8")
			}
		}()
	}
	wg.Wait()
}

func TestAPointerThatPointsAtItselfIsAnErrorNotAStackOverflow(t *testing.T) {
	data := []byte{0x20, 0x00}
	if _, _, err := (decoder{b: data}).decode(0); err == nil {
		t.Fatal("自指的 mmdb 指针应当报错——否则一个 16 字节的坏库就能把读它的进程栈打爆")
	}
}
