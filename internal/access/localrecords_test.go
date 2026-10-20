package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLocalRecordRejectsMismatchedFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, kind, value string
		ok                bool
	}{
		{"NAS.home.arpa.", "a", "192.168.1.2", true},
		{"nas.home.arpa", "AAAA", "fd00::2", true},
		{"nas.home.arpa", "A", "fd00::2", false},
		{"nas.home.arpa", "AAAA", "192.168.1.2", false},
		{"nas.home.arpa", "AAAA", "::ffff:192.168.1.2", false},
		{"nas", "A", "192.168.1.2", false},
		{"nas.home.arpa", "CNAME", "192.168.1.2", false},
		{"nas.home.arpa", "A", "fe80::1%eth0", false},
		{"bad name.lan", "A", "1.2.3.4", false},
	} {
		record, err := ParseLocalRecord(tc.name, tc.kind, tc.value)
		if (err == nil) != tc.ok {
			t.Errorf("%s %s %s: err=%v, want ok=%v", tc.name, tc.kind, tc.value, err, tc.ok)
		}
		if err == nil && (record.Name != strings.ToLower(strings.TrimSuffix(tc.name, ".")) || record.Type != strings.ToUpper(tc.kind)) {
			t.Errorf("没有规范化: %+v", record)
		}
	}
}

func TestLocalRecordsRoundTripAndRemoveByName(t *testing.T) {
	store := Store{StateDir: t.TempDir()}
	for _, raw := range [][3]string{
		{"nas.home.arpa", "A", "192.168.1.2"},
		{"nas.home.arpa", "AAAA", "fd00::2"},
		{"router.home.arpa", "A", "192.168.1.1"},
	} {
		record, err := ParseLocalRecord(raw[0], raw[1], raw[2])
		if err != nil {
			t.Fatal(err)
		}
		if added, err := store.AddLocalRecord(record); err != nil || !added {
			t.Fatalf("add %v: %v %v", record, added, err)
		}
	}
	dup, _ := ParseLocalRecord("nas.home.arpa", "A", "192.168.1.2")
	if added, err := store.AddLocalRecord(dup); err != nil || added {
		t.Fatalf("重复记录被当成新的: %v %v", added, err)
	}
	removed, err := store.RemoveLocalRecords("NAS.home.arpa.", "", "")
	if err != nil || len(removed) != 2 {
		t.Fatalf("按名字删应删掉两条: %v %v", removed, err)
	}
	left, err := store.LocalRecords()
	if err != nil || len(left) != 1 || left[0].Name != "router.home.arpa" {
		t.Fatalf("剩下的不对: %v %v", left, err)
	}
	conf := RenderUnboundLocal(left)
	if !strings.Contains(conf, `local-data: "router.home.arpa. 300 IN A 192.168.1.1"`) {
		t.Fatalf("渲染结果不对:\n%s", conf)
	}
}

func TestLocalRecordsRefuseAMalformedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LocalRecordsFile), []byte("nas.lan A not-an-ip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{StateDir: dir}).LocalRecords(); err == nil {
		t.Fatal("坏行应该报错，而不是被静默跳过后渲染出缺条目的配置")
	}
}

func TestShadowingFollowsMosproxyRuleOrder(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(BlocklistFile, "ads.example.com\n")
	write(RouteHKFile, "example.org\n")
	write("manual-exclude.txt", "local.example.org\n")
	store := Store{StateDir: dir}
	for name, want := range map[string]bool{
		"x.ads.example.com":   true,
		"www.example.org":     true,
		"a.local.example.org": false,
		"nas.home.arpa":       false,
		"notexample.org":      false,
	} {
		got, err := store.Shadowing(name)
		if err != nil {
			t.Fatal(err)
		}
		if (got != "") != want {
			t.Errorf("%s: shadow=%q, want shadowed=%v", name, got, want)
		}
	}
}
