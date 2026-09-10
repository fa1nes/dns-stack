package anycast

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seed(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写 %s 失败: %v", path, err)
	}
}

func TestDataLinesSkipsCommentsAndTakesFirstField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	seed(t, path, "# generated-at 1\n\n1.1.1.1 备注\n  2.2.2.2  \n#尾注\n")
	got := dataLines(path)
	want := []string{"1.1.1.1", "2.2.2.2"}
	if len(got) != len(want) {
		t.Fatalf("得到 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("得到 %v，期望 %v", got, want)
		}
	}
	if dataLines(filepath.Join(dir, "nope.txt")) != nil {
		t.Error("文件不存在应当返回 nil")
	}
}

func TestLoadDirect4ReturnsNilWhenNothingUsable(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "direct4.txt")
	seed(t, good, "1.0.1.0/24\n2001:db8::/32\n垃圾\n")
	set := loadDirect4(good)
	if set == nil {
		t.Fatal("有可用 IPv4 网段时不该返回 nil")
	}
	if !set.Contains(netip.MustParseAddr("1.0.1.5")) {
		t.Error("网段内地址应当命中")
	}
	if set.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("网段外地址不该命中")
	}

	empty := filepath.Join(dir, "empty.txt")
	seed(t, empty, "# 只有注释\n2001:db8::/32\n")
	if loadDirect4(empty) != nil {
		t.Error("没有 IPv4 网段时必须返回 nil，让调用方走 fail-open 而不是拿空集合当真")
	}
}

func TestServesCNZoneMatchesExactAndSuffix(t *testing.T) {
	exact := map[string]bool{"qq.com": true}
	suffixes := []string{"akamaiedge.net"}

	if got := servesCNZone([]string{"other.example", "qq.com"}, exact, suffixes); got != "qq.com" {
		t.Errorf("精确命中失败，得到 %q", got)
	}
	if got := servesCNZone([]string{"a.b.akamaiedge.net"}, exact, suffixes); got != "a.b.akamaiedge.net" {
		t.Errorf("人工 CDN 区域按后缀命中失败，得到 %q", got)
	}
	if got := servesCNZone([]string{"akamaiedge.net"}, exact, suffixes); got != "akamaiedge.net" {
		t.Errorf("后缀本身也该命中，得到 %q", got)
	}
	if got := servesCNZone([]string{"notakamaiedge.net"}, exact, suffixes); got != "" {
		t.Errorf("后缀匹配必须按标签边界，notakamaiedge.net 不该命中，得到 %q", got)
	}
	if got := servesCNZone([]string{"unrelated.example"}, exact, suffixes); got != "" {
		t.Errorf("无关区域不该命中，得到 %q", got)
	}
}

func TestSharedDNSASTableCoversTheProvidersWeCareAbout(t *testing.T) {
	for asn, want := range map[int]string{
		16509: "AWS", 20940: "Akamai", 13335: "Cloudflare", 30060: "Verisign",
	} {
		if got := sharedDNSAS[asn]; got != want {
			t.Errorf("AS%d 应当标为 %s，得到 %q", asn, want, got)
		}
	}
	if _, shared := sharedDNSAS[4134]; shared {
		t.Error("中国电信 AS4134 不该被当成共享 DNS 托管商")
	}
}

func TestMissingGeoIPFailsOpenAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "shared-anycast.txt")
	report, err := Run(context.Background(), Config{StateDir: dir, OutPath: out})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if report.Note != "geoip-unavailable" {
		t.Errorf("归属库不可用必须写明原因，得到 %q", report.Note)
	}
	if len(report.Shared) != 0 {
		t.Error("护栏自身缺席时不能产出任何排除项")
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("读输出失败: %v", err)
	}
	if !strings.Contains(string(body), "# note geoip-unavailable") {
		t.Errorf("空清单必须带上原因注释，否则下游看到的只是「清单为空」:\n%s", body)
	}
}

func TestDryRunNeverTouchesTheExistingList(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "shared-anycast.txt")
	seed(t, out, "# generated-at 1\n1.2.3.4\n")

	if _, err := Run(context.Background(), Config{StateDir: dir, OutPath: out, DryRun: true}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("读输出失败: %v", err)
	}
	if !strings.Contains(string(body), "1.2.3.4") {
		t.Errorf("--dry-run 不能改动现有清单:\n%s", body)
	}
}

func TestWriteIsAtomicAndCarriesCount(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "shared-anycast.txt")
	if err := write(out, []Finding{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}}, ""); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("读输出失败: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "# count 2") {
		t.Errorf("表头要带条目数，供下游做骤降判断:\n%s", text)
	}
	if !strings.Contains(text, "1.1.1.1\n2.2.2.2\n") {
		t.Errorf("正文不对:\n%s", text)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件必须被 rename 掉，不能留在磁盘上")
	}
}
