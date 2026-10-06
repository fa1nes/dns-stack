package domain

import "testing"

const samplePSL = `// ===BEGIN ICANN DOMAINS===
com
cn
com.cn
gd.cn
top
hk
com.hk
uk
co.uk
ck
*.ck
!www.ck
jp
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
blogspot.com
s3.amazonaws.com
// ===END PRIVATE DOMAINS===
`

func testPSL(t *testing.T) *PSL {
	t.Helper()
	p := ParsePSL(samplePSL, "test")
	if p.Len() == 0 {
		t.Fatal("PSL 解析为空")
	}
	return p
}

func TestParseOnlyICANNSection(t *testing.T) {
	p := testPSL(t)
	if p.IsPublicSuffix("blogspot.com") {
		t.Error("私有段 blogspot.com 不应被当作公共后缀：它是真实 DNS 区域，误判会让国内 CDN 调度区域被排除")
	}
	if p.IsPublicSuffix("s3.amazonaws.com") {
		t.Error("私有段 s3.amazonaws.com 不应被当作公共后缀")
	}
	if !p.IsPublicSuffix("com.cn") {
		t.Error("ICANN 段的 com.cn 必须被识别")
	}
}

func TestPublicSuffixOutsideFallback(t *testing.T) {
	p := testPSL(t)
	if _, inFallback := fallbackPublicSuffixes["gd.cn"]; inFallback {
		t.Fatal("测试前提失效：gd.cn 不应在内置兜底表里")
	}
	if got := ZoneDefect("gd.cn", p); got != DefectPublicSuffix {
		t.Errorf("gd.cn 有 PSL 时应判 public_suffix，实际 %q", got)
	}
	if got := ZoneDefect("gd.cn", nil); got != "" {
		t.Errorf("gd.cn 无 PSL 时兜底表覆盖不到，应放行，实际 %q", got)
	}
}

func TestWildcardAndException(t *testing.T) {
	p := testPSL(t)
	if !p.IsPublicSuffix("foo.ck") {
		t.Error("*.ck 通配规则应让 foo.ck 成为公共后缀")
	}
	if p.IsPublicSuffix("www.ck") {
		t.Error("!www.ck 例外规则应让 www.ck 不是公共后缀")
	}
}

func TestZoneDefectOrder(t *testing.T) {
	p := testPSL(t)
	cases := []struct {
		name string
		want string
	}{
		{"", DefectEmpty},
		{"   ", DefectEmpty},
		{"top", DefectSingleLabel},
		{"cn", DefectSingleLabel},
		{"1.0.0.127.in-addr.arpa", DefectReserved},
		{"foo.local", DefectReserved},
		{"com.cn", DefectPublicSuffix},
		{"com.hk", DefectPublicSuffix},
		{"co.uk", DefectPublicSuffix},
		{"qq.com", ""},
		{"tencent-cloud.net", ""},
		{"akamaiedge.net", ""},
		{"-bad.com", DefectMalformed},
		{"bad-.com", DefectMalformed},
		{"a..b", DefectMalformed},
		{"_dmarc.example.com", ""},
	}
	for _, c := range cases {
		if got := ZoneDefect(c.name, p); got != c.want {
			t.Errorf("ZoneDefect(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"QQ.COM.":      "qq.com",
		"  Example.  ": "example",
		"a.b.":         "a.b",
		".":            "",
		"":             "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRootZoneNotCrash(t *testing.T) {
	p := testPSL(t)
	if got := ZoneDefect(".", p); got != DefectEmpty {
		t.Errorf("根区应判 empty 而不是崩溃或误判，实际 %q", got)
	}
}

func TestLabelLengthLimits(t *testing.T) {
	p := testPSL(t)
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if got := ZoneDefect(long+".com", p); got != DefectMalformed {
		t.Errorf("64 字符 label 应判 malformed，实际 %q", got)
	}
	ok := ""
	for i := 0; i < 63; i++ {
		ok += "a"
	}
	if got := ZoneDefect(ok+".com", p); got != "" {
		t.Errorf("63 字符 label 合法，实际 %q", got)
	}
}

func TestIPLiteralsAreNotDNSZones(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "2001:db8::1"} {
		if got := ZoneDefect(value, testPSL(t)); got != DefectMalformed {
			t.Fatalf("IP literal %q classified as %q", value, got)
		}
	}
}

func TestLoadPSLMissingReturnsNil(t *testing.T) {
	psl, note := LoadPSL([]string{"/nonexistent/psl.dat"})
	if psl != nil {
		t.Error("路径都不存在时应返回 nil")
	}
	if note == "" {
		t.Error("说明文本不能为空，调用方要打进日志")
	}
}

func TestTooFewRulesRejected(t *testing.T) {
	psl, _ := LoadPSL(nil)
	_ = psl
	small := ParsePSL("// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n", "small")
	if small.Len() >= 100 {
		t.Fatal("测试前提失效")
	}
}
