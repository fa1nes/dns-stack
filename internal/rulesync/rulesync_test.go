package rulesync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写 %s 失败: %v", path, err)
	}
	return path
}

func TestValidDomainRejectsEverythingThatIsNotADNSName(t *testing.T) {
	valid := []string{
		"qq.com", "a.b.c.example.com", "xn--fiqs8s", "0-a.example",
		strings.Repeat("a", 63) + ".com",
	}
	for _, name := range valid {
		if !ValidDomain(name) {
			t.Errorf("%q 应当被接受", name)
		}
	}
	invalid := []string{
		"", "-lead.com", "trail-.com", "under_score.com", "UPPER.com",
		"a..b.com", "a.b.", ".a.com", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com",
	}
	for _, name := range invalid {
		if ValidDomain(name) {
			t.Errorf("%q 应当被拒绝", name)
		}
	}
}

func TestCheckRuleSetsRejectsExactIntersection(t *testing.T) {
	err := CheckRuleSets([]string{"qq.com", "blocked.example"}, []string{"blocked.example"})
	if err == nil {
		t.Fatal("同一域名同时出现在 CN 与 GFW 必须拒绝")
	}
	if !strings.Contains(err.Error(), "blocked.example") {
		t.Errorf("错误消息要指出是哪一条，得到: %v", err)
	}
}

func TestCheckRuleSetsRejectsCNChildUnderGFWParent(t *testing.T) {
	err := CheckRuleSets([]string{"cdn.blocked.example"}, []string{"blocked.example"})
	if err == nil {
		t.Fatal("CN 子域会被更宽泛的 GFW 父规则抢先命中，必须拒绝——那条 CN 规则永远不生效")
	}
	if !strings.Contains(err.Error(), "cdn.blocked.example") {
		t.Errorf("错误消息要指出具体的父子对，得到: %v", err)
	}
}

func TestCheckRuleSetsAllowsSpecificGFWUnderBroadCN(t *testing.T) {
	if err := CheckRuleSets([]string{"example.com"}, []string{"blocked.example.com"}); err != nil {
		t.Errorf("更具体的 GFW 规则覆盖宽泛的 CN 规则是允许的: %v", err)
	}
}

func TestCheckRuleSetsIgnoresBlankLines(t *testing.T) {
	if err := CheckRuleSets([]string{"", "  ", "qq.com"}, []string{"", "other.example"}); err != nil {
		t.Errorf("空行不该被当成规则: %v", err)
	}
}

func TestCheckRuleSetsHandlesNoOverlap(t *testing.T) {
	if err := CheckRuleSets([]string{"qq.com", "taobao.com"}, []string{"twitter.com"}); err != nil {
		t.Errorf("不相交的两份规则应当通过: %v", err)
	}
}

func TestCheckDisjointCatchesOverlappingCIDRs(t *testing.T) {
	dir := t.TempDir()
	cn := writeFile(t, dir, "cn.txt", "1.0.0.0/8\n223.0.0.0/8\n")
	clean := writeFile(t, dir, "clean.txt", "127.0.0.0/8\n")
	dirty := writeFile(t, dir, "dirty.txt", "223.5.5.0/24\n")

	if err := CheckDisjoint(cn, clean); err != nil {
		t.Errorf("不相交应当通过: %v", err)
	}
	err := CheckDisjoint(cn, dirty)
	if err == nil {
		t.Fatal("CN 与污染网段重叠必须拒绝：两者语义相反")
	}
	if !strings.Contains(err.Error(), "223") {
		t.Errorf("错误消息要指出相交的那一对，得到: %v", err)
	}
}

func TestCheckDomainsReportsTheOffendingLines(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.txt", "qq.com\ntaobao.com\n")
	if err := CheckDomains(good); err != nil {
		t.Errorf("合法域名文件应当通过: %v", err)
	}
	bad := writeFile(t, dir, "bad.txt", "qq.com\n-nope.com\nUPPER.com\n")
	err := CheckDomains(bad)
	if err == nil {
		t.Fatal("含非法域名的文件必须拒绝")
	}
	if !strings.Contains(err.Error(), "-nope.com") {
		t.Errorf("错误消息要列出非法条目，得到: %v", err)
	}
}

func TestCleanCIDRFileCollapsesAndSorts(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "src.txt", "# 注释\n10.0.0.128/25\n10.0.0.0/25\n\n2001:db8::/33\n2001:db8:8000::/33\n")
	dst := filepath.Join(dir, "dst.txt")
	if err := CleanCIDRFile(src, dst); err != nil {
		t.Fatalf("清洗失败: %v", err)
	}
	got := strings.Fields(readAll(t, dst))
	want := []string{"10.0.0.0/24", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("相邻网段应当合并，得到 %v 期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("得到 %v 期望 %v", got, want)
		}
	}
}

func TestMergePollutedCombinesAllSources(t *testing.T) {
	dir := t.TempDir()
	remote := writeFile(t, dir, "remote.txt", "127.0.0.0/9\n")
	localIPs := writeFile(t, dir, "ips.txt", "10.0.0.1\n垃圾行\n")
	localCIDRs := writeFile(t, dir, "local.txt", "127.128.0.0/9\n")
	out := filepath.Join(dir, "out.txt")

	if err := MergePolluted(remote, localIPs, localCIDRs, out); err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	body := readAll(t, out)
	if !strings.Contains(body, "127.0.0.0/8") {
		t.Errorf("远端与本地的两个 /9 应当合并成 /8，得到:\n%s", body)
	}
	if !strings.Contains(body, "10.0.0.1/32") {
		t.Errorf("裸地址应当作为 /32 并入，得到:\n%s", body)
	}
}

func TestMergePollutedToleratesMissingSources(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	local := writeFile(t, dir, "local.txt", "127.0.0.0/8\n")
	if err := MergePolluted(filepath.Join(dir, "nope.txt"), "", local, out); err != nil {
		t.Errorf("缺失的来源应当跳过而不是让整轮失败: %v", err)
	}
	if !strings.Contains(readAll(t, out), "127.0.0.0/8") {
		t.Error("现有来源仍应写入")
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", path, err)
	}
	return string(data)
}
