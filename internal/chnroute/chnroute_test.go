package chnroute

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

func rangeOf(t *testing.T, prefix string) ipset.Range {
	t.Helper()
	r, ok := ipset.PrefixRange(netip.MustParsePrefix(prefix))
	if !ok {
		t.Fatalf("%s 不是合法的 IPv4 前缀", prefix)
	}
	return r
}

func spanOf(t *testing.T, prefix, code, name string) foreignSpan {
	t.Helper()
	r := rangeOf(t, prefix)
	return foreignSpan{lo: r.Lo, hi: r.Hi, code: code, name: name}
}

func writeAPNIC(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "delegated-apnic-latest.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("写 APNIC 夹具失败: %v", err)
	}
	return path
}

func TestParseAPNICAcceptsOnlyAllocatedCNIPv4(t *testing.T) {
	path := writeAPNIC(t,
		"2|apnic|20260101|1|19830613|20260101|+1000",
		"apnic|CN|ipv4|1.0.1.0|256|20110414|allocated",
		"apnic|CN|ipv4|223.5.5.0|256|20110414|assigned",
		"apnic|CN|ipv4|8.8.8.0|256|20110414|reserved",
		"apnic|CN|ipv4|9.9.9.0|256|20110414|available",
		"apnic|HK|ipv4|203.198.0.0|256|20110414|allocated",
		"apnic|CN|ipv6|2001:db8::|32|20110414|allocated",
		"apnic|CN|ipv4|坏地址|256|20110414|allocated",
		"apnic|CN|ipv4|1.2.3.0|0|20110414|allocated",
		"字段不够",
	)
	ranges, err := parseAPNIC(path)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("只有 allocated/assigned 的 CN IPv4 该被收下，得到 %d 条: %v", len(ranges), ranges)
	}
	set := ipset.New(ranges)
	if !containsAddr(set, "1.0.1.5") || !containsAddr(set, "223.5.5.5") {
		t.Error("已分配的大陆段应当在集合里")
	}
	for _, outside := range []string{"8.8.8.8", "9.9.9.9", "203.198.0.1"} {
		if containsAddr(set, outside) {
			t.Errorf("%s 不该被收下", outside)
		}
	}
}

func TestOffshoreProbeGuardStopsHongKongLeakingIntoMainland(t *testing.T) {
	if err := guardOffshoreLeak([]ipset.Range{rangeOf(t, "223.5.5.0/24")}); err != nil {
		t.Errorf("纯大陆段不该触发护栏: %v", err)
	}
	err := guardOffshoreLeak([]ipset.Range{rangeOf(t, "203.198.0.0/16")})
	if err == nil {
		t.Fatal("港澳台探针落进大陆补充集合必须中止——否则整批香港地址会被判成直连")
	}
	if !strings.Contains(err.Error(), "203.198.0.1") {
		t.Errorf("错误消息要指出是哪个探针，得到: %v", err)
	}
}

func probeRanges() []ipset.Range {
	out := make([]ipset.Range, 0, len(mainlandProbes))
	for _, probe := range mainlandProbes {
		addr := netip.MustParseAddr(probe)
		out = append(out, ipset.Range{Lo: addrToUint(addr), Hi: addrToUint(addr)})
	}
	return out
}

func mainlandBase(t *testing.T) []ipset.Range {
	t.Helper()
	return append(probeRanges(), rangeOf(t, "36.0.0.0/8"))
}

func TestReverseExclusionRemovesForeignSegments(t *testing.T) {
	base := append(mainlandBase(t), rangeOf(t, "23.56.0.0/16"))
	cnSet := ipset.New(base)
	foreign := []foreignSpan{spanOf(t, "23.56.0.0/16", "US", "美国")}

	plan := planReverseExclusion(cnSet, foreign, 99)
	if plan.rejected != "" {
		t.Fatalf("这轮不该被护栏拦下: %s", plan.rejected)
	}
	if containsAddr(plan.kept, "23.56.25.51") {
		t.Error("qqwry 判为境外的段应当从直连集合里剔掉")
	}
	for _, probe := range mainlandProbes {
		if !containsAddr(plan.kept, probe) {
			t.Errorf("已知国内地址 %s 必须保留", probe)
		}
	}
	if plan.addrs != 65536 {
		t.Errorf("剔除地址数应为 65536，得到 %d", plan.addrs)
	}
	if len(plan.dropped) == 0 || plan.dropped[0].code != "US" {
		t.Errorf("剔除清单要带上国别归因，得到 %+v", plan.dropped)
	}
}

func TestReverseExclusionRefusesWhenDropRatioIsAbsurd(t *testing.T) {
	cnSet := ipset.New(append(probeRanges(), rangeOf(t, "23.56.0.0/16")))
	foreign := []foreignSpan{spanOf(t, "23.56.0.0/16", "US", "美国")}

	plan := planReverseExclusion(cnSet, foreign, 5)
	if plan.rejected == "" {
		t.Fatal("剔除比例超过上限必须整轮放弃——归属库整体漂移时不能把直连集合削掉一大半")
	}
	if !strings.Contains(plan.rejected, "上限") {
		t.Errorf("拒绝原因要说明是比例护栏，得到: %s", plan.rejected)
	}
}

func TestReverseExclusionRefusesWhenItWouldDropKnownMainlandAddresses(t *testing.T) {
	base := append(mainlandBase(t), rangeOf(t, "23.56.0.0/12"))
	cnSet := ipset.New(base)
	foreign := []foreignSpan{
		spanOf(t, "223.6.6.6/32", "US", "美国"),
		spanOf(t, "23.56.0.0/12", "US", "美国"),
	}

	plan := planReverseExclusion(cnSet, foreign, 99.9)
	if plan.rejected == "" {
		t.Fatal("剔除会命中已知国内地址时必须整轮放弃")
	}
	if strings.Contains(plan.rejected, "上限") {
		t.Fatalf("这轮该被大陆探针拦下而不是比例护栏，说明夹具的分母不对: %s", plan.rejected)
	}
	if !strings.Contains(plan.rejected, "223.6.6.6") {
		t.Errorf("拒绝原因要指出被误伤的地址，得到: %s", plan.rejected)
	}
}

func TestRunEmitsReservedRangesAndStats(t *testing.T) {
	apnic := writeAPNIC(t,
		"apnic|CN|ipv4|1.0.1.0|256|20110414|allocated",
		"apnic|CN|ipv4|223.5.5.0|256|20110414|allocated",
	)
	dir := t.TempDir()
	out := filepath.Join(dir, "direct4.txt")
	stats := filepath.Join(dir, "stats.txt")
	var log bytes.Buffer

	res, err := Run(Options{APNICPath: apnic, OutPath: out, StatsPath: stats, Out: &log})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.CNAddresses != 512 {
		t.Errorf("大陆地址数应为 512，得到 %d", res.CNAddresses)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("读输出失败: %v", err)
	}
	text := string(body)
	for _, want := range []string{"1.0.1.0/24", "223.5.5.0/24", "10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3"} {
		if !strings.Contains(text, want) {
			t.Errorf("输出里应当有 %s（保留网段也要写进去，nft 才不会把它们送出隧道；224/4 与 240/4 相邻，合并成 224/3 是对的）:\n%s", want, text)
		}
	}
	statsText, err := os.ReadFile(stats)
	if err != nil {
		t.Fatalf("读 stats 失败: %v", err)
	}
	if !strings.Contains(string(statsText), "CN_ADDRESSES=512") {
		t.Errorf("stats 内容不对: %s", statsText)
	}
}

func TestRunRefusesAnEmptyAPNICSnapshot(t *testing.T) {
	apnic := writeAPNIC(t, "apnic|HK|ipv4|203.198.0.0|256|20110414|allocated")
	var log bytes.Buffer
	_, err := Run(Options{APNICPath: apnic, OutPath: filepath.Join(t.TempDir(), "out.txt"), Out: &log})
	if err == nil {
		t.Fatal("APNIC 里没有 CN 段时必须失败，绝不能写出一份空的 direct4")
	}
}

func TestGroupDigits(t *testing.T) {
	cases := map[uint64]string{0: "0", 12: "12", 512: "512", 1024: "1,024", 344130560: "344,130,560"}
	for value, want := range cases {
		if got := groupDigits(value); got != want {
			t.Errorf("groupDigits(%d) = %q，期望 %q", value, got, want)
		}
	}
}
