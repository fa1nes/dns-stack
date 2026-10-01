package chnroute

import (
	"os"
	"testing"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

func TestPrefilteringForeignSpansByAPNICLosesNothingOnRealData(t *testing.T) {
	apnic, qqwry := os.Getenv("DNS_STACK_APNIC"), os.Getenv("DNS_STACK_QQWRY")
	if apnic == "" || qqwry == "" {
		t.Skip("设置 DNS_STACK_APNIC / DNS_STACK_QQWRY 指向真实快照后运行")
	}
	cnRanges, err := parseAPNIC(apnic)
	if err != nil {
		t.Fatal(err)
	}
	everything := func(lo, hi uint32) bool { return true }
	cnipCN, allForeign, err := loadCNIP(qqwry, everything)
	if err != nil {
		t.Fatal(err)
	}
	full := ipset.New(append(append([]ipset.Range{}, cnRanges...), cnipCN...))
	apnicSet := ipset.New(cnRanges)
	for _, f := range allForeign {
		if full.Overlaps(f.lo, f.hi) != apnicSet.Overlaps(f.lo, f.hi) {
			t.Fatalf("境外段 %08x-%08x 只和 qqwry 自己的 CN 段重叠——"+
				"遍历时按 APNIC 预筛会把它漏掉，反向排除的护栏就看不到这类 qqwry 数据异常", f.lo, f.hi)
		}
	}
}
