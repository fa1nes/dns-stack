package cdnhit

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestTheSecondSubnetDoesNotBlameECSForTheFirstSubnetsGlobalAnswer(t *testing.T) {
	var mu sync.Mutex
	cachedGlobal := map[string]bool{}
	resolve := func(_ context.Context, name string, _ netip.Prefix) (Answer, error) {
		mu.Lock()
		defer mu.Unlock()
		out := Answer{Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}
		if cachedGlobal[name] {
			return out, nil
		}
		cachedGlobal[name] = true
		out.Echoed, out.Scope = true, 0
		return out, nil
	}
	flush := func(_ context.Context, name string) error {
		mu.Lock()
		defer mu.Unlock()
		delete(cachedGlobal, name)
		return nil
	}
	reports, err := RunAll(context.Background(), Options{
		Set: testSet(t), Mainland: mainlandSet(t, "220.181.10.0/24"), Resolve: resolve, Flush: flush,
		Probes: []Probe{{"a.big.example", "全球 anycast"}},
		Now:    func() time.Time { return time.Unix(1_700_000_100, 0) },
	}, []string{BeijingTelecom, BeijingUnicom, BeijingMobile})
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range reports {
		if got := report.Probes[0].Verdict; got != VerdictNoSteering {
			t.Errorf("%s 判成 %s——第一个子网拿到 scope=0 后 unbound 把答案缓存成全局，后两个子网命中缓存没有回显，"+
				"这是「不分地区」，不是「子网没送到」", report.Subnet, got)
		}
	}
}
