package ecszone

import (
	"strings"
	"testing"
)

func TestPickFanoutKeepsBusyCarrierZonesWithTheirMostUsedSubnet(t *testing.T) {
	byZone := map[string]*ZoneTraffic{}
	AddTraffic(byZone, "广东电信", "113.64.10.0/24", 900)
	AddTraffic(byZone, "广东电信", "113.64.99.0/24", 50)
	AddTraffic(byZone, "广东移动", "120.230.5.0/24", 300)
	AddTraffic(byZone, "北京联通", "202.106.0.0/24", 3)
	AddTraffic(byZone, "", "1.2.3.0/24", 5000)
	AddTraffic(byZone, "广东电信", "240e::/48", 5000)

	picked := PickFanout(byZone, 20, 6)
	if len(picked) != 2 {
		t.Fatalf("picked %v, want the two busy Guangdong zones", picked)
	}
	text := RenderFanout(picked, 14)
	for _, line := range []string{"广东电信,113.64.10.0/24\n", "广东移动,120.230.5.0/24\n"} {
		if !strings.Contains(text, line) {
			t.Fatalf("rendered fanout lacks %q:\n%s", line, text)
		}
	}
	if byZone["广东电信"].Queries != 950 {
		t.Fatalf("IPv6 traffic leaked into the zone count: %d", byZone["广东电信"].Queries)
	}
}

func TestPickFanoutNeedsAtLeastTwoZones(t *testing.T) {
	byZone := map[string]*ZoneTraffic{}
	AddTraffic(byZone, "广东电信", "113.64.10.0/24", 900)
	if picked := PickFanout(byZone, 20, 6); picked != nil {
		t.Fatalf("a single zone has nobody to fan out to, got %v", picked)
	}
}
