package panel

import (
	"strings"
	"testing"
)

func TestRoutingReasonNeverClaimsWhatItDidNotCheck(t *testing.T) {
	cases := []struct {
		name       string
		zone       string
		authorites int
		viaTable   int
		domestic   bool
		wantAny    []string
		wantNone   []string
	}{
		{
			name: "认不出注册域", zone: "", authorites: 0, domestic: false,
			wantAny:  []string{"没有查过任何权威"},
			wantNone: []string{"都不在 direct4"},
		},
		{
			name: "权威没问到", zone: "example.com", authorites: 0, domestic: false,
			wantAny:  []string{"没问到", "不代表"},
			wantNone: []string{"都不在 direct4"},
		},
		{
			name: "查过了确实没有", zone: "example.com", authorites: 4, domestic: false,
			wantAny: []string{"查过", "都不在 direct4"},
		},
		{
			name: "只在国内权威表里", zone: "example.com", authorites: 4, viaTable: 2, domestic: false,
			wantAny:  []string{"国内权威表", "可能已经过期", "不作为"},
			wantNone: []string{"都不在 direct4 或国内权威表里"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := routingReason(c.zone, c.authorites, c.viaTable, c.domestic)
			for _, want := range c.wantAny {
				if !strings.Contains(got, want) {
					t.Errorf("reason = %q，应当含 %q", got, want)
				}
			}
			for _, none := range c.wantNone {
				if strings.Contains(got, none) {
					t.Errorf("reason = %q，不该断言 %q——这一次根本没查过权威，"+
						"「查不到」和「查了没有」是两回事", got, none)
				}
			}
		})
	}
	if got := routingReason("example.com", 4, 0, true); got != "" {
		t.Errorf("找到了大陆权威时应由 direct 分支自己写 reason，这里返回 %q", got)
	}
}
