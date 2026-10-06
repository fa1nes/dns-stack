package cdnrules

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func syntheticRuleset(tb testing.TB, prefixes int) []byte {
	tb.Helper()
	providers := make([]Provider, 0, 20)
	perProvider := prefixes / 20
	for i := 0; i < 20; i++ {
		p := Provider{
			ID:      fmt.Sprintf("p%02d", i),
			Name:    fmt.Sprintf("Provider %02d", i),
			Domains: []string{fmt.Sprintf("p%02d.example", i)},
		}
		for n := 0; n < perProvider; n++ {
			addr := netip.AddrFrom4([4]byte{byte(1 + i*2), byte(n >> 8), byte(n), 0})
			prefix := netip.PrefixFrom(addr, 24)
			if n%4 == 0 {
				p.Mainland = append(p.Mainland, prefix)
			} else {
				p.Offshore = append(p.Offshore, prefix)
			}
		}
		providers = append(providers, p)
	}
	var buf bytes.Buffer
	if err := Render(&buf, time.Unix(1_700_000_000, 0), providers); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

func BenchmarkParse(b *testing.B) {
	for _, size := range []int{8400, 16000} {
		body := syntheticRuleset(b, size)
		b.Run(fmt.Sprintf("prefixes=%d/bytes=%d", size, len(body)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				set, err := Parse(bytes.NewReader(body))
				if err != nil {
					b.Fatal(err)
				}
				if set.PrefixCount() == 0 {
					b.Fatal("解析出空规则集，基准测的不是真实工作量")
				}
			}
		})
	}
}

func BenchmarkOwnerLookup(b *testing.B) {
	set, err := Parse(bytes.NewReader(syntheticRuleset(b, 16000)))
	if err != nil {
		b.Fatal(err)
	}
	probe := netip.MustParseAddr("21.1.5.7")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Owner(probe)
	}
}

func BenchmarkMainlandRoots(b *testing.B) {
	set, err := Parse(bytes.NewReader(syntheticRuleset(b, 16000)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(set.MainlandRoots()) == 0 {
			b.Fatal("没有大陆根域，基准测的不是真实工作量")
		}
	}
}
