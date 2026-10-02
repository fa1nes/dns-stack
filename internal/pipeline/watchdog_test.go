package pipeline

import (
	"fmt"
	"strings"
	"testing"
)

func watchdogForTest() WatchdogConfig {
	return WatchdogConfig{
		Config:     Config{NFTTable: "dns_route", DirectSet: "direct4", AuthoritySet: "cn_authority", TunnelIf: "wg0"},
		FWMark:     DefaultFWMark,
		MinEntries: DefaultMinSetEntries,
		AuthRatio:  DefaultAuthorityRatio,
	}
}

func nftElements(n int, ranges bool) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		base := fmt.Sprintf("%d.%d.%d.0", 1+i/65536, (i/256)%256, i%256)
		if ranges && i%3 == 0 {
			parts = append(parts, base+"-"+fmt.Sprintf("%d.%d.%d.255", 1+i/65536, (i/256)%256, i%256))
			continue
		}
		parts = append(parts, base+"/24")
	}
	var b strings.Builder
	for start := 0; start < len(parts); start += 4 {
		end := min(start+4, len(parts))
		if start == 0 {
			b.WriteString("\t\telements = { ")
		} else {
			b.WriteString("\t\t\t     ")
		}
		b.WriteString(strings.Join(parts[start:end], ", "))
		if end == len(parts) {
			b.WriteString(" }\n")
		} else {
			b.WriteString(",\n")
		}
	}
	return b.String()
}

func productionShapedTable(direct, authority int) string {
	return "table inet dns_route {\n" +
		"\tset direct4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n" + nftElements(direct, true) + "\t}\n\n" +
		"\tset cn_authority {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n" + nftElements(authority, false) + "\t}\n\n" +
		"\tset tunnel_endpoints {\n\t\ttype ipv4_addr\n\t\telements = { 203.0.113.7, 203.0.113.8 }\n\t}\n\n" +
		"\tchain output {\n\t\ttype route hook output priority mangle; policy accept;\n" +
		"\t\tmeta skuid 102 ip daddr != @direct4 ip daddr != @cn_authority ip daddr != @tunnel_endpoints counter packets 3443204 bytes 1526876745 meta mark set 0x000001d5\n\t}\n\n" +
		"\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n" +
		"\t\toifname \"wg0\" meta mark 0x000001d5 counter packets 3355882 bytes 282090211 masquerade\n\t}\n}\n"
}

func withACLChain(table string) string {
	return strings.TrimSuffix(table, "}\n") +
		"\n\tchain dns_acl {\n\t\ttype filter hook input priority filter; policy accept;\n" +
		"\t\tiif \"lo\" accept\n\t\tmeta l4proto { tcp, udp } th dport { 443, 853 } counter packets 0 bytes 0 drop\n\t}\n}\n"
}

const productionIPRules = "0:\tfrom all lookup local\n100:\tfrom 10.100.0.2 lookup 100\n101:\tfrom all fwmark 0x1d5 lookup 100\n102:\tfrom all fwmark 0x1d5 prohibit\n32766:\tfrom all lookup main\n"

func TestNFTTableBlocksCountEachSetOnItsOwn(t *testing.T) {
	blocks := nftTableBlocks(productionShapedTable(4256, 120))
	for name, want := range map[string]int{"set direct4": 4256, "set cn_authority": 120, "set tunnel_endpoints": 2} {
		if got := countNFTElements(blocks[name]); got != want {
			t.Errorf("%s 数出 %d 个元素，期望 %d——看门狗现在一次列出整张表再切块，"+
				"区间元素只能算一个，别的集合里的地址也不能串进来", name, got, want)
		}
	}
	for _, name := range []string{"chain output", "chain postrouting"} {
		if !strings.Contains(blocks[name], "0x000001d5") {
			t.Errorf("%s 块没切出来或切错了：%q", name, blocks[name])
		}
	}
}

func TestWatchdogJudgesOneSnapshotTheWayItJudgedSixCommands(t *testing.T) {
	w := watchdogForTest()
	for _, tc := range []struct {
		name  string
		snap  routingSnapshot
		wants []string
	}{
		{"健康", routingSnapshot{productionShapedTable(4256, 120), productionIPRules, 150, false}, nil},
		{"整张表被清空", routingSnapshot{"", productionIPRules, 150, false},
			[]string{"分流链缺失", "NAT 源地址改写链缺失", "大陆 IP 集合过小", "墙内权威集合过小"}},
		{"大陆集合只剩一点", routingSnapshot{productionShapedTable(12, 120), productionIPRules, 150, false},
			[]string{"大陆 IP 集合过小"}},
		{"权威集合不到基线的四成", routingSnapshot{productionShapedTable(4256, 50), productionIPRules, 150, false},
			[]string{"墙内权威集合过小"}},
		{"基线太小时不判权威集合", routingSnapshot{productionShapedTable(4256, 0), productionIPRules, 10, false}, nil},
		{"策略路由规则丢了", routingSnapshot{productionShapedTable(4256, 120), "0:\tfrom all lookup local\n", 150, false},
			[]string{"fwmark 策略路由规则缺失"}},
		{"配了访问控制但链不在", routingSnapshot{productionShapedTable(4256, 120), productionIPRules, 150, true},
			[]string{"访问控制链缺失"}},
		{"访问控制链在", routingSnapshot{withACLChain(productionShapedTable(4256, 120)), productionIPRules, 150, true}, nil},
		{"没配访问控制时不看这条链", routingSnapshot{productionShapedTable(4256, 120), productionIPRules, 150, false}, nil},
	} {
		got := w.problems(tc.snap)
		if len(got) != len(tc.wants) {
			t.Errorf("%s: 问题 = %q，期望 %d 条 %q", tc.name, got, len(tc.wants), tc.wants)
			continue
		}
		for i, want := range tc.wants {
			if !strings.Contains(got[i], want) {
				t.Errorf("%s: 第 %d 条 = %q，期望包含 %q", tc.name, i, got[i], want)
			}
		}
	}
}
