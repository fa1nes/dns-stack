package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func routingFixture() RoutingConfig {
	cfg := Config{
		StateDir: "/var/lib/dns-stack", TunnelIf: "wg0", TunnelAddr: "10.100.0.2",
		NFTTable: "dns_route", DirectSet: "direct4", AuthoritySet: "cn_authority",
		values: map[string]string{},
	}
	return LoadRoutingConfig(cfg)
}

func TestChainScriptKeepsEveryGuardFromTheShell(t *testing.T) {
	rc := routingFixture()
	script := rc.renderChainScript("111", []string{"203.0.113.7"}, []string{"1.2.3.0/24"})
	for _, want := range []string{
		"add chain inet dns_route output { type route hook output priority mangle; policy accept; }",
		"meta skuid 111",
		"ip daddr != @direct4",
		"ip daddr != @cn_authority",
		"ip daddr != @tunnel_endpoints",
		"meta mark set 0x1d5",
		"add chain inet dns_route postrouting { type nat hook postrouting priority srcnat; policy accept; }",
		`oifname "wg0" meta mark 0x1d5 counter masquerade`,
		"flush chain inet dns_route output",
		"flush chain inet dns_route postrouting",
		"add element inet dns_route tunnel_endpoints { 203.0.113.7 }",
		"add element inet dns_route cn_authority { 1.2.3.0/24 }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("分流链脚本缺少 %q\n---\n%s", want, script)
		}
	}
}

func TestChainScriptNeverFlushesTheDirectSet(t *testing.T) {
	rc := routingFixture()
	script := rc.renderChainScript("111", nil, nil)
	if strings.Contains(script, "flush set inet dns_route direct4") {
		t.Fatal("分流链脚本不该 flush direct4——那是 routing-data 维护的大陆网段，清空会把国内查询全导进隧道")
	}
	if !strings.Contains(script, "flush set inet dns_route tunnel_endpoints") {
		t.Error("端点集合每轮必须重建，否则旧端点会一直被豁免")
	}
	if !strings.Contains(script, "flush set inet dns_route cn_authority") {
		t.Error("墙内权威集合每轮必须重建")
	}
}

func TestChainScriptChunksLargeAuthoritySets(t *testing.T) {
	rc := routingFixture()
	entries := make([]string, nftChunk*2+5)
	for i := range entries {
		entries[i] = "10.0.0.1"
	}
	script := rc.renderChainScript("111", nil, entries)
	if got := strings.Count(script, "add element inet dns_route cn_authority"); got != 3 {
		t.Fatalf("%d 条应切成 3 批，实得 %d 批", len(entries), got)
	}
}

func TestWireGuardConfGuardRefusesUncontainedDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	rc := routingFixture()

	rc.WGConf = filepath.Join(dir, "missing.conf")
	if err := rc.guardWireGuardConf(); err != nil {
		t.Errorf("配置文件不存在时不该拦截: %v", err)
	}

	rc.WGConf = filepath.Join(dir, "bad.conf")
	os.WriteFile(rc.WGConf, []byte("[Interface]\nAddress = 10.100.0.2/24\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\n"), 0o600)
	if err := rc.guardWireGuardConf(); err == nil {
		t.Error("AllowedIPs = 0.0.0.0/0 且缺少 Table = off 时必须拒绝，否则重启后整机流量进隧道")
	}

	rc.WGConf = filepath.Join(dir, "good.conf")
	os.WriteFile(rc.WGConf, []byte("[Interface]\nTable = off\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\n"), 0o600)
	if err := rc.guardWireGuardConf(); err != nil {
		t.Errorf("有 Table = off 时应放行: %v", err)
	}

	rc.WGConf = filepath.Join(dir, "narrow.conf")
	os.WriteFile(rc.WGConf, []byte("[Peer]\nAllowedIPs = 10.100.0.3/32\n"), 0o600)
	if err := rc.guardWireGuardConf(); err != nil {
		t.Errorf("窄 allowed-ips 不需要 Table = off: %v", err)
	}
}

func TestRoutingConfigDefaultsMatchTheShell(t *testing.T) {
	rc := routingFixture()
	if rc.RouteTable != "100" || rc.FWMark != "0x1d5" || rc.UnboundUser != "unbound" {
		t.Errorf("默认值漂移: table=%s mark=%s user=%s", rc.RouteTable, rc.FWMark, rc.UnboundUser)
	}
	if rc.FailMode != "closed" {
		t.Errorf("隧道故障策略默认必须是 closed（不回落直连），得到 %s", rc.FailMode)
	}
	if rc.MinEntries != 1000 {
		t.Errorf("集合规模下限默认必须是 1000，得到 %d", rc.MinEntries)
	}
	if rc.WGConf != "/etc/wireguard/wg0.conf" {
		t.Errorf("WG 配置路径应随 TUNNEL_IF 变化，得到 %s", rc.WGConf)
	}
	if rc.EndpointSet != "tunnel_endpoints" {
		t.Errorf("端点集合名漂移: %s", rc.EndpointSet)
	}
}

func TestSetSemanticsAssertsPrivateRangesAreAbsent(t *testing.T) {
	body, err := os.ReadFile("routing.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	start := strings.Index(text, "func (rc RoutingConfig) verifySetSemantics")
	if start < 0 {
		t.Fatal("找不到 verifySetSemantics")
	}
	end := strings.Index(text[start:], "\nfunc ")
	body2 := text[start : start+end]
	if strings.Contains(body2, "if !rc.inSet(ctx, rc.Config.TunnelAddr)") {
		t.Fatal("隧道地址是私有段，direct4 只含大陆公网网段——" +
			"断言它必须在集合内会让 routing-setup 永远起不来（含 watchdog 的自动修复）")
	}
	if !strings.Contains(body2, "if rc.inSet(ctx, rc.Config.TunnelAddr)") {
		t.Error("应当反过来断言隧道地址不在集合内，以此检出被污染的来源")
	}
	if !strings.Contains(body2, "endpoints[0]") {
		t.Error("隧道对端必须仍然断言为不在集合内——它是境外地址，进了集合就会直连吃污染")
	}
}

func TestPreviewRunsBeforeAnySideEffect(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("routing.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	previewAt := strings.Index(text, "if rt.Preview {")
	if previewAt < 0 {
		t.Fatal("Apply 里找不到 preview 短路")
	}
	applyAt := strings.Index(text, "if err := rc.applyPolicyRoutes(ctx, rt); err != nil {")
	peerAt := strings.Index(text, "if err := rc.openHKPeer(ctx, rt); err != nil {")
	if applyAt < 0 || peerAt < 0 {
		t.Fatal("Apply 里找不到会改内核/隧道的调用")
	}
	if previewAt > applyAt || previewAt > peerAt {
		t.Fatal("preview 短路必须排在 applyPolicyRoutes 与 openHKPeer 之前——" +
			"否则 --preview 声称不动内核，却已经改了 ip rule 和 wg allowed-ips")
	}
}

func TestCNAuthorityEntriesSkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "chnroute"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "# 注释\n\n1.2.3.0/24\n  4.5.6.0/24  \nnot-an-ip\n"
	if err := os.WriteFile(filepath.Join(dir, "chnroute", "cn-authority.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := routingFixture()
	rc.Config.StateDir = dir
	got := rc.cnAuthorityEntries()
	want := []string{"1.2.3.0/24", "4.5.6.0/24"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("解析结果 %v，期望 %v", got, want)
	}
}
