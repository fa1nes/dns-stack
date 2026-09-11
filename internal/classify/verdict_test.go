package classify

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

type fakeMainland map[netip.Addr]struct{}

func (f fakeMainland) IsMainland(addr netip.Addr) bool {
	_, ok := f[addr]
	return ok
}

func mainlandOf(values ...string) fakeMainland {
	out := fakeMainland{}
	for _, value := range values {
		out[netip.MustParseAddr(value)] = struct{}{}
	}
	return out
}

func answer(chain []string, ips ...string) *resolve.Outcome {
	out := &resolve.Outcome{OK: true, Reason: resolve.ReasonAnswer, CNAMEChain: chain}
	for _, ip := range ips {
		addr := netip.MustParseAddr(ip)
		if addr.Is4() {
			out.A = append(out.A, addr)
		} else {
			out.AAAA = append(out.AAAA, addr)
		}
	}
	return out
}

func failure(reason string, chain ...string) *resolve.Outcome {
	return &resolve.Outcome{Reason: reason, CNAMEChain: chain}
}

func pollutedOf(values ...string) *cidrutil.Set {
	set, rejected := cidrutil.ParseSet(values)
	if len(rejected) > 0 {
		panic("测试污染集合里有非法条目: " + strings.Join(rejected, ","))
	}
	return set
}

var noMainland = fakeMainland{}

func decide(t *testing.T, name string, cn, foreign *resolve.Outcome, opts ...func(*decideOpts)) Verdict {
	t.Helper()
	options := decideOpts{mainland: noMainland, polluted: pollutedOf()}
	for _, apply := range opts {
		apply(&options)
	}
	return Decide(Input{Domain: name, CN: cn, Foreign: foreign},
		options.override, options.mainland, options.polluted)
}

type decideOpts struct {
	override string
	mainland Mainland
	polluted *cidrutil.Set
}

func withMainland(m Mainland) func(*decideOpts) {
	return func(o *decideOpts) { o.mainland = m }
}
func withPolluted(values ...string) func(*decideOpts) {
	return func(o *decideOpts) { o.polluted = pollutedOf(values...) }
}
func withOverride(kind string) func(*decideOpts) {
	return func(o *decideOpts) { o.override = kind }
}

func expect(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: 得到 %q，期望 %q", label, got, want)
	}
}

func TestDecisiveRequiresBothViews(t *testing.T) {
	if !decide(t, "both.example", answer(nil, "1.1.1.1"), answer(nil, "1.1.1.1")).Decisive {
		t.Error("两侧都拿到可路由应答应当算一次决定性复检")
	}
	gone := failure(resolve.ReasonNXDomain)
	if !decide(t, "gone.example", gone, gone).Decisive {
		t.Error("两侧一致 NXDOMAIN 应当算决定性")
	}
	timeout := failure(resolve.ReasonTimeout)
	if decide(t, "half.example", answer(nil, "1.1.1.1"), timeout).Decisive {
		t.Error("境外单侧超时不能刷新复检时间，否则一次跨境抖动就把规则当成复检过了")
	}
	if decide(t, "half.example", timeout, answer(nil, "8.8.8.8")).Decisive {
		t.Error("国内单侧超时不能刷新复检时间")
	}
	if decide(t, "dead.example", timeout, timeout).Decisive {
		t.Error("两侧都失败不能算决定性")
	}
}

func TestIdenticalAnswersRouteCNButNeedMainlandLanding(t *testing.T) {
	cn := answer(nil, "1.1.1.1", "2606:4700:4700::1111")
	foreign := answer(nil, "2606:4700:4700::1111", "1.1.1.1")

	v := decide(t, "same.example", cn, foreign)
	expect(t, "route", v.Route, RouteCN)
	expect(t, "reason", v.Reason, ReasonIdenticalAnswer)
	expect(t, "landing", v.Landing, LandingOffshore)
	expect(t, "status", v.Status, StatusUnknown)
}

func TestAddressSubsetIsNotIdentical(t *testing.T) {
	v := decide(t, "subset.example", answer(nil, "1.1.1.1"), answer(nil, "1.1.1.1", "8.8.8.8"))
	expect(t, "route", v.Route, RouteForeign)
	expect(t, "reason", v.Reason, ReasonViewsConflict)
	expect(t, "status", v.Status, StatusUnknown)
}

func TestSharedGeoSteeredChainKeepsCDNTrafficDomestic(t *testing.T) {
	chain := []string{"service.example.akadns.net", "edge.akamaiedge.net"}
	v := decide(t, "service.example",
		answer(chain, "125.89.169.195"), answer(chain, "17.57.145.154"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "route", v.Route, RouteCN)
	expect(t, "reason", v.Reason, ReasonSharedGeoDNSChain)
	expect(t, "status", v.Status, StatusCN)
}

func TestChineseCDNChainIsAlsoGeoSteered(t *testing.T) {
	chain := []string{"www.example.com.w.kunlunsl.com"}
	v := decide(t, "www.example.com",
		answer(chain, "140.205.31.96"), answer(chain, "47.246.24.1"),
		withMainland(mainlandOf("140.205.31.96")))
	expect(t, "reason", v.Reason, ReasonSharedGeoDNSChain)
	expect(t, "status", v.Status, StatusCN)
}

func TestArbitraryCommonCNAMEDoesNotValidateConflict(t *testing.T) {
	chain := []string{"edge.untrusted.example"}
	v := decide(t, "conflict.example", answer(chain, "8.8.8.8"), answer(chain, "1.1.1.1"))
	expect(t, "route", v.Route, RouteForeign)
	expect(t, "reason", v.Reason, ReasonViewsConflict)
}

func TestSplitHorizonGeoDNSStaysDomestic(t *testing.T) {
	v := decide(t, "split.example",
		answer([]string{"split.example.cdn-custom.example"}, "125.89.169.195", "140.205.31.96"),
		answer([]string{"split.example.cdn-custom.example"}, "17.253.200.10"),
		withMainland(mainlandOf("125.89.169.195", "140.205.31.96")))
	expect(t, "route", v.Route, RouteCN)
	expect(t, "reason", v.Reason, ReasonSplitHorizon)
	expect(t, "status", v.Status, StatusCN)
}

func TestDualStackAnswerStillSplitHorizons(t *testing.T) {
	v := decide(t, "dual.example",
		answer(nil, "125.89.169.195", "2408:8756::1"),
		answer(nil, "17.253.200.10", "2620:149:af0::10"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "route", v.Route, RouteCN)
	expect(t, "reason", v.Reason, ReasonSplitHorizon)
	expect(t, "landing", v.Landing, LandingMainland)
	expect(t, "status", v.Status, StatusCN)
}

func TestUnjudgeableAnswerNeverClaimsOffshore(t *testing.T) {
	only6 := answer(nil, "2408:8756::1")
	v := decide(t, "v6only.example", only6, only6)
	expect(t, "landing", v.Landing, LandingUnjudged)
	expect(t, "status", v.Status, StatusUnknown)

	noEvidence := decide(t, "v6split.example",
		answer(nil, "2408:8756::1"), answer(nil, "17.253.200.10"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "国内侧没有可判据的地址时不得声称分水", noEvidence.Reason, ReasonViewsConflict)

	foreign6 := decide(t, "foreign6.example",
		answer(nil, "125.89.169.195"), answer(nil, "2620:149:af0::10"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "境外侧没有可判据的地址时不得声称分水", foreign6.Reason, ReasonViewsConflict)
}

func TestSplitHorizonRejectsMixedCNView(t *testing.T) {
	v := decide(t, "mixed.example",
		answer(nil, "125.89.169.195", "8.8.8.8"),
		answer(nil, "17.253.200.10"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "route", v.Route, RouteForeign)
	expect(t, "reason", v.Reason, ReasonViewsConflict)
	expect(t, "status", v.Status, StatusUnknown)
}

func TestSplitHorizonRejectsForeignLandingInMainland(t *testing.T) {
	v := decide(t, "both-cn.example",
		answer(nil, "125.89.169.195"),
		answer(nil, "140.205.31.96"),
		withMainland(mainlandOf("125.89.169.195", "140.205.31.96")))
	expect(t, "reason", v.Reason, ReasonViewsConflict)
	expect(t, "status", v.Status, StatusUnknown)
}

func TestPollutionStillBeatsSplitHorizon(t *testing.T) {
	v := decide(t, "poisoned.example",
		answer(nil, "157.240.7.20"), answer(nil, "17.253.200.10"),
		withPolluted("157.240.7.20"), withMainland(mainlandOf("157.240.7.20")))
	expect(t, "status", v.Status, StatusGFW)
	expect(t, "reason", v.Reason, ReasonCNViewPolluted)
}

func TestMinorityNonGlobalAnswerDoesNotVoidView(t *testing.T) {
	v := decide(t, "mostly-good.example",
		answer(nil, "125.89.169.195", "192.168.10.1"),
		answer(nil, "17.253.200.10"),
		withMainland(mainlandOf("125.89.169.195")))
	expect(t, "route", v.Route, RouteCN)
	expect(t, "reason", v.Reason, ReasonSplitHorizon)
	if len(v.AnomalousIPs) != 1 || v.AnomalousIPs[0].String() != "192.168.10.1" {
		t.Errorf("混入的私网地址应单列进异常清单，得到 %v", v.AnomalousIPs)
	}

	allBad := decide(t, "all-bad.example",
		answer(nil, "127.0.0.1", "192.168.10.1"),
		answer(nil, "8.8.8.8"))
	expect(t, "全异常仍走异常分支", allBad.Reason, ReasonAbnormalCNAnswer)
	expect(t, "route", allBad.Route, RouteForeign)
}

func TestCNPollutionUnconfirmedIsRechecked(t *testing.T) {
	for _, r := range recheckReasons {
		if r == ReasonCNPollutionUnconfirmed {
			return
		}
	}
	t.Error("cn_pollution_unconfirmed_hk 必须在复检清单里，否则香港侧一次抖动就把污染域名永久悬置")
}

func TestAbnormalAnswersPreferTheSafeView(t *testing.T) {
	hijacked := decide(t, "hijacked.example", answer(nil, "127.0.0.1"), answer(nil, "8.8.8.8"))
	expect(t, "route", hijacked.Route, RouteForeign)
	expect(t, "reason", hijacked.Reason, ReasonAbnormalCNAnswer)
	if len(hijacked.AnomalousIPs) != 1 || hijacked.AnomalousIPs[0].String() != "127.0.0.1" {
		t.Errorf("异常地址应当被单列出来，得到 %v", hijacked.AnomalousIPs)
	}
	expect(t, "status", hijacked.Status, StatusUnknown)

	reverse := decide(t, "foreign-bad.example", answer(nil, "8.8.8.8"), answer(nil, "127.0.0.1"))
	expect(t, "route", reverse.Route, RouteCN)
	expect(t, "reason", reverse.Reason, ReasonAbnormalForeignAnswer)
}

func TestSingleUsableViewIsFallbackOnly(t *testing.T) {
	v := decide(t, "fallback.example", failure(resolve.ReasonTimeout), answer(nil, "8.8.8.8"))
	expect(t, "route", v.Route, RouteForeign)
	expect(t, "reason", v.Reason, "cn_timeout_foreign_fallback")
	expect(t, "status", v.Status, StatusUnknown)
}

func TestCNAMELoopStaysIndeterminate(t *testing.T) {
	loop := failure(resolve.ReasonCNAMELoop, "a.example", "b.example")
	v := decide(t, "loop.example", loop, loop)
	expect(t, "route", v.Route, RouteUnknown)
	expect(t, "reason", v.Reason, ReasonIndeterminate)
	expect(t, "status", v.Status, StatusUnknown)
}

func TestLandingVerdicts(t *testing.T) {
	mainland := mainlandOf("125.89.169.195", "140.205.31.96", "103.115.248.1")

	disagree := decide(t, "apps.apple.com",
		answer(nil, "125.89.169.195"), answer(nil, "17.253.200.10"), withMainland(mainland))
	expect(t, "landing", disagree.Landing, LandingMainland)
	expect(t, "国内视角全落大陆且境外视角全在境外，按分水晋级",
		disagree.Status, StatusCN)

	mixed := answer(nil, "140.205.31.96", "17.253.200.10")
	mixedVerdict := decide(t, "gs-loc.apple.com", mixed, mixed, withMainland(mainland))
	expect(t, "landing", mixedVerdict.Landing, LandingMixed)
	expect(t, "status", mixedVerdict.Status, StatusCN)

	offshore := answer(nil, "93.184.216.34")
	offshoreVerdict := decide(t, "example.com", offshore, offshore, withMainland(mainland))
	expect(t, "landing", offshoreVerdict.Landing, LandingOffshore)
	expect(t, "纯境外落点绝不产生 gfw", offshoreVerdict.Status, StatusUnknown)

	dead := failure(resolve.ReasonTimeout)
	expect(t, "landing", decide(t, "dead.example", dead, dead, withMainland(mainland)).Landing, LandingNoAnswer)

	hidden := answer(nil, "127.0.0.1", "192.168.10.1")
	expect(t, "非全局地址不参与落点判定",
		decide(t, "hidden-master.example", hidden, hidden, withMainland(mainland)).Landing, LandingNoAnswer)

	fallback := decide(t, "cn-down.example",
		failure(resolve.ReasonTimeout), answer(nil, "103.115.248.1"), withMainland(mainland))
	expect(t, "国内视角为空时落点回退到境外视角", fallback.Landing, LandingMainland)
	expect(t, "status", fallback.Status, StatusUnknown)
}

func TestPollutionIsTheOnlyEvidenceForGFW(t *testing.T) {
	polluted := withPolluted("157.240.7.20", "31.13.69.245", "2001::1")
	mainland := withMainland(mainlandOf("125.89.169.195"))

	confirmed := decide(t, "blocked.example",
		answer(nil, "157.240.7.20"), answer(nil, "93.184.216.34"), polluted, mainland)
	if !confirmed.CNViewPolluted {
		t.Error("国内视角被污染且境外视角干净，应当确认污染")
	}
	expect(t, "status", confirmed.Status, StatusGFW)
	expect(t, "reason", confirmed.Reason, ReasonCNViewPolluted)
	expect(t, "route", confirmed.Route, RouteForeign)

	unconfirmed := decide(t, "blocked.example",
		answer(nil, "157.240.7.20"), failure(resolve.ReasonTimeout), polluted, mainland)
	if unconfirmed.CNViewPolluted {
		t.Error("境外视角拿不到对照时不能确认污染")
	}
	expect(t, "reason", unconfirmed.Reason, ReasonCNPollutionUnconfirmed)
	expect(t, "status", unconfirmed.Status, StatusUnknown)

	bothSides := answer(nil, "157.240.7.20")
	both := decide(t, "blocked.example", bothSides, bothSides, polluted, mainland)
	if both.CNViewPolluted {
		t.Error("两侧同样结果说明那是真实地址，不是国内注入")
	}
	if !both.ForeignPolluted {
		t.Error("境外侧命中污染清单应当被记录")
	}
	expect(t, "reason", both.Reason, ReasonBothViewsPolluted)
	expect(t, "status", both.Status, StatusUnknown)

	byCIDR := decide(t, "blocked.example",
		answer(nil, "157.240.7.20"), answer(nil, "93.184.216.34"), withPolluted("157.240.7.0/24"))
	expect(t, "污染判据按 CIDR 命中", byCIDR.Status, StatusGFW)

	overMainland := decide(t, "blocked.example",
		answer(nil, "157.240.7.20", "125.89.169.195"), answer(nil, "93.184.216.34"), polluted, mainland)
	expect(t, "污染优先于看起来像大陆的落点", overMainland.Status, StatusGFW)
}

func TestManualOverrideOutranksEveryAutomaticVerdict(t *testing.T) {
	cn := answer(nil, "157.240.7.20")
	v := decide(t, "pinned.example", cn, cn,
		withOverride(OverrideCN), withPolluted("157.240.7.20"))
	expect(t, "status", v.Status, StatusCN)

	excluded := decide(t, "pinned.example", cn, cn, withOverride(OverrideExclude))
	expect(t, "exclude 只是撤回自动结论，不产生规则", excluded.Status, StatusUnknown)
}

func TestNonGlobalAddressesNeverCountAsPollution(t *testing.T) {
	v := decide(t, "local.example",
		answer(nil, "127.0.0.1"), answer(nil, "8.8.8.8"), withPolluted("127.0.0.0/8"))
	if v.CNViewPolluted {
		t.Error("非全局地址不能作为污染证据，它先被 abnormal 分支拦下")
	}
	expect(t, "reason", v.Reason, ReasonAbnormalCNAnswer)
}
