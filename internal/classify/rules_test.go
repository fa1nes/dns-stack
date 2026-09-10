package classify

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/domain"
)

func TestProviderSuffixMatchingRespectsLabelBoundaries(t *testing.T) {
	shouldMatch := []string{
		"fastly.net", "a.b.fastly.net", "akamaiedge.net", "edge.akamaiedge.net",
		"alicdn.com", "img.alicdn.com", "aliyuncs.com", "example.com",
	}
	for _, name := range shouldMatch {
		if !IsSharedTenancyRoot(name) {
			t.Errorf("%s 应当被识别为多租户共享根域", name)
		}
	}
	shouldNotMatch := []string{
		"notfastly.net", "evil-example.com", "fastly.net.evil.com",
		"myakamaiedge.net", "qq.com", "baidu.com", "net", "com",
	}
	for _, name := range shouldNotMatch {
		if IsSharedTenancyRoot(name) {
			t.Errorf("%s 不该命中共享根域判据（按标签边界匹配才不会误伤）", name)
		}
	}
}

func TestGeoSteeringRootsAreAlwaysSharedTenancy(t *testing.T) {
	for _, root := range geoSteeringRoots {
		if !isGeoSteered(root) {
			t.Errorf("%s 应当带 geo-steering 标志", root)
		}
		if !IsSharedTenancyRoot(root) {
			t.Errorf("%s 带 geo-steering 却不带多租户标志——这两个集合的包含关系必须由构造保证", root)
		}
	}
	if isGeoSteered("qq.com") {
		t.Error("普通域名不该被当成 geo-steering 链")
	}
}

func testPSL(t *testing.T) *domain.PSL {
	t.Helper()
	var body []string
	body = append(body, "// ===BEGIN ICANN DOMAINS===")
	for _, rule := range []string{"com", "net", "org", "cn", "com.cn", "co.uk", "uk", "sh", "dev", "io"} {
		body = append(body, rule)
	}
	body = append(body, "// ===END ICANN DOMAINS===")
	text := ""
	for _, line := range body {
		text += line + "\n"
	}
	return domain.ParsePSL(text, "test")
}

func TestRuleKeyRefusesEverythingThatIsNotARegistrableZone(t *testing.T) {
	psl := testPSL(t)
	accepted := map[string]string{
		"www.qq.com":          "qq.com",
		"QQ.COM.":             "qq.com",
		"a.b.c.example.com":   "example.com",
		"shop.example.com.cn": "example.com.cn",
		"_dmarc.example.com":  "example.com",
		"www.example.co.uk":   "example.co.uk",
	}
	for input, want := range accepted {
		if got := ruleKey(input, psl); got != want {
			t.Errorf("ruleKey(%q) = %q，期望 %q", input, got, want)
		}
	}
	rejected := []string{
		"", "com", "com.cn", "co.uk", "localhost", "example.local",
		"1.2.3.4", "10.in-addr.arpa", "-bad.com", "bad-.com",
		"toplevelonly", "a..b.com", "x.test", "foo.invalid",
	}
	for _, input := range rejected {
		if got := ruleKey(input, psl); got != "" {
			t.Errorf("ruleKey(%q) 应当拒绝，却得到 %q", input, got)
		}
	}
}

func TestDropShadowedByForeignKeepsTheUnavailableSideSafe(t *testing.T) {
	kept, dropped := dropShadowedByForeign(
		[]string{"qq.com", "cdn.blocked.example", "blocked.example", "safe.example"},
		[]string{"blocked.example"})
	if !reflect.DeepEqual(kept, []string{"qq.com", "safe.example"}) {
		t.Errorf("保留集合不对: %v", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"cdn.blocked.example", "blocked.example"}) {
		t.Errorf("被 foreign 遮蔽的集合不对: %v", dropped)
	}
	same, none := dropShadowedByForeign([]string{"a.com"}, nil)
	if len(none) != 0 || !reflect.DeepEqual(same, []string{"a.com"}) {
		t.Error("没有 foreign 标记时应当原样返回")
	}
}

func TestCleanDomainsCollapsesRedundantSubdomainsExceptUnderSharedRoots(t *testing.T) {
	got := cleanDomains([]string{
		"taobao.com", "www.taobao.com", "pf123.taobao.com",
		"aliyuncs.com", "bucket.aliyuncs.com",
		"BAD_NAME", "-nope.com", "", "# comment",
		"solo.example",
	})
	want := []string{"aliyuncs.com", "bucket.aliyuncs.com", "solo.example", "taobao.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("清洗结果不对:\n得到 %v\n期望 %v", got, want)
	}
}

func TestPollutedPartitionKeepsGlobalAddressesOutOfTheClientDropList(t *testing.T) {
	publishable, auditOnly := partitionPollutedCIDRs([]string{
		"127.0.0.0/8", "0.0.0.0/8", "8.8.8.8/32", "157.240.7.0/24", "192.168.0.0/16",
	})
	if !reflect.DeepEqual(publishable, []string{"127.0.0.0/8", "0.0.0.0/8", "192.168.0.0/16"}) {
		t.Errorf("可发布集合不对: %v", publishable)
	}
	if !reflect.DeepEqual(auditOnly, []string{"8.8.8.8/32", "157.240.7.0/24"}) {
		t.Errorf("真实业务地址必须只进审计，不能进客户端 drop-list: %v", auditOnly)
	}
	if err := assertPollutedPublishable(publishable); err != nil {
		t.Errorf("非全局网段应当通过发布校验: %v", err)
	}
	if err := assertPollutedPublishable([]string{"157.240.7.0/24"}); err == nil {
		t.Error("全局可路由网段必须被发布护栏拦下")
	}
}

func TestAssertDisjointCatchesOverlapAcrossFamilies(t *testing.T) {
	if err := assertDisjoint([]string{"1.0.0.0/8"}, []string{"2001:db8::/32"}); err != nil {
		t.Errorf("不同协议族不该判为重叠: %v", err)
	}
	if err := assertDisjoint([]string{"1.0.0.0/8", "223.0.0.0/8"}, []string{"223.5.5.0/24"}); err == nil {
		t.Error("CN 与污染网段重叠必须拒绝发布")
	}
	if err := assertDisjoint([]string{"2001:db8::/32"}, []string{"2001:db8:1::/48"}); err == nil {
		t.Error("IPv6 重叠同样必须拒绝")
	}
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	frozen := time.Unix(1_800_000_000, 0)
	engine, err := Open(Config{
		DBPath:          filepath.Join(dir, "classifier.db"),
		StateDir:        dir,
		PublishMaxStale: 24 * time.Hour,
	}, func() time.Time { return frozen })
	if err != nil {
		t.Fatalf("打开测试引擎失败: %v", err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

func TestStoreAppliesVerdictsAndTracksChanges(t *testing.T) {
	engine := newTestEngine(t)
	verdicts := []Verdict{
		{Domain: "a.example", Status: StatusCN, Route: RouteCN, Reason: ReasonIdenticalAnswer,
			Landing: LandingMainland, Decisive: true},
		{Domain: "b.example", Status: StatusUnknown, Route: RouteUnknown, Reason: ReasonNoFinalIP,
			Landing: LandingNoAnswer},
	}
	changed, err := engine.Store.ApplyVerdicts(verdicts)
	if err != nil {
		t.Fatalf("写入判定失败: %v", err)
	}
	if changed != 1 {
		t.Errorf("首轮只有 a.example 从无到 cn，changed 应为 1，得到 %d", changed)
	}
	if changed, err = engine.Store.ApplyVerdicts(verdicts); err != nil || changed != 0 {
		t.Errorf("同样的判定重复写入不该记为变化，得到 %d (%v)", changed, err)
	}

	counts, err := engine.Store.Counts()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if counts.CN != 1 || counts.Unknown != 1 {
		t.Errorf("状态统计不对: %+v", counts)
	}

	history, err := engine.Store.History("a.example", 10)
	if err != nil {
		t.Fatalf("读历史失败: %v", err)
	}
	if len(history) != 2 || history[0].Status != StatusCN {
		t.Errorf("每轮观测都应当留档，得到 %+v", history)
	}
}

func TestManualOverridesOutrankAutomaticStatusInTheStore(t *testing.T) {
	engine := newTestEngine(t)
	if err := engine.Store.ReplaceManualOverrides(map[string]string{
		"pinned.example":  OverrideCN,
		"blocked.example": OverrideGFW,
		"muted.example":   OverrideExclude,
	}); err != nil {
		t.Fatalf("写人工规则失败: %v", err)
	}
	if _, err := engine.Store.ApplyVerdicts([]Verdict{
		{Domain: "pinned.example", Status: StatusUnknown, Route: RouteForeign, Reason: ReasonViewsConflict, Landing: LandingOffshore},
		{Domain: "muted.example", Status: StatusCN, Route: RouteCN, Reason: ReasonIdenticalAnswer, Landing: LandingMainland},
	}); err != nil {
		t.Fatalf("写入判定失败: %v", err)
	}
	manualCN, err := engine.Store.ManualByStatus(OverrideCN)
	if err != nil || !reflect.DeepEqual(manualCN, []string{"pinned.example"}) {
		t.Errorf("自动分类不得推翻人工规则，得到 %v (%v)", manualCN, err)
	}
	counts, _ := engine.Store.Counts()
	if counts.CN != 1 || counts.GFW != 1 {
		t.Errorf("人工规则应当反映在状态统计里: %+v", counts)
	}

	if err := engine.Store.ReplaceManualOverrides(map[string]string{"bad.example": "nonsense"}); err == nil {
		t.Error("非法的人工规则类型必须被拒绝")
	}
}

func TestTrafficRulesReplacePerClassAndSkipEmptyClasses(t *testing.T) {
	engine := newTestEngine(t)
	if _, err := engine.Store.ReplaceTrafficRules(map[string][]string{
		RuleCN:      {"qq.com", "taobao.com"},
		RuleForeign: {"blocked.example"},
	}); err != nil {
		t.Fatalf("写流量规则失败: %v", err)
	}
	if _, err := engine.Store.ReplaceTrafficRules(map[string][]string{
		RuleCN:      {"qq.com"},
		RuleForeign: nil,
	}); err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	cn, _ := engine.Store.PublicStaticRules(RuleCN)
	if !reflect.DeepEqual(cn, []string{"qq.com"}) {
		t.Errorf("cn 类应当被整体替换: %v", cn)
	}
	foreign, _ := engine.Store.PublicStaticRules(RuleForeign)
	if !reflect.DeepEqual(foreign, []string{"blocked.example"}) {
		t.Errorf("本轮为空的类必须整类跳过，不能把上一轮抹掉: %v", foreign)
	}
	removed, err := engine.Store.ClearTrafficRuleClass(RuleForeign)
	if err != nil || removed != 1 {
		t.Errorf("显式撤回应当是唯一的清空出口，得到 %d (%v)", removed, err)
	}
	if foreign, _ = engine.Store.PublicStaticRules(RuleForeign); len(foreign) != 0 {
		t.Errorf("撤回后应当为空: %v", foreign)
	}
}

func TestCIDRClassesMustStayDisjointInTheStore(t *testing.T) {
	engine := newTestEngine(t)
	if err := engine.Store.ReplaceCIDRs("cn", map[string][]string{"apnic": {"223.5.5.0/24"}}); err != nil {
		t.Fatalf("写 CN CIDR 失败: %v", err)
	}
	if err := engine.Store.ReplaceCIDRs("polluted", map[string][]string{"probe": {"223.5.5.128/25"}}); err == nil {
		t.Error("与 CN 网段重叠的污染网段必须在写入时就被拒绝")
	}
	active, _ := engine.Store.ActiveCIDRs("cn")
	if !reflect.DeepEqual(active, []string{"223.5.5.0/24"}) {
		t.Errorf("失败的写入必须整体回滚，CN 集合应当原样保留: %v", active)
	}
}

func TestPublicationFreshnessBlocksRulesFromAnOlderBaseline(t *testing.T) {
	engine := newTestEngine(t)
	if _, err := engine.Store.ApplyVerdicts([]Verdict{
		{Domain: "a.example", Status: StatusCN, Route: RouteCN, Reason: ReasonIdenticalAnswer, Landing: LandingMainland},
	}); err != nil {
		t.Fatalf("写入判定失败: %v", err)
	}
	readiness, err := engine.Store.PublicationReadiness(24 * time.Hour)
	if err != nil {
		t.Fatalf("读发布就绪度失败: %v", err)
	}
	if readiness.AutomaticTotal != 1 || readiness.Stale != 1 {
		t.Errorf("非决定性观测不该刷新 last_decisive_at: %+v", readiness)
	}
	if _, err := engine.Store.ApplyVerdicts([]Verdict{
		{Domain: "a.example", Status: StatusCN, Route: RouteCN, Reason: ReasonIdenticalAnswer,
			Landing: LandingMainland, Decisive: true},
	}); err != nil {
		t.Fatalf("写入判定失败: %v", err)
	}
	if readiness, err = engine.Store.PublicationReadiness(24 * time.Hour); err != nil || readiness.Stale != 0 {
		t.Errorf("决定性观测之后应当就绪: %+v (%v)", readiness, err)
	}
}

func TestMassDeletionGuard(t *testing.T) {
	engine := newTestEngine(t)
	bodies := map[string][]string{
		FileCN:  {"a.com", "b.com", "c.com", "d.com", "e.com"},
		FileGFW: {"x.com"}, FileCNCIDR: {"1.0.0.0/8"}, FilePolluted: {"127.0.0.0/8"},
	}
	if err := engine.writeBundle(renderBundle(1, ModeStandard, bodies)); err != nil {
		t.Fatalf("写规则包失败: %v", err)
	}
	shrunk := map[string][]string{
		FileCN: {"a.com"}, FileGFW: {"x.com"},
		FileCNCIDR: {"1.0.0.0/8"}, FilePolluted: {"127.0.0.0/8"},
	}
	if err := engine.guardMassDeletion(shrunk, false); err == nil {
		t.Error("骤降超阈值必须拦下")
	}
	if err := engine.guardMassDeletion(shrunk, true); err != nil {
		t.Errorf("--force 应当只跳过这道数量门禁: %v", err)
	}
	emptied := map[string][]string{
		FileCN: nil, FileGFW: {"x.com"},
		FileCNCIDR: {"1.0.0.0/8"}, FilePolluted: {"127.0.0.0/8"},
	}
	if err := engine.guardMassDeletion(emptied, false); err == nil {
		t.Error("从非空清空为 0 必须拦下")
	}
}

func TestBundleRoundTripPreservesHeaderAndBody(t *testing.T) {
	engine := newTestEngine(t)
	bodies := map[string][]string{
		FileCN: {"qq.com"}, FileGFW: nil,
		FileCNCIDR: {"223.5.5.0/24"}, FilePolluted: nil,
	}
	if err := engine.writeBundle(renderBundle(1788667325, ModeColdStart, bodies)); err != nil {
		t.Fatalf("写规则包失败: %v", err)
	}
	generations, modes := engine.bundleState()
	if uniform(generations) != 1788667325 {
		t.Errorf("四文件版本号必须一致且可读回: %v", generations)
	}
	if !sameMode(modes, ModeColdStart) {
		t.Errorf("bundle-mode 必须可读回: %v", modes)
	}
	if !engine.bodiesUnchanged(bodies) {
		t.Error("正文比对应当判为无变化")
	}
	bodies[FileGFW] = []string{"blocked.example"}
	if engine.bodiesUnchanged(bodies) {
		t.Error("正文变化必须被检出（阴性对照）")
	}
}
