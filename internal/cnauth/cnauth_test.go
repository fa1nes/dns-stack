package cnauth

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

var frozen = time.Unix(1_800_000_000, 0)

type lab struct {
	t   *testing.T
	dir string
	opt Options
	log bytes.Buffer
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{t: t, dir: t.TempDir()}
	l.write("direct4.txt", "1.1.1.0/24\n8.8.8.0/24\n")
	l.write("pairs.txt", "example.com 1.1.1.1 30\nother.example 8.8.8.8 40\n")
	l.write("manual.txt", "")
	l.write("shared.txt", fmt.Sprintf("# generated-at %d\n", frozen.Unix()))
	l.write("psl.dat", syntheticPSL())
	l.opt = Options{
		Direct4Path:       l.path("direct4.txt"),
		PairsPath:         l.path("pairs.txt"),
		ManualPath:        l.path("manual.txt"),
		SharedPath:        l.path("shared.txt"),
		PSLPaths:          []string{l.path("psl.dat")},
		ResultPath:        l.path("cn-authority.txt"),
		MatchedPath:       l.path("cn-zones-matched.txt"),
		ECSOutPath:        l.path("ecs.conf"),
		PrevECSPath:       l.path("ecs.conf"),
		ECSStatePath:      l.path("ecs-accum-state.tsv"),
		SharedExcludedOut: l.path("shared-excluded.txt"),
		Now:               func() time.Time { return frozen },
		Out:               &l.log,
	}
	return l
}

func syntheticPSL() string {
	var b strings.Builder
	b.WriteString("// ===BEGIN ICANN DOMAINS===\n")
	for _, rule := range []string{"com", "net", "org", "cn", "com.cn", "example"} {
		b.WriteString(rule + "\n")
	}
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "t%d\n", i)
	}
	b.WriteString("// ===END ICANN DOMAINS===\n")
	return b.String()
}

func (l *lab) path(name string) string { return filepath.Join(l.dir, name) }

func (l *lab) write(name, body string) {
	l.t.Helper()
	if err := os.WriteFile(l.path(name), []byte(body), 0o644); err != nil {
		l.t.Fatalf("写 %s 失败: %v", name, err)
	}
}

func (l *lab) writeCross(name, kind string, prefixes ...string) {
	l.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "# generated-at %d\n# kind %s\n# agreement 2\n# sources qqwry,maxmind\n",
		frozen.Unix(), kind)
	for _, prefix := range prefixes {
		b.WriteString(prefix + "\n")
	}
	l.write(name, b.String())
}

func (l *lab) run() (Result, error) {
	l.t.Helper()
	return Run(l.opt)
}

func (l *lab) ecsWhitelist() []netip.Prefix {
	l.t.Helper()
	prefixes, err := LoadECSWhitelist(l.opt.ECSOutPath)
	if err != nil {
		l.t.Fatalf("读 ECS 白名单失败: %v", err)
	}
	return prefixes
}

func TestECSWhitelistHasZeroIntersectionWithDisputedRanges(t *testing.T) {
	l := newLab(t)
	l.writeCross("disputed.txt", geoaudit.KindDisputed, "1.1.1.1/32")
	l.opt.DisputedPath = l.path("disputed.txt")

	if _, err := l.run(); err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}

	disputed, err := geoaudit.LoadSnapshot(l.path("disputed.txt"))
	if err != nil {
		t.Fatalf("读争议清单失败: %v", err)
	}
	for _, prefix := range l.ecsWhitelist() {
		lo, ok := ipset.PrefixRange(prefix)
		if !ok {
			continue
		}
		if disputed.Set.Overlaps(lo.Lo, lo.Hi) {
			t.Fatalf("ECS 白名单条目 %s 与争议网段相交——三层扣除里至少漏了一层\n%s",
				prefix, l.log.String())
		}
	}
}

func TestDisputedAddressCarvesTheColdStartRangeInsteadOfBeingOverwritten(t *testing.T) {
	l := newLab(t)
	l.writeCross("disputed.txt", geoaudit.KindDisputed, "1.1.1.1/32")
	l.opt.DisputedPath = l.path("disputed.txt")
	if _, err := l.run(); err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}

	carved := l.ecsWhitelist()
	for _, prefix := range carved {
		if prefix.String() == "1.1.1.0/24" {
			t.Fatalf("整条 /24 原样进了白名单，说明 direct4 冷启动段没扣掉争议地址——"+
				"那条 /24 会把刚挡掉的 /32 原样覆盖回来\n%v", carved)
		}
	}
	if !containsPrefix(carved, "1.1.1.0/32") || !containsPrefix(carved, "1.1.1.2/31") {
		t.Errorf("挖洞后应当出现 1.1.1.0/32 与 1.1.1.2/31 这样的碎片，得到 %v", carved)
	}
}

func TestWithoutDisputedListTheColdStartRangeStaysWhole(t *testing.T) {
	l := newLab(t)
	if _, err := l.run(); err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}
	if !containsPrefix(l.ecsWhitelist(), "1.1.1.0/24") {
		t.Errorf("没有争议清单时应当 fail-open，direct4 网段原样纳入，得到 %v", l.ecsWhitelist())
	}
}

func TestAccumulationDoesNotResurrectDisputedAddresses(t *testing.T) {
	l := newLab(t)
	l.write("ecs.conf", "server:\n    send-client-subnet: 9.9.9.9/32\n")
	l.write("ecs-accum-state.tsv", fmt.Sprintf("9.9.9.9/32 %d\n", frozen.Unix()-3600))
	l.writeCross("disputed.txt", geoaudit.KindDisputed, "9.9.9.9/32")
	l.opt.DisputedPath = l.path("disputed.txt")

	res, err := l.run()
	if err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}
	for _, prefix := range l.ecsWhitelist() {
		if prefix.String() == "9.9.9.9/32" {
			t.Fatalf("累积保留把争议地址从上一版白名单捞了回来——它绕开本轮全部判据，"+
				"72 小时后自然过期，永远不会有人把它归因到这次改动\n%s", l.log.String())
		}
	}
	if res.AccumKept != 0 {
		t.Errorf("这一条不该被计入累积保留，得到 %d", res.AccumKept)
	}
}

func TestAccumulationKeepsUndisputedAddressesWithinTTL(t *testing.T) {
	l := newLab(t)
	l.write("ecs.conf", "server:\n    send-client-subnet: 9.9.9.9/32\n")
	l.write("ecs-accum-state.tsv", fmt.Sprintf("9.9.9.9/32 %d\n", frozen.Unix()-3600))

	res, err := l.run()
	if err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}
	if res.AccumKept != 1 {
		t.Fatalf("TTL 内、本轮 infra 未覆盖的权威应当短期保留，得到 %d\n%s", res.AccumKept, l.log.String())
	}
	if !containsPrefix(l.ecsWhitelist(), "9.9.9.9/32") {
		t.Error("累积保留的地址应当仍在白名单里")
	}
}

func TestAccumulationExpiresBeyondTTL(t *testing.T) {
	l := newLab(t)
	l.write("ecs.conf", "server:\n    send-client-subnet: 9.9.9.9/32\n")
	l.write("ecs-accum-state.tsv", fmt.Sprintf("9.9.9.9/32 %d\n", frozen.Unix()-int64(DefaultAccumTTL.Seconds())-1))

	res, err := l.run()
	if err != nil {
		t.Fatalf("执行失败: %v\n%s", err, l.log.String())
	}
	if res.AccumKept != 0 {
		t.Errorf("超过 TTL 的累积条目必须过期，得到 %d", res.AccumKept)
	}
}

func TestPromotedListMustNotBeUsedAsDisputed(t *testing.T) {
	l := newLab(t)
	l.writeCross("wrong.txt", geoaudit.KindPromoted, "1.1.1.1/32")
	l.opt.DisputedPath = l.path("wrong.txt")

	_, err := l.run()
	if err == nil {
		t.Fatal("把 promoted 当 disputed 用必须 fail-closed——那会把真正的大陆权威整批踢出 ECS")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("错误消息要点明是 kind 接错线，得到: %v", err)
	}
}

func TestUnreadableCrossListFailsOpen(t *testing.T) {
	l := newLab(t)
	l.opt.DisputedPath = l.path("does-not-exist.txt")

	if _, err := l.run(); err != nil {
		t.Fatalf("清单读不到应当 fail-open 而不是让整轮失败: %v", err)
	}
	if !strings.Contains(l.log.String(), "读不到多源") {
		t.Errorf("fail-open 必须留下告警，否则护栏缺席会被当成正常:\n%s", l.log.String())
	}
}

func TestEmptyDirect4IsRefused(t *testing.T) {
	l := newLab(t)
	l.write("direct4.txt", "# 只有注释\n")
	if _, err := l.run(); err == nil {
		t.Fatal("direct4 为空时必须拒绝，绝不能拿空集合去重建权威集合")
	}
}

func TestMissingPSLIsRefused(t *testing.T) {
	l := newLab(t)
	l.opt.PSLPaths = []string{l.path("no-such-psl.dat")}
	if _, err := l.run(); err == nil {
		t.Fatal("缺少 PSL 时必须拒绝：没有它就分不清公共后缀和可注册域")
	}
}

func TestECSWhitelistLoaderRejectsMalformedLines(t *testing.T) {
	l := newLab(t)
	l.write("bad.conf", "server:\n    send-client-subnet: 不是网段\n")
	if _, err := LoadECSWhitelist(l.path("bad.conf")); err == nil {
		t.Fatal("白名单里出现无法解析的网段必须报错，而不是静默跳过")
	}
}

func containsPrefix(prefixes []netip.Prefix, want string) bool {
	for _, prefix := range prefixes {
		if prefix.String() == want {
			return true
		}
	}
	return false
}
