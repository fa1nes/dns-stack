package classify

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/geoaudit"
)

var frozenNow = time.Unix(1_800_000_000, 0)

func crossEngine(t *testing.T, requireCross bool) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "chnroute"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "chnroute", "direct4.txt"),
		"125.89.169.0/24\n140.205.31.0/24\n1.2.3.0/24\n")
	engine, err := Open(Config{
		DBPath:       filepath.Join(dir, "classifier.db"),
		StateDir:     dir,
		Direct4Path:  filepath.Join(dir, "chnroute", "direct4.txt"),
		CrossMaxAge:  48 * time.Hour,
		RequireCross: requireCross,
	}, func() time.Time { return frozenNow })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeDisputed(t *testing.T, e *Engine, generatedAt int64, sources, prefixes string) {
	t.Helper()
	body := "# generated-at " + strconv.FormatInt(generatedAt, 10) + "\n" +
		"# kind disputed\n# agreement 2\n# sources " + sources + "\n" + prefixes
	write(t, e.DisputedPath(), body)
	e.disputed = nil
}

func TestMissingCrossListRefusesToClassifyByDefault(t *testing.T) {
	engine := crossEngine(t, true)
	_, err := engine.Mainland()
	if err == nil {
		t.Fatal("缺少交叉清单时必须拒绝，否则会把注册在中国、实际在境外的段直连出去")
	}
	if !strings.Contains(err.Error(), "多源争议清单") {
		t.Fatalf("错误信息要指明缺什么，得到: %v", err)
	}
}

func TestStaleCrossListIsRefused(t *testing.T) {
	engine := crossEngine(t, true)
	writeDisputed(t, engine, frozenNow.Add(-72*time.Hour).Unix(), "qqwry,maxmind,dbip", "125.89.169.0/24\n")
	if _, err := engine.Mainland(); err == nil || !strings.Contains(err.Error(), "陈旧") {
		t.Fatalf("陈旧清单必须被拒（生成侧只在交叉成立时才写文件），得到: %v", err)
	}
}

func TestSingleSourceCrossListIsRefused(t *testing.T) {
	engine := crossEngine(t, true)
	writeDisputed(t, engine, frozenNow.Add(-time.Hour).Unix(), "qqwry", "125.89.169.0/24\n")
	if _, err := engine.Mainland(); err == nil || !strings.Contains(err.Error(), "归属库") {
		t.Fatalf("单一来源不构成交叉验证，必须被拒，得到: %v", err)
	}
}

func TestPromotedListRejectedAsDisputed(t *testing.T) {
	engine := crossEngine(t, true)
	body := "# generated-at " + strconv.FormatInt(frozenNow.Add(-time.Hour).Unix(), 10) + "\n" +
		"# kind " + geoaudit.KindPromoted + "\n# agreement 3\n# sources qqwry,maxmind,dbip\n125.89.169.0/24\n"
	write(t, engine.DisputedPath(), body)
	if _, err := engine.Mainland(); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("晋级清单和争议清单方向相反，混用会把判据反向，得到: %v", err)
	}
}

func TestFreshCrossListRemovesDisputedAddressesFromMainland(t *testing.T) {
	engine := crossEngine(t, true)
	writeDisputed(t, engine, frozenNow.Add(-time.Hour).Unix(), "qqwry,maxmind,dbip", "125.89.169.0/24\n")
	mainland, err := engine.Mainland()
	if err != nil {
		t.Fatalf("新鲜且多源的清单应当被接受: %v", err)
	}
	disputed := netip.MustParseAddr("125.89.169.195")
	clean := netip.MustParseAddr("140.205.31.96")

	if mainland.IsMainland(disputed) {
		t.Error("被多源判为境外的地址不得再算大陆")
	}
	if mainland.Judgeable(disputed) {
		t.Error("争议地址应当弃权，而不是被当成有效判据")
	}
	if !mainland.IsMainland(clean) {
		t.Error("未争议的 direct4 地址必须仍算大陆，否则规则会整体塌掉")
	}
	if !mainland.Judgeable(clean) {
		t.Error("未争议地址必须可判据")
	}
	if mainland.IsMainland(netip.MustParseAddr("8.8.8.8")) {
		t.Error("direct4 外的地址本来就不算大陆")
	}
}

func TestOptOutKeepsRunningWithoutCrossCheck(t *testing.T) {
	engine := crossEngine(t, false)
	mainland, err := engine.Mainland()
	if err != nil {
		t.Fatalf("显式关闭强制交叉后不应报错: %v", err)
	}
	if !mainland.IsMainland(netip.MustParseAddr("125.89.169.195")) {
		t.Error("退化模式下 direct4 仍是唯一判据")
	}
}

func TestRequireCrossDefaultsToOn(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "config.env"), "STATE_DIR="+dir+"\n")
	cfg, err := LoadConfig(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireCross {
		t.Error("默认必须要求交叉验证，否则新装节点会静默退化成 direct4 单源")
	}
	write(t, filepath.Join(dir, "off.env"), "RULE_REQUIRE_CROSS=0\n")
	off, err := LoadConfig(filepath.Join(dir, "off.env"))
	if err != nil {
		t.Fatal(err)
	}
	if off.RequireCross {
		t.Error("显式关闭必须生效，否则没有逃生口")
	}
}
