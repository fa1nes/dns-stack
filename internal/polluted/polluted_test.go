package polluted

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const day = 86400

type fixture struct {
	dir    string
	opt    Options
	nowSec int64
}

func newFixture(t *testing.T, raw string) *fixture {
	t.Helper()
	dir := t.TempDir()
	frozen := time.Unix(1_800_000_000, 0)
	f := &fixture{dir: dir, nowSec: frozen.Unix()}
	f.opt = Options{
		RawPath:         filepath.Join(dir, "raw.txt"),
		EvidencePath:    filepath.Join(dir, "evidence.json"),
		OldOutputPath:   filepath.Join(dir, "active.txt"),
		ActiveOutPath:   filepath.Join(dir, "active.txt"),
		EvidenceOutPath: filepath.Join(dir, "evidence.json"),
		CIDROutPath:     filepath.Join(dir, "cidr.txt"),
		StatsPath:       filepath.Join(dir, "stats.txt"),
		MaxAgeDays:      7,
		MinObservations: 2,
		Now:             func() time.Time { return frozen },
	}
	write(t, f.opt.RawPath, raw)
	return f
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写 %s 失败: %v", path, err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", path, err)
	}
	return string(data)
}

func (f *fixture) evidence(t *testing.T) map[string]Evidence {
	t.Helper()
	var out map[string]Evidence
	if err := json.Unmarshal([]byte(read(t, f.opt.EvidenceOutPath)), &out); err != nil {
		t.Fatalf("证据文件不是合法 JSON: %v", err)
	}
	return out
}

func TestObservationThresholdKeepsSingleSightingsOut(t *testing.T) {
	f := newFixture(t, strings.Join([]string{
		"157.240.7.20", "157.240.7.20",
		"31.13.69.245",
		"2001:db8::1", "2001:db8::1", "2001:db8::1",
		"不是地址", "",
	}, "\n"))

	res, err := Run(f.opt)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.RawUnique != 3 {
		t.Errorf("原始去重数应为 3，得到 %d", res.RawUnique)
	}
	if res.Observed != 2 {
		t.Errorf("只出现一次的地址不该达标，期望 2 条，得到 %d", res.Observed)
	}
	body := read(t, f.opt.ActiveOutPath)
	if strings.Contains(body, "31.13.69.245") {
		t.Error("单次观测不能进入活跃清单——一次抖动就写死一个地址是不可接受的")
	}
	if !strings.Contains(body, "157.240.7.20") || !strings.Contains(body, "2001:db8::1") {
		t.Errorf("达标地址应当入选，得到:\n%s", body)
	}
}

func TestActiveListSortsIPv4BeforeIPv6(t *testing.T) {
	f := newFixture(t, strings.Join([]string{
		"2001:db8::1", "2001:db8::1",
		"223.5.5.5", "223.5.5.5",
		"1.1.1.1", "1.1.1.1",
	}, "\n"))
	if _, err := Run(f.opt); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	got := strings.Fields(read(t, f.opt.ActiveOutPath))
	want := []string{"1.1.1.1", "223.5.5.5", "2001:db8::1"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("排序应为 v4 在前再按数值，得到 %v，期望 %v", got, want)
		}
	}
}

func TestFirstSeenSurvivesWhileLastSeenRefreshes(t *testing.T) {
	f := newFixture(t, "1.2.3.4\n1.2.3.4\n")
	old := f.nowSec - 3*day
	write(t, f.opt.EvidencePath, `{"1.2.3.4":{"first_seen_at":`+strconv.FormatInt(old, 10)+`,"last_seen_at":`+strconv.FormatInt(old, 10)+`,"seen_count":5}}`)

	if _, err := Run(f.opt); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	item := f.evidence(t)["1.2.3.4"]
	if item.FirstSeenAt != old {
		t.Errorf("首次观测时间必须保留，得到 %d 期望 %d", item.FirstSeenAt, old)
	}
	if item.LastSeenAt != f.nowSec {
		t.Errorf("最近观测时间应当刷新，得到 %d 期望 %d", item.LastSeenAt, f.nowSec)
	}
	if item.SeenCount != 6 {
		t.Errorf("观测计数应当累加，得到 %d 期望 6", item.SeenCount)
	}
}

func TestStaleEvidenceExpiresButFreshSurvives(t *testing.T) {
	f := newFixture(t, "")
	stale := f.nowSec - 8*day
	fresh := f.nowSec - 2*day
	write(t, f.opt.EvidencePath, `{
		"9.9.9.9":{"first_seen_at":`+strconv.FormatInt(stale, 10)+`,"last_seen_at":`+strconv.FormatInt(stale, 10)+`,"seen_count":9},
		"8.8.8.8":{"first_seen_at":`+strconv.FormatInt(fresh, 10)+`,"last_seen_at":`+strconv.FormatInt(fresh, 10)+`,"seen_count":3}}`)

	if _, err := Run(f.opt); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	evidence := f.evidence(t)
	if _, ok := evidence["9.9.9.9"]; ok {
		t.Error("超过 MaxAgeDays 的证据必须过期，否则污染清单只增不减")
	}
	if _, ok := evidence["8.8.8.8"]; !ok {
		t.Error("TTL 内的证据必须保留")
	}
}

func TestEvidenceBootstrapsFromPreviousActiveList(t *testing.T) {
	f := newFixture(t, "")
	write(t, f.opt.OldOutputPath, "203.0.113.7\n203.0.113.8\n")

	res, err := Run(f.opt)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.Total != 2 {
		t.Errorf("证据文件丢失时应当从上一版活跃清单重建，得到 %d 条", res.Total)
	}
	if res.Added != 0 {
		t.Errorf("重建出来的条目不是新增，Added 应为 0，得到 %d", res.Added)
	}
	for key, item := range f.evidence(t) {
		if item.FirstSeenAt != f.nowSec || item.SeenCount != 1 {
			t.Errorf("%s 重建记录不对: %+v", key, item)
		}
	}
}

func TestAddedCountsOnlyGenuinelyNewAddresses(t *testing.T) {
	f := newFixture(t, "5.5.5.5\n5.5.5.5\n6.6.6.6\n6.6.6.6\n")
	write(t, f.opt.OldOutputPath, "5.5.5.5\n")

	res, err := Run(f.opt)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.Added != 1 || res.Total != 2 {
		t.Errorf("新增应只数上一版没有的地址，得到 Added=%d Total=%d", res.Added, res.Total)
	}
	stats := strings.Fields(read(t, f.opt.StatsPath))
	if len(stats) != 4 || stats[0] != "2" || stats[1] != "1" || stats[2] != "2" || stats[3] != "2" {
		t.Errorf("stats 应为「observed added total raw_unique」，得到 %v", stats)
	}
}

func TestAdjacentAddressesCollapseIntoCIDR(t *testing.T) {
	f := newFixture(t, strings.Join([]string{
		"203.0.113.0", "203.0.113.0", "203.0.113.1", "203.0.113.1",
		"2001:db8::2", "2001:db8::2", "2001:db8::3", "2001:db8::3",
	}, "\n"))
	if _, err := Run(f.opt); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	got := strings.Fields(read(t, f.opt.CIDROutPath))
	want := []string{"203.0.113.0/31", "2001:db8::2/127"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("相邻地址应当合并，得到 %v 期望 %v", got, want)
		}
	}
}

func TestNonAdjacentIPv6DoesNotCollapseAcrossPrefixBoundary(t *testing.T) {
	f := newFixture(t, strings.Join([]string{
		"2001:db8::1", "2001:db8::1", "2001:db8::2", "2001:db8::2",
	}, "\n"))
	if _, err := Run(f.opt); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	got := strings.Fields(read(t, f.opt.CIDROutPath))
	if len(got) != 2 {
		t.Fatalf("::1 与 ::2 跨 /127 边界，本来就不该合并，得到 %v", got)
	}
}

func TestThresholdGuardsRejectMeaninglessSettings(t *testing.T) {
	f := newFixture(t, "1.1.1.1\n")
	f.opt.MaxAgeDays = 0
	if _, err := Run(f.opt); err == nil {
		t.Error("MaxAgeDays<1 必须拒绝：证据会立刻过期，清单永远为空")
	}
	f.opt.MaxAgeDays = 7
	f.opt.MinObservations = 1
	if _, err := Run(f.opt); err == nil {
		t.Error("MinObservations<2 必须拒绝：一次抖动就能写死一个地址")
	}
}

func TestMissingRawFileIsNotAnError(t *testing.T) {
	f := newFixture(t, "")
	os.Remove(f.opt.RawPath)
	if _, err := Run(f.opt); err != nil {
		t.Errorf("原始观测文件不存在只表示本轮没有新观测，不该失败: %v", err)
	}
}
