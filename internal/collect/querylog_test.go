package collect

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassifyKindCoversEveryOutcome(t *testing.T) {
	cases := []struct {
		respBy string
		rcode  int64
		want   string
	}{
		{"", 3, KindBlocked},
		{"", 5, KindRefused},
		{"", 0, KindUnknown},
		{"cache", 0, KindCache},
		{"foreign-hk", 0, KindForward},
		{"local-unbound", 0, KindRecursive},
		{"something-else", 0, KindUnknown},
	}
	for _, c := range cases {
		if got := ClassifyKind(c.respBy, c.rcode); got != c.want {
			t.Errorf("ClassifyKind(%q,%d) = %s，期望 %s", c.respBy, c.rcode, got, c.want)
		}
	}
	for _, kind := range []string{KindBlocked, KindRefused, KindCache, KindForward, KindRecursive} {
		if KindLabel(kind) == "未知" {
			t.Errorf("%s 没有中文标签", kind)
		}
	}
}

func TestCoarseSubnetNeverKeepsAWholeClientAddress(t *testing.T) {
	cases := map[string]string{
		"219.141.136.7/32":    "219.141.136.0/24",
		"219.141.136.0/24":    "219.141.136.0/24",
		"219.141.136.0/20":    "219.141.128.0/20",
		"219.141.136.7":       "219.141.136.0/24",
		"2001:db8:1:2::1/128": "2001:db8:1::/48",
		"2001:db8::/32":       "2001:db8::/32",
	}
	for input, want := range cases {
		if got := CoarseSubnet(input); got != want {
			t.Errorf("CoarseSubnet(%q) = %q，期望 %q", input, got, want)
		}
	}
	if got := CoarseSubnet("not an address"); got != "" {
		t.Errorf("无法解析时应返回空串，实得 %q", got)
	}
}

func TestQueryLogFiltersAndExports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	elapsed := 12.5
	events := []Event{
		{TS: now.Add(-time.Minute).Unix(), Domain: "ads.example.com", QType: 1, RCode: 3,
			Kind: KindBlocked, Route: "reject"},
		{TS: now.Add(-2 * time.Minute).Unix(), Domain: "www.qq.com", QType: 1, RCode: 0,
			RespBy: "local-unbound", Route: "cn", Kind: KindRecursive, ExitPath: "direct",
			ClientSubnet: "219.141.136.0/24", ElapsedMS: &elapsed},
		{TS: now.Add(-3 * time.Minute).Unix(), Domain: "www.wikipedia.org", QType: 1, RCode: 0,
			RespBy: "foreign-hk", Route: "foreign", Kind: KindForward, ExitPath: "hongkong"},
	}
	if err := RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	all, err := QueryLog(ctx, db, LogFilter{Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("应取回 3 条，实得 %d", len(all))
	}
	if all[0].Domain != "ads.example.com" {
		t.Errorf("应按时间倒序，首条是 %s", all[0].Domain)
	}
	if all[0].KindLabel != "域名黑名单" {
		t.Errorf("递归类型标签 = %q", all[0].KindLabel)
	}

	blocked, err := QueryLog(ctx, db, LogFilter{Since: now.Add(-time.Hour), Kind: KindBlocked})
	if err != nil || len(blocked) != 1 {
		t.Fatalf("按递归类型筛选应只剩 1 条: %v %v", blocked, err)
	}
	bySubnet, err := QueryLog(ctx, db, LogFilter{Since: now.Add(-time.Hour), ClientSubnet: "219.141.136"})
	if err != nil || len(bySubnet) != 1 {
		t.Fatalf("按来源子网筛选应只剩 1 条: %v %v", bySubnet, err)
	}
	byExit, err := QueryLog(ctx, db, LogFilter{Since: now.Add(-time.Hour), ExitPath: "hongkong"})
	if err != nil || len(byExit) != 1 || byExit[0].Domain != "www.wikipedia.org" {
		t.Fatalf("按出口筛选结果不对: %v %v", byExit, err)
	}
	byDomain, err := QueryLog(ctx, db, LogFilter{Since: now.Add(-time.Hour), Domain: "qq"})
	if err != nil || len(byDomain) != 1 {
		t.Fatalf("按域名模糊匹配应只剩 1 条: %v %v", byDomain, err)
	}

	counts, err := KindBreakdown(ctx, db, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, item := range counts {
		total += item.Count
	}
	if total != 3 {
		t.Fatalf("构成统计总数 = %d", total)
	}

	var buf strings.Builder
	if err := WriteLogCSV(&buf, all); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if !strings.HasPrefix(text, "\xEF\xBB\xBF") {
		t.Error("CSV 需要 BOM，否则 Excel 打开中文是乱码")
	}
	if !strings.Contains(text, "域名黑名单") || !strings.Contains(text, "ads.example.com") {
		t.Errorf("CSV 内容不完整:\n%s", text)
	}
	if strings.Count(text, "\n") < 4 {
		t.Errorf("CSV 应有表头加 3 行数据:\n%s", text)
	}
}

func TestOldRowsWithoutKindStillClassify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if err := RecordEvents(db, []Event{
		{TS: now.Unix(), Domain: "legacy.example.com", QType: 1, RCode: 0,
			RespBy: "cache", Route: "cache"},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := QueryLog(context.Background(), db, LogFilter{Since: now.Add(-time.Hour)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	if rows[0].Kind != KindCache {
		t.Fatalf("迁移前写入的行没有 kind 列，读取时应按 resp_by 现场判定，实得 %q", rows[0].Kind)
	}
}
