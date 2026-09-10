package collect

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"  WWW.Example.COM.  ":            "www.example.com",
		"a-b.example.com":                 "a-b.example.com",
		"xn--fiqs8s":                      "xn--fiqs8s",
		"":                                "",
		".":                               "",
		"-bad.example.com":                "",
		"bad-.example.com":                "",
		"_dmarc.example.com":              "",
		"a..b.com":                        "",
		"例子.测试":                           "",
		strings.Repeat("a", 64) + ".com":  "",
		strings.Repeat("a.", 130) + "com": "",
	}
	for input, want := range cases {
		if got := NormalizeDomain(input); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, 期望 %q", input, got, want)
		}
	}

	if !NonASCII("例子.测试") {
		t.Error("非 ASCII 名字未被识别")
	}
	if NonASCII("_dmarc.example.com") {
		t.Error("纯 ASCII 的非法名字被误判为非 ASCII")
	}
}

func TestClassifyRoute(t *testing.T) {
	cases := map[string]string{
		"":              "reject",
		"cache":         "cache",
		"local-unbound": "cn",
		"foreign-hk":    "foreign",
		"alidns":        "unknown",
	}
	for input, want := range cases {
		if got := ClassifyRoute(input); got != want {
			t.Errorf("ClassifyRoute(%q) = %q, 期望 %q", input, got, want)
		}
	}
}

func TestClassifyExitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn-zones-matched.txt")
	if err := os.WriteFile(path, []byte("# 注释\nqq.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zones := NewZoneSet(path)
	cases := []struct {
		domain, route, want string
	}{
		{"www.qq.com", "cn", "direct"},
		{"qq.com", "cn", "direct"},
		{"github.com", "cn", "tunnel"},
		{"github.com", "cache", "cache"},
		{"github.com", "foreign", "hongkong"},
		{"github.com", "reject", "reject"},
		{"github.com", "unknown", "unknown"},
	}
	for _, item := range cases {
		if got := ClassifyExitPath(zones, item.domain, item.route); got != item.want {
			t.Errorf("ClassifyExitPath(%s,%s) = %q, 期望 %q",
				item.domain, item.route, got, item.want)
		}
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyExitPath(NewZoneSet(path), "www.qq.com", "cn"); got != "tunnel" {
		t.Errorf("清单缺失时 = %q，期望 tunnel", got)
	}
}

func TestZoneSetReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zones.txt")
	if err := os.WriteFile(path, []byte("qq.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zones := NewZoneSet(path)
	if !zones.Covers("qq.com") {
		t.Fatal("首次读取失败")
	}

	later := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(path, []byte("baidu.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if zones.Covers("qq.com") {
		t.Error("mtime 变化后仍返回旧集合")
	}
	if !zones.Covers("baidu.com") {
		t.Error("未读到新集合")
	}
}

func newTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collector.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestRecordEventsAggregatesByDomain(t *testing.T) {
	db, _ := newTestDB(t)
	elapsed := 12.5
	events := []Event{
		{TS: 100, Domain: "qq.com", QType: 1, RCode: 0, RespBy: "local-unbound",
			Route: "cn", ExitPath: "direct", ServerTag: "doh-in", ElapsedMS: &elapsed},
		{TS: 300, Domain: "qq.com", QType: 28, RCode: 3, RespBy: "cache", Route: "cache",
			ExitPath: "cache", ServerTag: "doh-in"},
		{TS: 200, Domain: "qq.com", QType: 1, RCode: 0, RespBy: "local-unbound",
			Route: "cn", ExitPath: "direct", ServerTag: "doh-in"},
		{TS: 150, Domain: "baidu.com", QType: 1, RCode: 0, RespBy: "local-unbound",
			Route: "cn", ExitPath: "direct", ServerTag: "doh-in"},
	}
	if err := RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("事件条数 = %d，期望 4", count)
	}
	var first, last, occurrences, fails int64
	var rcode int64
	var route string
	err := db.QueryRow("SELECT first_seen_at,last_seen_at,occurrence_count,fail_count,last_rcode,last_route "+
		"FROM domains WHERE domain='qq.com'").Scan(&first, &last, &occurrences, &fails, &rcode, &route)
	if err != nil {
		t.Fatal(err)
	}

	if first != 100 || last != 300 || occurrences != 3 || fails != 1 {
		t.Fatalf("聚合错误: first=%d last=%d count=%d fails=%d", first, last, occurrences, fails)
	}
	if rcode != 3 || route != "cache" {
		t.Fatalf("last_rcode/route 未取时间最晚那条: rcode=%d route=%q", rcode, route)
	}

	var nullElapsed int64
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events WHERE elapsed_ms IS NULL").Scan(&nullElapsed); err != nil {
		t.Fatal(err)
	}
	if nullElapsed != 3 {
		t.Fatalf("NULL 耗时条数 = %d，期望 3", nullElapsed)
	}
}

func TestRecordEventsNeverRollsBackLastSeen(t *testing.T) {
	db, _ := newTestDB(t)
	if err := RecordEvents(db, []Event{{TS: 500, Domain: "qq.com", Route: "cn"}}); err != nil {
		t.Fatal(err)
	}

	if err := RecordEvents(db, []Event{{TS: 100, Domain: "qq.com", Route: "cn"}}); err != nil {
		t.Fatal(err)
	}
	var last, occurrences int64
	if err := db.QueryRow("SELECT last_seen_at,occurrence_count FROM domains WHERE domain='qq.com'").
		Scan(&last, &occurrences); err != nil {
		t.Fatal(err)
	}
	if last != 500 {
		t.Fatalf("last_seen_at 倒退到 %d", last)
	}
	if occurrences != 2 {
		t.Fatalf("occurrence_count = %d，期望 2", occurrences)
	}
}

func TestPullBatchMarksAndFiltersCandidates(t *testing.T) {
	db, _ := newTestDB(t)
	events := []Event{
		{TS: 100, Domain: "qq.com", Route: "cn"},
		{TS: 100, Domain: "1.0.0.127.in-addr.arpa", Route: "cn"},
		{TS: 100, Domain: "single", Route: "cn"},
	}
	if err := RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}
	rows, err := PullBatch(db, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 1 || rows[0].Domain != "qq.com" {
		t.Fatalf("候选过滤错误: %+v", rows)
	}
	var pending int64
	if err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE pulled_by_foreign = 0").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("仍有 %d 条未标记为已拉取", pending)
	}
	again, err := PullBatch(db, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("同一批被拉取了两次: %+v", again)
	}
}

func TestPruneEventsHonoursRetentionWindow(t *testing.T) {
	db, _ := newTestDB(t)
	now := int64(10_000_000)
	old := now - (eventRetentionDays+1)*86400
	if err := RecordEvents(db, []Event{
		{TS: old, Domain: "old.example", Route: "cn"},
		{TS: now, Domain: "fresh.example", Route: "cn"},
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := PruneEvents(db, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("删除条数 = %d，期望 1", deleted)
	}
	var remaining int64
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("剩余 %d 条，期望 1", remaining)
	}

	var domains int64
	if err := db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domains); err != nil {
		t.Fatal(err)
	}
	if domains != 2 {
		t.Fatalf("domains 被误删：剩 %d 条", domains)
	}
}

func TestHandleLineDropsClientAddressAndForwardsOperationalLogs(t *testing.T) {
	var out bytes.Buffer
	consumer := NewConsumer("", t.TempDir(), &out)
	consumer.now = func() time.Time { return time.Unix(1700000000, 0) }

	consumer.HandleLine("plain mosproxy line")

	consumer.HandleLine(`{"level":"info","message":"router is up and running"}`)

	consumer.HandleLine(`{"message":"query log","time":1700000000123,` +
		`"query":{"name":"WWW.QQ.com.","type":1,"prefetch":true},` +
		`"meta":{"server":"doh-in","remote":"203.0.113.7:5555"},` +
		`"resp":{"rcode":0,"resp_by":"local-unbound"},"elapsed":9.5}`)

	text := out.String()
	if !strings.Contains(text, "plain mosproxy line") ||
		!strings.Contains(text, "router is up and running") {
		t.Fatalf("运营日志未原样转发: %q", text)
	}
	if strings.Contains(text, "203.0.113.7") {
		t.Fatal("客户端地址被转发到了 stdout")
	}
	if len(consumer.pending) != 1 {
		t.Fatalf("待写事件数 = %d，期望 1", len(consumer.pending))
	}
	event := consumer.pending[0]
	if event.Domain != "www.qq.com" {
		t.Errorf("域名未规范化: %q", event.Domain)
	}
	if event.TS != 1700000000 {
		t.Errorf("毫秒时间戳未换算: %d", event.TS)
	}
	if event.Route != "cn" || event.ExitPath != "tunnel" {
		t.Errorf("route/exit_path = %q/%q", event.Route, event.ExitPath)
	}
	if event.Prefetch != 1 {
		t.Errorf("prefetch = %d", event.Prefetch)
	}
	if event.ElapsedMS == nil || *event.ElapsedMS != 9.5 {
		t.Errorf("elapsed_ms = %v", event.ElapsedMS)
	}
	if event.ServerTag != "doh-in" {
		t.Errorf("server_tag = %q", event.ServerTag)
	}
}

func TestHandleLineReportsNonASCIIInsteadOfSilentlyDropping(t *testing.T) {
	var out bytes.Buffer
	consumer := NewConsumer("", t.TempDir(), &out)
	consumer.HandleLine(`{"message":"query log","query":{"name":"例子.测试","type":1},` +
		`"resp":{"rcode":0,"resp_by":"cache"}}`)
	if len(consumer.pending) != 0 {
		t.Fatal("非 ASCII 名字不该入库")
	}

	if !strings.Contains(out.String(), "非 ASCII 查询名") {
		t.Fatalf("未告警: %q", out.String())
	}
	if consumer.nonASCIIDropped != 1 {
		t.Fatalf("丢弃计数 = %d", consumer.nonASCIIDropped)
	}
}

func TestRunSurvivesUnwritableDatabase(t *testing.T) {

	db, path := newTestDB(t)
	var out bytes.Buffer
	consumer := NewConsumer(path, t.TempDir(), &out)
	consumer.now = time.Now
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o500); err != nil {
		t.Skipf("无法构造不可写路径: %v", err)
	}
	err := consumer.Run(strings.NewReader(`{"message":"query log","query":{"name":"qq.com","type":1},"resp":{"rcode":0,"resp_by":"cache"}}` + "\n"))

	if err == nil {
		t.Log("数据库意外可用，跳过断言")
	}
}

func TestConsumeStdinPersistsThroughRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	var out bytes.Buffer
	consumer := NewConsumer(path, t.TempDir(), &out)
	input := strings.Join([]string{
		`{"message":"query log","time":1700000000000,"query":{"name":"qq.com","type":1},"meta":{"server":"doh-in"},"resp":{"rcode":0,"resp_by":"local-unbound"}}`,
		`{"message":"query log","time":1700000001000,"query":{"name":"qq.com","type":28},"meta":{"server":"doh-in"},"resp":{"rcode":2,"resp_by":"foreign-hk"}}`,
		"",
	}, "\n")
	if err := consumer.Run(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stats, err := ReadStats(db)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalDomains != 1 || stats.QueryEvents != 2 || stats.PendingPull != 1 {
		t.Fatalf("落盘结果不符: %+v", stats)
	}
}

func TestLoadCNCIDRsRefusesUndersizedSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "chnroute"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "chnroute", "direct4.txt"),
		[]byte("116.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCNCIDRs(dir); len(got) != 0 {
		t.Fatalf("残缺快照应返回空集，实际 %d 条", len(got))
	}
}

func TestLoadPollutedCIDRsMergesBothSources(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "polluted-ip-cidr.txt"),
		[]byte("# 注释\n157.240.7.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "polluted-ip.txt"),
		[]byte("31.13.64.1\n157.240.7.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadPollutedCIDRs(dir)
	want := []string{"31.13.64.1/32", "157.240.7.0/24"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("= %v, 期望 %v", got, want)
	}
}

func TestCollapsePrefixesMergesSiblingsAndContained(t *testing.T) {
	got := formatPrefixes(collapsePrefixes(mustPrefixes(t,
		"10.0.0.0/25", "10.0.0.128/25",
		"10.0.0.0/24",
		"10.0.1.0/24", "10.0.0.0/23",
		"192.168.1.0/24",
	)))
	want := []string{"10.0.0.0/23", "192.168.1.0/24"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("= %v, 期望 %v", got, want)
	}
}

func TestJSONOutputStaysCompact(t *testing.T) {

	encoded, err := json.Marshal(Candidate{Domain: "qq.com", FirstSeenAt: 1, LastSeenAt: 2, OccurrenceCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"domain":"qq.com","first_seen_at":1,"last_seen_at":2,"occurrence_count":3}`
	if string(encoded) != want {
		t.Fatalf("= %s, 期望 %s", encoded, want)
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("非法前缀 %q: %v", value, err)
		}
		out = append(out, prefix)
	}
	return out
}
