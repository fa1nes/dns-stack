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
	cases := []struct {
		respBy string
		rcode  int64
		want   string
	}{
		{"", rcodeNXDomain, "reject"},
		{"", rcodeRefused, "reject"},
		{"", 2, "failed"},
		{"", 0, "failed"},
		{"cache", 0, "cache"},
		{"local-unbound", 0, "cn"},
		{"foreign-hk", 0, "foreign"},
		{"alidns", 0, "unknown"},
	}
	for _, c := range cases {
		if got := ClassifyRoute(c.respBy, c.rcode); got != c.want {
			t.Errorf("ClassifyRoute(%q, %d) = %q, 期望 %q；"+
				"没有上游应答只说明这次没人回答，只有我们自己回了 NXDOMAIN 或 REFUSED "+
				"才是「已拒绝」——把 SERVFAIL 标成拒绝，面板上就会出现一堆查不出来源的「路由错误」",
				c.respBy, c.rcode, got, c.want)
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
		{"www.qq.com", "cache", "direct"},
		{"github.com", "cache", "tunnel"},
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

	for _, name := range []string{"www.qq.com", "github.com", "a.b.example"} {
		live := ClassifyExitPath(zones, name, "cn")
		cached := ClassifyExitPath(zones, name, "cache")
		if live != cached {
			t.Errorf("%s 的出口不该因为命中缓存而改变: 直查 %q vs 缓存 %q", name, live, cached)
		}
	}
	if ClassifyExitPath(zones, "github.com", "cache") == "cache" {
		t.Error("缓存命中必须落到真实出口，否则占七成的流量在出口分布里整个消失")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyExitPath(NewZoneSet(path), "www.qq.com", "cn"); got != "tunnel" {
		t.Errorf("清单缺失时 = %q，期望 tunnel", got)
	}
	if got := ClassifyExitPath(NewZoneSet(path), "www.qq.com", "cache"); got != "tunnel" {
		t.Errorf("清单缺失时缓存命中也应保守判为 tunnel，得到 %q", got)
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

	if first != 100 || last != 300 || occurrences != 3 || fails != 0 {
		t.Fatalf("聚合错误: first=%d last=%d count=%d fails=%d；"+
			"NXDOMAIN 是正确答案不是失败，不该计入 fail_count", first, last, occurrences, fails)
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
	if domains != 1 {
		t.Fatalf("domains 剩 %d 条，期望 1；"+
			"domains 必须与 query_events 用同一个留存窗口，否则域名页会列出"+
			"一堆点进去看不到任何查询记录的条目，两个页面的计数也对不上", domains)
	}
	var name string
	if err := db.QueryRow("SELECT domain FROM domains").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "fresh.example" {
		t.Fatalf("留下的应该是新鲜那条，实际 %q", name)
	}
}

func TestRunPrunesAtStartupAndNotAnHourLater(t *testing.T) {
	db, path := newTestDB(t)
	now := time.Unix(10_000_000, 0)
	stale := now.Unix() - (eventRetentionDays+1)*86400
	if err := RecordEvents(db, []Event{
		{TS: stale, Domain: "old.example", Route: "cn"},
		{TS: now.Unix(), Domain: "fresh.example", Route: "cn"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	consumer := NewConsumer(path, t.TempDir(), &bytes.Buffer{})
	consumer.now = func() time.Time { return now }
	if err := consumer.Run(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for table, want := range map[string]int64{"query_events": 1, "domains": 1} {
		var got int64
		if err := reopened.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s 剩 %d 行，期望 %d；"+
				"清理只挂在每小时的 ticker 上，重启后要等满一小时才第一次生效——"+
				"部署完面板上的数字不会变，重启比一小时更频繁时则永远不清",
				table, got, want)
		}
	}
}

func TestNXDomainIsNotAResolutionFailure(t *testing.T) {
	for rcode, want := range map[int64]bool{0: false, 3: false, 2: true, 5: true, 4: true} {
		if got := resolutionFailed(rcode); got != want {
			t.Errorf("rcode=%d 判为失败=%v，期望 %v；"+
				"只有 SERVFAIL/REFUSED 这类才是失败；NOERROR 与 NXDOMAIN 都是成功解析",
				rcode, got, want)
		}
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
	if stats.TotalDomains != 1 || stats.QueryEvents != 2 {
		t.Fatalf("落盘结果不符: %+v", stats)
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

	encoded, err := json.Marshal(Stats{TotalDomains: 1, QueryEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"total_domains":1,"query_events":2}`
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
