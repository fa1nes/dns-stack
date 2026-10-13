package panel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func journalLine(t *testing.T, unit, ident, message string, usec int64) string {
	t.Helper()
	rec := map[string]any{"MESSAGE": message, "PRIORITY": "6", "SYSLOG_IDENTIFIER": ident,
		"__REALTIME_TIMESTAMP": strconv.FormatInt(usec, 10), "__CURSOR": "s=" + strconv.FormatInt(usec, 10)}
	if ident == "systemd" {
		rec["_SYSTEMD_UNIT"], rec["UNIT"] = "init.scope", unit+".service"
	} else {
		rec["_SYSTEMD_UNIT"] = unit + ".service"
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJournalEntriesFromProductionShapes(t *testing.T) {
	stdout := strings.Join([]string{
		journalLine(t, "mosproxy", "dns-stack-go", `{"level":"warn","module":"server_http","server_tag":"doh-in","request":{"proto":"HTTP/2.0","method":"GET","url":"/favicon.ico","ua":"Mozilla/5.0","remote":"178.62.x.x:50960"},"time":1,"message":"invalid path"}`, 5_000_000),
		journalLine(t, "mosproxy", "dns-stack-go", `{"level":"error","module":"upstream","upstream_tag":"local-unbound","time":1,"message":"upstream offline"}`, 4_000_000),
		journalLine(t, "unbound", "unbound", `[1785577614] unbound[454285:0] warning: subnetcache: prefetch is set but not working`, 3_000_000),
		journalLine(t, "dns-stack-panel", "dns-stack-go", `2026/10/13 13:55:01 http: TLS handshake error from 66.132.x.x:7970: tls: client offered only unsupported versions: [301]`, 2_000_000),
		journalLine(t, "dns-stack-panel", "dns-stack-go", `[错误] 读不到配置文件: /etc/dns-stack/config.env`, 1_500_000),
		journalLine(t, "dns-stack-recursive-routing", "systemd", `Failed to start dns-stack-recursive-routing.service - dns-stack 递归出口按目标 IP 分流.`, 1_000_000),
		journalLine(t, "mosproxy", "dns-stack-go", `{"level":"info","module":"upstream","upstream_tag":"local-unbound","time":1,"message":"health check ping succeed"}`, 6_000_000),
		journalLine(t, "dns-stack-routing-watchdog", "systemd", `Starting dns-stack-routing-watchdog.service - dns-stack 递归出口分流存活看门狗...`, 7_000_000),
		journalLine(t, "dns-stack-routing-watchdog", "systemd", `dns-stack-routing-watchdog.service: Deactivated successfully.`, 7_100_000),
		journalLine(t, "dns-stack-panel", "systemd", `Started dns-stack-panel.service - dns-stack 中文管理面板.`, 7_200_000),
		`{"MESSAGE":"cut`,
	}, "\n")
	got := parseJournal(stdout)
	want := []struct {
		unit  string
		level int
		noise bool
		msg   string
	}{
		{"dns-stack-recursive-routing", 2, false, "Failed to start"},
		{"dns-stack-panel", 2, false, "读不到配置文件: /etc/dns-stack/config.env"},
		{"dns-stack-panel", 0, true, "http: TLS handshake error"},
		{"unbound", 1, false, "subnetcache: prefetch is set but not working"},
		{"mosproxy", 2, false, "[upstream] upstream offline upstream_tag=local-unbound"},
		{"mosproxy", 0, true, "[server_http] invalid path method=GET proto=HTTP/2.0 remote=178.62.x.x:50960 url=/favicon.ico server_tag=doh-in"},
		{"mosproxy", 0, false, "[upstream] health check ping succeed upstream_tag=local-unbound"},
		{"dns-stack-routing-watchdog", 0, true, "Starting dns-stack-routing-watchdog.service"},
		{"dns-stack-routing-watchdog", 0, true, "dns-stack-routing-watchdog.service: Deactivated successfully."},
		{"dns-stack-panel", 0, false, "Started dns-stack-panel.service"},
	}
	if len(got) != len(want) {
		t.Fatalf("条数 %d，想要 %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		e := got[i]
		if e.Unit != w.unit || e.Level != w.level || e.Noise != w.noise || !strings.HasPrefix(e.Msg, w.msg) {
			t.Errorf("第 %d 条 = {%s %d %v %q}，想要 {%s %d %v %q…}", i, e.Unit, e.Level, e.Noise, e.Msg, w.unit, w.level, w.noise, w.msg)
		}
		if i > 0 && got[i-1].T > e.T {
			t.Errorf("没按时间排序: %d > %d", got[i-1].T, e.T)
		}
	}
	if got[0].T != 1000 {
		t.Errorf("时间戳应当是毫秒: %d", got[0].T)
	}
}

func TestLogsMergesAllWatchedUnits(t *testing.T) {
	calls := fakeHelper(t, func(request map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": "", "stderr": ""}}
	})
	server := newOpenServer(t)
	res := serve(server, localRequest("GET", "/api/logs?lines=500"))
	checkedEqual(t, "合并视图 200", res.Code, http.StatusOK)
	sent := calls()
	if len(sent) != 1 {
		t.Fatalf("应当一次 helper 调用: %v", sent)
	}
	args, _ := sent[0]["args"].(map[string]any)
	units, _ := args["units"].([]any)
	if len(units) != len(server.watchedUnits()) || len(units) < 2 {
		t.Fatalf("应当带上全部受监视的服务: %v", units)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if entries, ok := body["entries"].([]any); !ok || entries == nil {
		t.Errorf("空日志也要回空数组: %v", body)
	}
}
