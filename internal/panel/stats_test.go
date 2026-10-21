package panel

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"
)

func TestStatsReportLeavesPrefetchOutAndSplitsLatencyByCache(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(createExportDB(t, t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,route,prefetch,elapsed_ms,exit_path) VALUES " +
		"(1700003700,'down.example.com',1,2,'local-unbound','cn',0,1500,'recursive')," +
		"(1700003701,'www.example.com',1,0,'cache','cache',0,0.4,'cache')"); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := statsReport(context.Background(), db, nil, out, 1700000000, 1700007200, 3600); err != nil {
		t.Fatal(err)
	}
	totals := out["totals"].(map[string]any)
	checkedEqual(t, "后台预取不算客户端查询", map[string]any{"q": totals["queries"], "p": totals["prefetch"]}, map[string]any{"q": 4, "p": 1})
	checkedEqual(t, "缓存与失败", map[string]any{"c": totals["cached"], "f": totals["servfail"], "slow": totals["slow_1s"]}, map[string]any{"c": 1, "f": 1, "slow": 1})
	latency := out["latency"].(map[string]any)
	checkedEqual(t, "缓存延迟落在 <1ms", latency["cache"].(map[string]any)["buckets"], []int64{1, 0, 0, 0, 0, 0, 0, 0})
	checkedEqual(t, "递归延迟 12ms 和 1500ms", latency["upstream"].(map[string]any)["buckets"], []int64{0, 0, 1, 0, 0, 0, 0, 1})
	series := out["series"].([]map[string]any)
	checkedEqual(t, "按小时分桶", map[string]any{"n": len(series), "first": series[0]["total"], "second": series[1]["total"]}, map[string]any{"n": 3, "first": 2, "second": 2})
	checkedEqual(t, "老库没有 client_subnet 列也能出报表", out["top_clients"], []any{})
	checkedEqual(t, "失败最多", out["top_failing"], []map[string]any{{"key": "down.example.com", "name": "down.example.com", "count": 1}})
}

func TestStatsRollupRescansOnlyHoursWhoseRowsChanged(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(createExportDB(t, t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const since, now = 1700000000 - 1700000000%3600, 1700000000 - 1700000000%3600 + 3*3600
	insert := func(ts int64, domain string, rcode int) {
		t.Helper()
		if _, err := db.Exec("INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,prefetch,elapsed_ms) VALUES (?,?,1,?,'local-unbound',0,30)",
			ts, domain, rcode); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 30; i++ {
		insert(since+int64(i)*300, "a.example.com", 0)
	}
	rollup := &statsRollup{}
	report := func() map[string]any {
		t.Helper()
		out := map[string]any{}
		if err := statsReport(context.Background(), db, rollup, out, since, now, 3600); err != nil {
			t.Fatal(err)
		}
		return out
	}
	var direct int64
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ? AND prefetch = 0", since).Scan(&direct); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "与直接数行一致", report()["totals"].(map[string]any)["queries"], direct)

	rollup.mu.Lock()
	firstHour := rollup.hours[since]
	rollup.mu.Unlock()
	insert(since+10, "late.example.com", 2)
	out := report()
	checkedEqual(t, "采集器补写到已结束的小时，也要算进去", out["totals"].(map[string]any)["queries"], direct+1)
	checkedEqual(t, "补写的失败进 SERVFAIL 榜", out["top_failing"], []map[string]any{{"key": "late.example.com", "name": "late.example.com", "count": 1}})
	rollup.mu.Lock()
	rescanned, kept := rollup.hours[since] != firstHour, rollup.hours[since+3600]
	rollup.mu.Unlock()
	if !rescanned {
		t.Fatal("行数变了的小时没有重扫")
	}
	report()
	rollup.mu.Lock()
	unchanged := rollup.hours[since+3600] == kept
	rollup.mu.Unlock()
	if !unchanged {
		t.Fatal("没变的小时又被重扫了一遍")
	}

	if _, err := db.Exec("DELETE FROM query_events WHERE ts >= ? AND ts < ?", since+3600, since+7200); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events WHERE ts >= ? AND prefetch = 0", since).Scan(&direct); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "删掉记录后不再算进去", report()["totals"].(map[string]any)["queries"], direct)
}

func TestStatsHourTrimKeepsTheBusiestNames(t *testing.T) {
	h := newStatsHour()
	for i := 0; i < rollupKeep+50; i++ {
		h.domains["d"+strconv.Itoa(i)+".example"] = int64(i + 1)
	}
	h.trim()
	_, keptBusiest := h.domains["d"+strconv.Itoa(rollupKeep+49)+".example"]
	_, keptQuietest := h.domains["d0.example"]
	checkedEqual(t, "只留最多的", map[string]any{"n": len(h.domains), "busiest": keptBusiest, "quietest": keptQuietest},
		map[string]any{"n": rollupKeep, "busiest": true, "quietest": false})
}
