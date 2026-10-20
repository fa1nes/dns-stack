package panel

import (
	"context"
	"database/sql"
	"path/filepath"
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
	if err := statsReport(context.Background(), db, out, 1700000000, 1700007200, 3600); err != nil {
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
