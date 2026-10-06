package panel

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTwentyFourHourViewsStartNoEarlierThanTheArchitectureEpoch(t *testing.T) {
	server := newExportServer(t)
	server.clock = func() time.Time { return time.Unix(1700000100, 0) }
	if err := os.WriteFile(server.statePath("architecture-epoch"), []byte("1700000003\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var collected map[string]any
	if err := json.Unmarshal(exportRequest(t, server, "/api/collected").Body.Bytes(), &collected); err != nil {
		t.Fatal(err)
	}
	if got := collected["queries_24h"]; got != float64(1) {
		t.Errorf("/api/collected queries_24h = %v, 期望 1——重设统计起点之前的请求不该再计入", got)
	}

	var summary map[string]any
	if err := json.Unmarshal(exportRequest(t, server, "/api/domains/summary").Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	exits, _ := summary["by_exit"].([]any)
	if len(exits) != 1 || exits[0].(map[string]any)["path"] != "tunnel" {
		t.Errorf("/api/domains/summary by_exit = %v, 期望只剩起点之后那条 tunnel——"+
			"两个页面并排显示「近 24 小时」，窗口起点不一致时同一个数字会对不上", exits)
	}

}

func TestFailingDomainsListStartsAtTheArchitectureEpoch(t *testing.T) {
	server := newExportServer(t)
	server.clock = func() time.Time { return time.Unix(1700000100, 0) }
	if err := os.WriteFile(server.statePath("architecture-epoch"), []byte("1700000050\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(server.cfg.DBPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,route) VALUES (1700000010,'before.example',1,2,'','failed')",
		"INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,route) VALUES (1700000060,'after.example',1,2,'','failed')",
		"INSERT INTO domains(domain,first_seen_at,last_seen_at,occurrence_count,fail_count) VALUES ('before.example',1700000010,1700000010,1,1)",
		"INSERT INTO domains(domain,first_seen_at,last_seen_at,occurrence_count,fail_count) VALUES ('after.example',1700000060,1700000060,1,1)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	var failing map[string]any
	if err := json.Unmarshal(exportRequest(t, server, "/api/domains?metric=fail").Body.Bytes(), &failing); err != nil {
		t.Fatal(err)
	}
	var listed []string
	items, _ := failing["items"].([]any)
	for _, item := range items {
		listed = append(listed, item.(map[string]any)["domain"].(string))
	}
	if len(listed) != 1 || listed[0] != "after.example" {
		t.Errorf("失败榜 = %v，期望只有起点之后失败的 after.example——"+
			"按 now-24h 算的话，重设统计起点之前的失败还会一直挂在榜上，和旁边的汇总数字对不上", listed)
	}
}
