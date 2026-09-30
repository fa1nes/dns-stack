package panel

import (
	"encoding/json"
	"os"
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
