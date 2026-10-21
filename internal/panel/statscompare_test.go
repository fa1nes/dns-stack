package panel

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/collect"
)

func newCollectorServer(t *testing.T, now int64, events []collect.Event) *Server {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "collector.db")
	db, err := collect.OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := collect.RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}
	db.Close()
	server := New(Config{DBPath: path, StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"), AuthPath: filepath.Join(dir, "auth.json"), TOTPStepPath: filepath.Join(dir, "step")})
	server.clock = func() time.Time { return time.Unix(now, 0) }
	return server
}

func clientEvent(ts int64, respBy string, rcode int64, client, zone string) collect.Event {
	route := collect.ClassifyRoute(respBy, rcode)
	return collect.Event{TS: ts, Domain: "www.example.com", QType: 1, RCode: rcode, RespBy: respBy, Route: route,
		ExitPath: collect.ClassifyExitPath(route), ClientSubnet: client, ECSZone: zone}
}

func TestStatsComparesWithThePreviousDayOnlyWhenItWasRecorded(t *testing.T) {
	const now = 1700000000
	events := []collect.Event{
		clientEvent(now-30*3600, "cache", 0, "1.203.88.0/24", "北京电信"),
		clientEvent(now-30*3600, "local-unbound", 2, "1.203.88.0/24", "北京电信"),
		clientEvent(now-3600, "cache", 0, "111.198.122.0/24", "北京联通"),
		clientEvent(now-3500, "cache", 0, "111.198.122.0/24", "北京联通"),
		clientEvent(now-3400, "cache", 0, "10.100.0.0/24", ""),
	}
	status, out := newCollectorServer(t, now, append([]collect.Event{clientEvent(now-47*3600, "cache", 0, "", "")}, events...)).buildStats(t.Context(), "24h")
	checkedEqual(t, "status", status, http.StatusOK)
	raw, _ := json.Marshal(out["previous"])
	var previous map[string]any
	_ = json.Unmarshal(raw, &previous)
	checkedEqual(t, "前一天", map[string]any{"q": previous["queries"], "hit": previous["cache_ratio"], "fail": previous["servfail_ratio"]},
		map[string]any{"q": 3.0, "hit": 66.67, "fail": 33.33})
	checkedEqual(t, "网段带上运营商", out["top_clients"], []map[string]any{
		{"key": "111.198.122.0/24", "name": "111.198.122.0/24", "count": int64(2), "zone": "北京联通"},
		{"key": "10.100.0.0/24", "name": "10.100.0.0/24", "count": int64(1)},
	})

	_, out = newCollectorServer(t, now, events[2:]).buildStats(t.Context(), "24h")
	if _, ok := out["previous"]; ok {
		t.Fatalf("库里最早的记录晚于前一天开头，不该给出对比：%v", out["previous"])
	}
}

func TestQueryRowsCarryTheClientSubnetAndZone(t *testing.T) {
	const now = 1700000000
	server := newCollectorServer(t, now, []collect.Event{clientEvent(now-10, "cache", 0, "111.198.122.0/24", "北京联通")})
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(serve(server, localRequest(http.MethodGet, "/api/queries")).Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "客户端", map[string]any{"c": body.Items[0]["client"], "z": body.Items[0]["client_zone"]},
		map[string]any{"c": "111.198.122.0/24", "z": "北京联通"})

	if err := json.Unmarshal(serve(newExportServer(t), localRequest(http.MethodGet, "/api/queries")).Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) == 0 || body.Items[0]["client"] != "" {
		t.Fatalf("老库没有 client_subnet 列，查询列表也要照常返回：%v", body.Items)
	}
}
