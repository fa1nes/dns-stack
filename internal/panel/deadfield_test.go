package panel

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func assertFrontendReads(t *testing.T, route string, keys []string, frontend string) {
	t.Helper()
	for _, key := range keys {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `\b`).MatchString(frontend) {
			t.Errorf("%s 每次都带上 %s，前端却从来不读它——"+
				"删掉一个功能之后，它在接口里的字段最容易留下来，"+
				"面板上看不见，只在流量和维护成本里", route, key)
		}
	}
}

func frontendText(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, path := range []string{"../../web/assets/panel.js", "../../web/index.html", "../../web/login.html"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("读不到前端资源 %s: %v", path, err)
		}
		all.Write(body)
		all.WriteByte('\n')
	}
	return all.String()
}

func TestRulesInfoShipsNothingTheFrontendIgnores(t *testing.T) {
	dir := t.TempDir()
	server := New(Config{
		StateDir:   dir,
		ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath:   filepath.Join(dir, "auth.json"),
		DBPath:     filepath.Join(dir, "collector.db"),
	})
	frontend := frontendText(t)
	keys := make([]string, 0, len(server.rulesInfo()))
	for key := range server.rulesInfo() {
		keys = append(keys, key)
	}
	assertFrontendReads(t, "/api/rules", keys, frontend)
}

func latencyDB(t *testing.T, rows int) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "latency.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(
		"CREATE TABLE query_events (id INTEGER PRIMARY KEY, ts INTEGER, elapsed_ms REAL)"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare("INSERT INTO query_events (ts, elapsed_ms) VALUES (?, ?)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		if _, err := stmt.Exec(1000+i, float64(i%400)); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestLatencyStatsShipsNothingTheFrontendIgnores(t *testing.T) {
	frontend := frontendText(t)
	for name, rows := range map[string]int{"全量": 50, "抽样": latencySampleCap + 1} {
		t.Run(name, func(t *testing.T) {
			stats := latencyStats(latencyDB(t, rows), 0)
			keys := make([]string, 0, len(stats))
			for key := range stats {
				keys = append(keys, key)
			}
			assertFrontendReads(t, "/api/overview.latency", keys, frontend)
		})
	}
}

func TestLatencyStatsAnnouncesWhenQuantilesAreSampled(t *testing.T) {
	small := latencyStats(latencyDB(t, 50), 0)
	if small["sampled"] != false {
		t.Errorf("只有 50 条时 sampled=%v，应当是 false", small["sampled"])
	}
	if _, ok := small["sampled_from"]; ok {
		t.Error("没抽样却报了 sampled_from，前端会显示一句没有意义的说明")
	}

	big := latencyStats(latencyDB(t, latencySampleCap+1), 0)
	if big["sampled"] != true {
		t.Fatalf("超过 %d 条时 sampled=%v，应当是 true", latencySampleCap, big["sampled"])
	}
	if got := big["sampled_from"]; got != int64(latencySampleCap) {
		t.Errorf("sampled_from=%v，应当是实际参与分位数计算的 %d 条——"+
			"samples 是总数，两者不是一回事，前端拿错了就会把「取最近一万条」说成「取全部」",
			got, latencySampleCap)
	}
	if big["samples"] != int64(latencySampleCap+1) {
		t.Errorf("samples=%v，应当仍是总数 %d", big["samples"], latencySampleCap+1)
	}
}
