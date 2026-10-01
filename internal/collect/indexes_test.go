package collect

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func eventIndexes(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='query_events'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	return out
}

func TestUnreadableSchemaVersionNeverWipesFailCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO domains(domain,first_seen_at,last_seen_at,occurrence_count,fail_count) VALUES ('flaky.example',1,2,9,7)",
		"UPDATE schema_meta SET value = 'garbled' WHERE key = 'schema_version'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	if reopened, err := OpenDB(path); err == nil {
		reopened.Close()
		t.Error("schema_version 读不出来时 OpenDB 应当报错，而不是把它当成「旧库」继续迁移")
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var fails int
	if err := raw.QueryRow("SELECT fail_count FROM domains WHERE domain='flaky.example'").Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 7 {
		t.Errorf("fail_count = %d，期望 7——读版本号出错时 stored 停在 0，"+
			"看起来就像迁移前的旧库，于是全部域名的累计失败数被清零", fails)
	}
}

func TestIndexesNoQueryCanUseAreDroppedFromExistingDatabases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	legacy, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE TABLE query_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, domain TEXT NOT NULL, qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, resp_by TEXT NOT NULL DEFAULT '', route TEXT NOT NULL DEFAULT 'unknown', server_tag TEXT NOT NULL DEFAULT '', prefetch INTEGER NOT NULL DEFAULT 0, elapsed_ms REAL, exit_path TEXT, client_subnet TEXT, ecs_zone TEXT, kind TEXT)",
		"CREATE INDEX idx_events_kind ON query_events(kind, ts)",
		"CREATE INDEX idx_events_domain_elapsed ON query_events(domain, elapsed_ms) WHERE elapsed_ms IS NOT NULL",
		"INSERT INTO query_events(ts,domain,qtype,rcode,kind) VALUES (1700000000,'kept.example',1,0,'cache')",
	} {
		if _, err := legacy.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	legacy.Close()

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB 在带旧索引的库上失败: %v", err)
	}
	defer db.Close()
	present := eventIndexes(t, db)
	for _, name := range []string{"idx_events_kind", "idx_events_domain_elapsed"} {
		if present[name] {
			t.Errorf("%s 仍在库里——生产快照上 34 条 SQL 没有一条的查询计划选中它，"+
				"它只是让每次写入多维护一棵 B 树", name)
		}
	}
	for _, name := range []string{"idx_events_ts", "idx_events_domain", "idx_events_route", "idx_events_rcode", "idx_events_exit", "idx_events_elapsed"} {
		if !present[name] {
			t.Errorf("%s 不见了——它有查询在用（route/rcode/exit 还是时间窗口聚合的覆盖索引），删掉会让对应查询退回全表扫描", name)
		}
	}
	var kept int
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events WHERE domain='kept.example'").Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("删索引不能动数据，kept.example 剩 %d 行 (%v)", kept, err)
	}
}
