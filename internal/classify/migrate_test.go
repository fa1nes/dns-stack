package classify

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const legacyPythonSchema = `
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE domains (
    domain TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('cn','gfw','unknown')),
    last_check_at INTEGER,
    cname_chain_json TEXT,
    final_ips_json TEXT,
    manual_override TEXT CHECK(manual_override IN (NULL,'cn','gfw','exclude')),
    github_published INTEGER NOT NULL DEFAULT 0,
    consec_no_cn_ip INTEGER NOT NULL DEFAULT 0,
    consec_stable_gfw INTEGER NOT NULL DEFAULT 0,
    consec_cn_after_gfw INTEGER NOT NULL DEFAULT 0,
    prev_result_signature TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    consec_cn_fail INTEGER NOT NULL DEFAULT 0,
    consec_stable_cn INTEGER NOT NULL DEFAULT 0,
    last_decisive_at INTEGER,
    status_changed_at INTEGER,
    runtime_route TEXT NOT NULL DEFAULT 'unknown',
    runtime_reason TEXT,
    static_rule TEXT NOT NULL DEFAULT 'none',
    static_rule_source TEXT,
    reachability TEXT NOT NULL DEFAULT 'indeterminate',
    publication_scope TEXT NOT NULL DEFAULT 'private'
);
CREATE TABLE candidates (
    domain TEXT PRIMARY KEY,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE ip_cidrs (
    cidr TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('cn','polluted')),
    source TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(cidr, kind, source)
);
CREATE TABLE classification_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    runtime_route TEXT,
    reason TEXT
);
CREATE TABLE classification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL CHECK(mode IN ('incremental','verify','manual')),
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    requested_count INTEGER NOT NULL DEFAULT 0,
    checked_count INTEGER NOT NULL DEFAULT 0,
    changed_count INTEGER NOT NULL DEFAULT 0,
    guard_ok INTEGER NOT NULL DEFAULT 0,
    guard_json TEXT NOT NULL DEFAULT '{}',
    error TEXT
);
INSERT INTO schema_meta(key,value) VALUES('schema_version','5');
INSERT INTO schema_meta(key,value) VALUES('classification_epoch','1785195443');
INSERT INTO schema_meta(key,value) VALUES('classification_epoch_observation_id','0');
INSERT INTO domains(domain,status,static_rule,publication_scope,runtime_route,created_at,updated_at)
    VALUES('qq.com','cn','cn','public','cn',1,2);
INSERT INTO domains(domain,status,static_rule,publication_scope,runtime_route,created_at,updated_at)
    VALUES('facebook.com','gfw','foreign-dns','public','foreign',1,2);
INSERT INTO domains(domain,status,created_at,updated_at) VALUES('pending.example','unknown',1,2);
INSERT INTO candidates(domain,first_seen_at,last_seen_at) VALUES('new.example',1,2);
INSERT INTO ip_cidrs(cidr,kind,source,first_seen_at,last_seen_at)
    VALUES('1.2.3.0/24','cn','cn-direct4-apnic',1,2);
INSERT INTO classification_observations(domain,observed_at,status,runtime_route,reason)
    VALUES('qq.com',10,'cn','cn','identical_answer');
INSERT INTO classification_observations(domain,observed_at,status,runtime_route,reason)
    VALUES('facebook.com',11,'gfw','foreign','cn_view_polluted');
INSERT INTO classification_runs(mode,started_at,checked_count) VALUES('incremental',5,2);
`

func writeLegacyDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(legacyPythonSchema); err != nil {
		t.Fatalf("构造 Python 版旧库失败: %v", err)
	}
}

func TestOpeningThePythonEraDatabaseMigratesInsteadOfFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classifier.db")
	writeLegacyDB(t, path)

	store, err := OpenStore(path, func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		t.Fatalf("打开 Python 版旧库应当自动迁移，实际报错: %v", err)
	}
	defer store.Close()

	if got := store.metaInt("schema_version"); got != int64(SchemaVersion) {
		t.Errorf("迁移后 schema_version = %d，期望 %d", got, SchemaVersion)
	}

	counts, err := store.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.CN != 1 || counts.GFW != 1 || counts.Unknown != 1 {
		t.Errorf("三条域名判定必须原样保留，得到 %+v", counts)
	}
	if counts.PublicCN != 1 || counts.PublicForeign != 1 {
		t.Errorf("已发布标记必须保留，得到 %+v", counts)
	}

	cn, err := store.PublicStaticRules(RuleCN)
	if err != nil {
		t.Fatal(err)
	}
	if len(cn) != 1 || cn[0] != "qq.com" {
		t.Errorf("已发布的国内规则不能在迁移中丢失，得到 %v", cn)
	}
	gfw, err := store.PublicStaticRules(RuleForeign)
	if err != nil {
		t.Fatal(err)
	}
	if len(gfw) != 1 || gfw[0] != "facebook.com" {
		t.Errorf("已发布的被墙规则不能在迁移中丢失，得到 %v", gfw)
	}

	history, err := store.History("qq.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Reason != "identical_answer" {
		t.Errorf("旧观测记录应并轨进 observations，得到 %+v", history)
	}

	values, err := store.ActiveCIDRs("cn")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0] != "1.2.3.0/24" {
		t.Errorf("CIDR 集合应保留，得到 %v", values)
	}

	for _, table := range []string{"classification_observations", "classification_runs"} {
		if exists, err := store.tableExists(table); err != nil || exists {
			t.Errorf("旧表 %s 应当在并轨后删除 (exists=%v err=%v)", table, exists, err)
		}
	}
}

func TestMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classifier.db")
	writeLegacyDB(t, path)
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }

	first, err := OpenStore(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	before, err := first.Counts()
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	second, err := OpenStore(path, clock)
	if err != nil {
		t.Fatalf("再次打开已迁移的库不应报错: %v", err)
	}
	defer second.Close()
	after, err := second.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("重复打开改变了统计: %+v -> %+v（观测会被重复并轨）", before, after)
	}
	history, err := second.History("qq.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Errorf("重复打开后观测条数变成 %d，旧记录被并轨了两次", len(history))
	}
}

func TestFreshDatabaseSkipsTheLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	store, err := OpenStore(path, func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got := store.metaInt("schema_version"); got != int64(SchemaVersion) {
		t.Errorf("新库应直接标记为 v%d，得到 %d", SchemaVersion, got)
	}
}
