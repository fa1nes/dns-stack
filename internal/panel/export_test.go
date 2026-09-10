package panel

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createExportDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "collector.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements := []string{
		"CREATE TABLE query_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, domain TEXT NOT NULL, qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, resp_by TEXT NOT NULL DEFAULT '', route TEXT NOT NULL DEFAULT 'unknown', server_tag TEXT NOT NULL DEFAULT '', prefetch INTEGER NOT NULL DEFAULT 0, elapsed_ms REAL, exit_path TEXT)",
		"CREATE TABLE domains (domain TEXT PRIMARY KEY, first_seen_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, occurrence_count INTEGER NOT NULL DEFAULT 0, last_rcode INTEGER, last_route TEXT, fail_count INTEGER NOT NULL DEFAULT 0)",
		"INSERT INTO query_events(id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path) VALUES (1,1700000001,'www.example.com',1,0,'cache','cache','cache',1,5.0,NULL)",
		"INSERT INTO query_events(id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path) VALUES (2,1700000002,'api.example.net',28,3,'local-unbound','cn','local-unbound',0,12.34,'direct')",
		`INSERT INTO query_events(id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path) VALUES (3,1700000003,'we"ird,example.org',99,0,'local-unbound','foreign','foreign-hk',0,NULL,'tunnel')`,
		"INSERT INTO domains(domain,first_seen_at,last_seen_at,occurrence_count,last_rcode,last_route,fail_count) VALUES ('www.example.com',1700000000,1700000100,42,0,'cn',1)",
		"INSERT INTO domains(domain,first_seen_at,last_seen_at,occurrence_count,last_rcode,last_route,fail_count) VALUES ('api.example.net',1699999000,1700000200,7,NULL,NULL,0)",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func newExportServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return New(Config{DBPath: createExportDB(t, dir), StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"), AuthPath: filepath.Join(dir, "auth.json"), TOTPStepPath: filepath.Join(dir, "step")})
}

func exportRequest(t *testing.T, server *Server, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.RemoteAddr = "127.0.0.1:4321"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestExportQueriesCSVBytes(t *testing.T) {
	response := exportRequest(t, newExportServer(t), "/api/export?dataset=queries&format=csv")
	checkedEqual(t, "status", response.Code, 200)
	checkedEqual(t, "content type", response.Header().Get("Content-Type"), "text/csv; charset=utf-8")
	checkedEqual(t, "disposition", response.Header().Get("Content-Disposition"), `attachment; filename="dns-stack-queries.csv"`)
	want := "id,ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path,qtype_name,rcode_name,route_name,cache_hit\n" +
		"1,1700000001,www.example.com,1,0,cache,cache,cache,true,5,,A,NOERROR,缓存命中,true\n" +
		"2,1700000002,api.example.net,28,3,local-unbound,cn,local-unbound,false,12.34,direct,AAAA,NXDOMAIN,本机递归,false\n" +
		"3,1700000003,\"we\"\"ird,example.org\",99,0,local-unbound,foreign,foreign-hk,false,,tunnel,SPF,NOERROR,香港递归,false\n"
	checkedEqual(t, "csv bytes", response.Body.String(), want)
}

func TestExportQueriesJSON(t *testing.T) {
	response := exportRequest(t, newExportServer(t), "/api/export?dataset=queries")
	checkedEqual(t, "status", response.Code, 200)
	checkedEqual(t, "content type", response.Header().Get("Content-Type"), "application/json; charset=utf-8")
	checkedEqual(t, "disposition", response.Header().Get("Content-Disposition"), `attachment; filename="dns-stack-queries.json"`)
	var items []map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "row count", len(items), 3)
	checkedEqual(t, "first row", items[0], map[string]any{"id": 1, "ts": 1700000001, "domain": "www.example.com", "qtype": 1, "qtype_name": "A", "rcode": 0, "rcode_name": "NOERROR", "resp_by": "cache", "route": "cache", "route_name": "缓存命中", "server_tag": "cache", "prefetch": true, "cache_hit": true, "elapsed_ms": 5})
	checkedEqual(t, "null fields omitted", map[string]any{"elapsed": items[2]["elapsed_ms"], "exit": items[0]["exit_path"]}, map[string]any{"elapsed": nil, "exit": nil})
	checkedEqual(t, "spf name", items[2]["qtype_name"], "SPF")

	if !strings.HasPrefix(response.Body.String(), `[{"cache_hit":true,"domain":"www.example.com"`) {
		t.Fatalf("unexpected JSON byte layout: %s", response.Body.String())
	}
	if !strings.HasSuffix(response.Body.String(), "\n") {
		t.Fatal("export JSON must end with newline")
	}
}

func TestExportDomainsCSVBytes(t *testing.T) {
	response := exportRequest(t, newExportServer(t), "/api/export?dataset=domains&format=csv")
	checkedEqual(t, "status", response.Code, 200)
	checkedEqual(t, "content type", response.Header().Get("Content-Type"), "text/csv; charset=utf-8")
	checkedEqual(t, "disposition", response.Header().Get("Content-Disposition"), `attachment; filename="dns-stack-domains.csv"`)
	want := "domain,first_seen_at,last_seen_at,occurrence_count,fail_count,last_rcode,last_route,last_rcode_name,last_route_name\n" +
		"www.example.com,1700000000,1700000100,42,1,0,cn,NOERROR,本机递归\n" +
		"api.example.net,1699999000,1700000200,7,0,,,,未知\n"
	checkedEqual(t, "csv bytes", response.Body.String(), want)
}

func TestExportTruncation(t *testing.T) {
	dir := t.TempDir()
	path := createExportDB(t, dir)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	items, err := exportQueryItems(db, 2)
	if err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "truncated to limit", len(items), 2)
	checkedEqual(t, "ascending order", []any{items[0]["id"], items[1]["id"]}, []any{1, 2})
	domains, err := exportDomainItems(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "domain truncation", len(domains), 1)
	checkedEqual(t, "highest count first", domains[0]["domain"], "www.example.com")
}

func TestExportBadParams(t *testing.T) {
	server := newExportServer(t)
	for _, tc := range []struct{ target, body string }{
		{"/api/export", `{"error":"不支持的 dataset 参数"}`},
		{"/api/export?dataset=nope", `{"error":"不支持的 dataset 参数"}`},
		{"/api/export?dataset=queries&format=xml", `{"error":"不支持的 format 参数"}`},
		{"/api/export?dataset=rules&format=csv", `{"error":"不支持的 format 参数"}`},
	} {
		response := exportRequest(t, server, tc.target)
		checkedEqual(t, "status "+tc.target, response.Code, 400)
		checkedEqual(t, "body "+tc.target, strings.TrimSpace(response.Body.String()), tc.body)
	}
}

func TestExportRulesJSON(t *testing.T) {
	server := newExportServer(t)
	if err := os.WriteFile(filepath.Join(server.cfg.StateDir, "cn.txt"), []byte("example.com\n# 注释\n\nexample.net\n"), 0600); err != nil {
		t.Fatal(err)
	}
	response := exportRequest(t, server, "/api/export?dataset=rules&format=json")
	checkedEqual(t, "status", response.Code, 200)
	checkedEqual(t, "content type", response.Header().Get("Content-Type"), "application/json; charset=utf-8")
	checkedEqual(t, "disposition", response.Header().Get("Content-Disposition"), `attachment; filename="dns-stack-rules.json"`)
	var info map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "cn count", info["cn_count"], 2)
	checkedEqual(t, "gfw count", info["gfw_count"], 0)
}
