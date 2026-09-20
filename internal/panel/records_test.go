package panel

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func postAction(t *testing.T, server *Server, op, body string) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/action/"+op, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:4321"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST /api/action/%s = %d，响应 %s", op, response.Code, response.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func countRows(t *testing.T, path, query string, args ...any) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int64
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDeleteQueryRemovesExactlyThatRow(t *testing.T) {
	server := newExportServer(t)
	path := server.dbPath()

	out := postAction(t, server, "delete_query", `{"id":2}`)
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("删除失败：%v", out["message"])
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM query_events"); got != 2 {
		t.Errorf("剩 %d 条查询记录，期望 2", got)
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM query_events WHERE id = 2"); got != 0 {
		t.Error("指定的那条没被删掉")
	}
}

func TestDeleteRejectsMissingAndUnknownTargets(t *testing.T) {
	server := newExportServer(t)
	cases := map[string]struct{ op, body, want string }{
		"缺少 id":     {"delete_query", `{}`, "缺少要删除的记录 id"},
		"id 不存在":    {"delete_query", `{"id":9999}`, "已经不存在"},
		"缺少 domain": {"delete_domain", `{"domain":"   "}`, "缺少要删除的域名"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := postAction(t, server, c.op, c.body)
			if ok, _ := out["ok"].(bool); ok {
				t.Fatalf("期望失败，却返回成功：%v", out["message"])
			}
			message, _ := out["message"].(string)
			if !strings.Contains(message, c.want) {
				t.Errorf("提示是 %q，里面应该含 %q——用户得知道为什么没删成", message, c.want)
			}
		})
	}
	if got := countRows(t, server.dbPath(), "SELECT COUNT(*) FROM query_events"); got != 3 {
		t.Errorf("失败的删除不应动数据，现在剩 %d 条", got)
	}
}

func TestDeleteDomainClearsBothTablesAndNormalisesTheName(t *testing.T) {
	server := newExportServer(t)
	path := server.dbPath()

	out := postAction(t, server, "delete_domain", `{"domain":"  WWW.Example.COM.  "}`)
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("删除失败：%v", out["message"])
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM domains WHERE domain = 'www.example.com'"); got != 0 {
		t.Error("domains 里的聚合行还在")
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM query_events WHERE domain = 'www.example.com'"); got != 0 {
		t.Error("只删了聚合行，逐条查询记录还在——域名页看着没了，查询页一刷新又冒出来")
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM domains"); got != 1 {
		t.Errorf("误伤了其他域名，domains 剩 %d 行，期望 1", got)
	}
}

func TestDeleteAuditRemovesTheRowAndLeavesItsOwnTrail(t *testing.T) {
	server := newExportServer(t)
	path := server.dbPath()
	server.writeAudit("healthcheck", map[string]any{}, true, "执行成功")

	var id int64
	func() {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.QueryRow("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&id); err != nil {
			t.Fatal(err)
		}
	}()

	out := postAction(t, server, "delete_audit", `{"id":`+strconv.FormatInt(id, 10)+`}`)
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("删除失败：%v", out["message"])
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM audit_log WHERE id = ?", id); got != 0 {
		t.Error("那条审计记录还在")
	}
	if got := countRows(t, path, "SELECT COUNT(*) FROM audit_log WHERE operation = 'delete_audit'"); got != 1 {
		t.Error("删除动作本身没有留下审计——谁删了审计记录就查不出来了")
	}
}
