package panel

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func cnResolverServer(t *testing.T, files map[string]string) *Server {
	t.Helper()
	dir := t.TempDir()
	files["config.env"] = "ROLE=cn-resolver\n"
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath: filepath.Join(dir, "auth.json"), DBPath: filepath.Join(dir, "collector.db")})
}

func TestRouteListsAreReadAndChangedThroughTheHelper(t *testing.T) {
	server := cnResolverServer(t, map[string]string{
		"manual-cn-zones.txt": "# 注释\nsb.sb\n",
		"manual-gfw.txt":      "google.com\n",
	})
	fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": "已生效"}}
	})
	var listed map[string]any
	_ = json.Unmarshal(serve(server, localRequest("GET", "/api/access")).Body.Bytes(), &listed)
	if cn, _ := listed["route_cn"].([]any); len(cn) != 1 || cn[0] != "sb.sb" {
		t.Fatalf("国内解析名单读成了 %v", listed["route_cn"])
	}
	if hk, _ := listed["route_hk"].([]any); len(hk) != 1 || hk[0] != "google.com" {
		t.Fatalf("香港解析名单读成了 %v", listed["route_hk"])
	}

	calls := fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": "已生效"}}
	})
	post := func(body string) int {
		response := httptest.NewRecorder()
		server.accessMutate(response, httptest.NewRequest("POST", "/api/access", strings.NewReader(body)))
		return response.Code
	}
	if got := post(`{"action":"route_add","list":"gfw","domains":["x.com"]}`); got != 400 {
		t.Fatalf("未知名单应当 400，得到 %d", got)
	}
	if got := post(`{"action":"route_add","list":"cn","domains":["example.com"]}`); got != 200 {
		t.Fatalf("加入国内解析得到 %d", got)
	}
	got := calls()
	args, _ := got[0]["args"].(map[string]any)
	if len(got) != 1 || got[0]["op"] != "route_add" || args["list"] != "cn" {
		t.Fatalf("应当交给 helper 的 route_add 并带上名单，实际 %v", got)
	}
}

func TestAHalfDoneListChangeShowsWhyItFailed(t *testing.T) {
	server := cnResolverServer(t, map[string]string{})
	fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 1,
			"stdout": "已加入国内解析：sb.sb", "stderr": "[错误] 重建国内权威路由失败，名单已保存"}}
	})
	response := httptest.NewRecorder()
	server.accessMutate(response, httptest.NewRequest("POST", "/api/access",
		strings.NewReader(`{"action":"route_add","list":"cn","domains":["sb.sb"]}`)))
	var out map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &out)
	if out["ok"] != false || !strings.Contains(out["message"].(string), "重建国内权威路由失败") {
		t.Fatalf("失败时只给出了「已加入」，看不出卡在哪：%v", out)
	}
}

func TestClearingTheAuditLogLeavesItEmpty(t *testing.T) {
	dir := t.TempDir()
	server := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath: filepath.Join(dir, "auth.json"), DBPath: filepath.Join(dir, "collector.db")})
	server.writeAudit("backup", nil, true, "之前的记录")
	fakeHelper(t, func(map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": "已清空"}}
	})
	_ = os.Remove(server.cfg.DBPath)
	request := localRequest("POST", "/api/action/clear_audit")
	request.Body = httptest.NewRequest("POST", "/", strings.NewReader(`{"confirm":true}`)).Body
	serve(server, request)
	var out map[string]any
	_ = json.Unmarshal(serve(server, localRequest("GET", "/api/audit")).Body.Bytes(), &out)
	if items, _ := out["items"].([]any); len(items) != 0 {
		t.Fatalf("清空审计记录之后列表里还剩 %v——第一条就是「清空审计记录」本身", items)
	}
}

func TestEveryAuditedOperationHasAReadableName(t *testing.T) {
	sources, _ := filepath.Glob("*.go")
	literal := regexp.MustCompile(`(?:writeAudit|commitAuthUpdate|commitAuthUpdateRaw)\(.*?"([a-z_]+)"\s*[,)]`)
	seen := 0
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllStringSubmatch(string(body), -1) {
			seen++
			if auditLabel(m[1], "") == m[1] {
				t.Errorf("%s 写进审计却没有中文名，审计页上只会显示 %s", m[1], m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("一处写审计的地方都没找到，测试本身失效了")
	}
	for op := range operationSpecs {
		if auditLabel(op, "") == op {
			t.Errorf("%s 在审计页上没有中文名", op)
		}
	}
	if got := auditLabel("route_add", `{"list":"cn","domains":["sb.sb"]}`); got != "加入国内解析" {
		t.Errorf("分流名单的审计要说清是哪张名单，得到 %q", got)
	}
}

func TestCertInfoCarriesDaysLeftAndAddresses(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	info := parseCertInfo("notAfter=Oct  8 00:00:00 2026 GMT\nnotBefore=Oct  1 00:00:00 2026 GMT\n"+
		"issuer=C = US, O = Let's Encrypt, CN = E6\nX509v3 Subject Alternative Name: critical\n    IP Address:203.0.113.1\n", now)
	if info["days_left"] != 5 || info["san"] != "203.0.113.1" || info["issuer"] != "C = US, O = Let's Encrypt, CN = E6" {
		t.Fatalf("证书卡片读 days_left 和 san，接口却不给：%v", info)
	}
}
