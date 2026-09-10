package panel

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newOpenServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return New(Config{
		ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath:   filepath.Join(dir, "auth.json"),
		DBPath:     filepath.Join(dir, "collector.db"),
	})
}

func localRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = "127.0.0.1:1000"
	return request
}

func serve(server *Server, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestStaticETagAndCacheHeaders(t *testing.T) {
	server := newOpenServer(t)
	first := serve(server, localRequest("GET", "/assets/panel.css"))
	checkedEqual(t, "assets 状态", first.Code, http.StatusOK)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("assets 缺少 ETag")
	}
	checkedEqual(t, "assets 缓存策略", first.Header().Get("Cache-Control"), "no-cache, must-revalidate")
	checkedEqual(t, "assets Content-Type 由扩展名推断", first.Header().Get("Content-Type"), "text/css; charset=utf-8")

	second := localRequest("GET", "/assets/panel.css")
	second.Header.Set("If-None-Match", etag)
	again := serve(server, second)
	checkedEqual(t, "If-None-Match 命中回 304", again.Code, http.StatusNotModified)
	checkedEqual(t, "304 不带响应体", again.Body.Len(), 0)

	index := serve(server, localRequest("GET", "/"))
	checkedEqual(t, "HTML 缓存策略", index.Header().Get("Cache-Control"), "no-store")
	checkedEqual(t, "HTML Content-Type", index.Header().Get("Content-Type"), "text/html; charset=utf-8")
}

func TestStaticAssetsAreCompressedOnceAndReused(t *testing.T) {
	server := newOpenServer(t)

	plain := serve(server, localRequest("GET", "/assets/panel.js"))
	checkedEqual(t, "未声明 gzip 时不压缩", plain.Header().Get("Content-Encoding"), "")

	request := localRequest("GET", "/assets/panel.js")
	request.Header.Set("Accept-Encoding", "gzip")
	zipped := serve(server, request)
	checkedEqual(t, "声明 gzip 时压缩", zipped.Header().Get("Content-Encoding"), "gzip")
	checkedEqual(t, "压缩响应带 Vary", zipped.Header().Get("Vary"), "Accept-Encoding")
	if zipped.Body.Len() >= plain.Body.Len() {
		t.Fatalf("压缩后 %d 字节，不小于原始 %d 字节", zipped.Body.Len(), plain.Body.Len())
	}

	reader, err := gzip.NewReader(bytes.NewReader(zipped.Body.Bytes()))
	if err != nil {
		t.Fatalf("压缩响应不是合法 gzip: %v", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if !bytes.Equal(decoded, plain.Body.Bytes()) {
		t.Fatal("解压后与未压缩响应不一致")
	}
	checkedEqual(t, "压缩与未压缩共用同一个 ETag",
		zipped.Header().Get("ETag"), plain.Header().Get("ETag"))

	first := assets()["assets/panel.js"]
	second := assets()["assets/panel.js"]
	if first != second {
		t.Fatal("资源缓存每次返回了新对象，说明没有被复用")
	}
	if first.compressed == nil {
		t.Fatal("panel.js 应当有预压缩副本")
	}
	if &first.compressed[0] != &second.compressed[0] {
		t.Fatal("预压缩字节被重新分配，说明压缩发生在请求路径上")
	}
}

func TestETagMatchingHandlesWeakAndList(t *testing.T) {
	cases := map[string]bool{
		`"abc"`:        true,
		`W/"abc"`:      true,
		`*`:            true,
		`"xyz", "abc"`: true,
		`"xyz"`:        false,
		``:             false,
		`"abcd"`:       false,
	}
	for header, want := range cases {
		if got := etagMatches(header, `"abc"`); got != want {
			t.Errorf("etagMatches(%q) = %v，期望 %v", header, got, want)
		}
	}
}

func TestGzipSkipsSSE(t *testing.T) {
	server := newOpenServer(t)
	plain := serve(server, localRequest("GET", "/assets/panel.css"))
	if plain.Body.Len() < gzipMinSize {
		t.Skip("内嵌资源太小，覆盖不到压缩分支")
	}

	zipped := localRequest("GET", "/assets/panel.css")
	zipped.Header.Set("Accept-Encoding", "gzip")
	packed := serve(server, zipped)
	checkedEqual(t, "声明 gzip 后压缩", packed.Header().Get("Content-Encoding"), "gzip")
	reader, err := gzip.NewReader(bytes.NewReader(packed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "解压后与原文一致", string(inflated), plain.Body.String())

	sse := localRequest("GET", "/api/queries/stream")
	sse.Header.Set("Accept-Encoding", "gzip")
	stream := serve(server, sse)
	checkedEqual(t, "SSE 不压缩", stream.Header().Get("Content-Encoding"), "")
	checkedEqual(t, "SSE 内容类型", stream.Header().Get("Content-Type"), "text/event-stream")
}

func TestLogsUnitWhitelist(t *testing.T) {
	fakeHelper(t, func(request map[string]any) map[string]any {
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": "line1\n", "stderr": ""}}
	})
	server := newOpenServer(t)
	bad := serve(server, localRequest("GET", "/api/logs?unit=nope"))
	checkedEqual(t, "未知 unit 回 400", bad.Code, http.StatusBadRequest)
	var body map[string]any
	if err := json.Unmarshal(bad.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "400 形态与 FastAPI 一致", body["detail"], "不支持的服务: nope")

	good := serve(server, localRequest("GET", "/api/logs?unit=unbound"))
	checkedEqual(t, "白名单内 unit 放行", good.Code, http.StatusOK)
}

func TestLogsStreamUnitWhitelist(t *testing.T) {
	server := newOpenServer(t)
	bad := serve(server, localRequest("GET", "/api/logs/stream?unit=nope"))
	checkedEqual(t, "流端点未知 unit 回 400", bad.Code, http.StatusBadRequest)
	checkedEqual(t, "400 不是 SSE", bad.Header().Get("Content-Type"), "application/json; charset=utf-8")
}

func TestLoginRedirectsWhenNoPassword(t *testing.T) {
	server := newOpenServer(t)
	response := serve(server, localRequest("GET", "/login"))
	checkedEqual(t, "未设密码时 /login 重定向", response.Code, http.StatusFound)
	checkedEqual(t, "目标为面板主页", response.Header().Get("Location"), "/")
}

func writeAuthFile(t *testing.T, path string) {
	t.Helper()
	record := map[string]any{"hash": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredSessionServesLoginPageWith401(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.json")
	writeAuthFile(t, auth)
	server := New(Config{ConfigPath: filepath.Join(dir, "config.env"), AuthPath: auth, DBPath: filepath.Join(dir, "collector.db")})
	response := serve(server, localRequest("GET", "/"))
	checkedEqual(t, "会话缺失回 401", response.Code, http.StatusUnauthorized)
	checkedEqual(t, "回的是登录页", response.Header().Get("Content-Type"), "text/html; charset=utf-8")
	if !bytes.Contains(response.Body.Bytes(), []byte("登录")) {
		t.Fatal("401 响应体应是 login.html 的内容")
	}
}

func TestCORSResponseHeaders(t *testing.T) {
	t.Setenv("PANEL_CORS_ORIGINS", "https://panel.example.com/")
	server := newOpenServer(t)

	request := localRequest("GET", "/api/health")
	request.Header.Set("Origin", "https://panel.example.com")
	allowed := serve(server, request)
	checkedEqual(t, "允许的来源拿到 ACAO", allowed.Header().Get("Access-Control-Allow-Origin"), "https://panel.example.com")
	checkedEqual(t, "允许凭证", allowed.Header().Get("Access-Control-Allow-Credentials"), "true")

	preflight := localRequest("OPTIONS", "/api/queries")
	preflight.Header.Set("Origin", "https://panel.example.com")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflightResp := serve(server, preflight)
	checkedEqual(t, "预检 200", preflightResp.Code, http.StatusOK)
	checkedEqual(t, "预检方法清单", preflightResp.Header().Get("Access-Control-Allow-Methods"), "GET, POST, PUT, PATCH, DELETE, OPTIONS")

	other := localRequest("GET", "/api/health")
	other.Header.Set("Origin", "https://evil.example.com")
	denied := serve(server, other)
	checkedEqual(t, "未列出的来源不发 ACAO", denied.Header().Get("Access-Control-Allow-Origin"), "")
}

func TestCORSOriginsFromConfigEnv(t *testing.T) {
	t.Setenv("PANEL_CORS_ORIGINS", "")
	dir := t.TempDir()
	config := filepath.Join(dir, "config.env")
	if err := os.WriteFile(config, []byte("PANEL_CORS_ORIGINS=https://a.example.com, https://b.example.com/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := New(Config{ConfigPath: config, AuthPath: filepath.Join(dir, "auth.json"), DBPath: filepath.Join(dir, "collector.db")})
	checkedEqual(t, "config.env 来源清单", server.corsOrigins(), []string{"https://a.example.com", "https://b.example.com"})
	checkedEqual(t, "通配来源被拒绝", New(Config{ConfigPath: filepath.Join(dir, "auth.json")}).allowedOrigin("*"), false)
}
