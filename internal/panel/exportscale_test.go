package panel

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
)

func seedQueryEvents(tb testing.TB, rows int) *sql.DB {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "scale.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE query_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, domain TEXT NOT NULL, qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, resp_by TEXT NOT NULL DEFAULT '', route TEXT NOT NULL DEFAULT 'unknown', server_tag TEXT NOT NULL DEFAULT '', prefetch INTEGER NOT NULL DEFAULT 0, elapsed_ms REAL, exit_path TEXT)"); err != nil {
		tb.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		tb.Fatal(err)
	}
	statement, err := tx.Prepare("INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,route,server_tag,prefetch,elapsed_ms,exit_path) VALUES (?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		if _, err := statement.Exec(1700000000+i, fmt.Sprintf("host%d.subdomain.example.com", i), 1, 0,
			"local-unbound", "cn", "local-unbound", 0, 12.34, "direct"); err != nil {
			tb.Fatal(err)
		}
	}
	if err := statement.Close(); err != nil {
		tb.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
	return db
}

func BenchmarkExportQueriesJSON(b *testing.B) {
	for _, rows := range []int{1000, 10000} {
		db := seedQueryEvents(b, rows)
		b.Run(fmt.Sprintf("rows=%d", rows), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cursor, err := openQueryExport(context.Background(), db, exportRowLimit)
				if err != nil {
					b.Fatal(err)
				}
				counted := 0
				if err := streamExportJSON(countingWriter{&counted}, cursor); err != nil {
					b.Fatal(err)
				}
				cursor.close()
				if counted == 0 {
					b.Fatal("没有写出任何字节")
				}
			}
		})
	}
}

type writeCounter struct {
	header http.Header
	writes int
	body   bytes.Buffer
}

func (c *writeCounter) Header() http.Header { return c.header }
func (c *writeCounter) WriteHeader(int)     {}
func (c *writeCounter) Write(p []byte) (int, error) {
	c.writes++
	return c.body.Write(p)
}

func TestExportReachesTheSocketBeforeTheLastRowIsRead(t *testing.T) {
	dir := t.TempDir()
	db := seedQueryEvents(t, 20000)
	if _, err := db.Exec("VACUUM INTO 'file:" + filepath.ToSlash(filepath.Join(dir, "collector.db")) + "'"); err != nil {
		t.Fatal(err)
	}
	server := New(Config{DBPath: filepath.Join(dir, "collector.db"), StateDir: dir,
		ConfigPath: filepath.Join(dir, "config.env"), AuthPath: filepath.Join(dir, "auth.json")})

	for _, encoding := range []string{"", "gzip"} {
		request := httptest.NewRequest(http.MethodGet, "/api/export?dataset=queries&format=csv", nil)
		request.RemoteAddr = "127.0.0.1:4321"
		if encoding != "" {
			request.Header.Set("Accept-Encoding", encoding)
		}
		response := &writeCounter{header: http.Header{}}
		server.Handler().ServeHTTP(response, request)

		if response.body.Len() < 64<<10 {
			t.Fatalf("Accept-Encoding=%q 时导出只写出 %d 字节，测试数据没被读到，"+
				"下面那条断言会变成空转", encoding, response.body.Len())
		}
		if response.writes < 2 {
			t.Errorf("Accept-Encoding=%q：%d 字节的导出只经过 %d 次 Write——"+
				"说明整个响应体先被攒在内存里才发出去。浏览器永远会带 Accept-Encoding: gzip，"+
				"所以只测不带这个头的那一路等于没测；exportRowLimit=%d 时这会让面板点一下导出就占掉几百 MB",
				encoding, response.body.Len(), response.writes, exportRowLimit)
		}
	}
}

func TestExportStaysDecodableWhenTheClientAsksForGzip(t *testing.T) {
	server := newExportServer(t)
	request := httptest.NewRequest(http.MethodGet, "/api/export?dataset=queries&format=csv", nil)
	request.RemoteAddr = "127.0.0.1:4321"
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if got := response.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q，客户端要了 gzip 却没压缩", got)
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatalf("响应声明了 gzip 却解不开：%v——"+
			"导出绕过了会缓冲的 gzip 中间件，自己压缩的那一路必须仍然是合法的 gzip 流", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := exportRequest(t, server, "/api/export?dataset=queries&format=csv")
	if string(decoded) != plain.Body.String() {
		t.Fatalf("解压后与未压缩响应不一致：\n压缩路径 %q\n直连路径 %q", decoded, plain.Body.String())
	}
}

type failingWriter struct {
	header http.Header
	left   int
}

func (f *failingWriter) Header() http.Header { return f.header }
func (f *failingWriter) WriteHeader(int)     {}
func (f *failingWriter) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errors.New("客户端断开")
	}
	f.left--
	return len(p), nil
}

func TestExportTruncatedMidStreamAbortsInsteadOfLookingComplete(t *testing.T) {
	dir := t.TempDir()
	db := seedQueryEvents(t, 20000)
	if _, err := db.Exec("VACUUM INTO 'file:" + filepath.ToSlash(filepath.Join(dir, "collector.db")) + "'"); err != nil {
		t.Fatal(err)
	}
	server := New(Config{DBPath: filepath.Join(dir, "collector.db"), StateDir: dir,
		ConfigPath: filepath.Join(dir, "config.env"), AuthPath: filepath.Join(dir, "auth.json")})
	request := httptest.NewRequest(http.MethodGet, "/api/export?dataset=queries&format=csv", nil)
	request.RemoteAddr = "127.0.0.1:4321"

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Errorf("写到一半失败时 recover() = %v，期望 http.ErrAbortHandler——"+
				"流式导出没法事后改成 503，只能让连接断掉；"+
				"若在这里正常返回，客户端会把截断的 CSV 当成一份完整导出存下来", recovered)
		}
	}()
	server.Handler().ServeHTTP(&failingWriter{header: http.Header{}, left: 2}, request)
	t.Error("写出失败却正常返回了")
}

type countingWriter struct{ n *int }

func (c countingWriter) Write(p []byte) (int, error) {
	*c.n += len(p)
	return len(p), nil
}

func TestExportPeakMemoryDoesNotGrowWithRowCount(t *testing.T) {
	measure := func(rows int) uint64 {
		db := seedQueryEvents(t, rows)
		cursor, err := openQueryExport(context.Background(), db, exportRowLimit)
		if err != nil {
			t.Fatal(err)
		}
		defer cursor.close()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		counted := 0
		if err := streamExportJSON(countingWriter{&counted}, cursor); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.HeapAlloc - min(after.HeapAlloc, before.HeapAlloc)
	}
	small, large := measure(500), measure(20000)
	if large > small+4<<20 {
		t.Fatalf("导出 20000 行的常驻堆比 500 行多了 %d 字节（%d vs %d）——"+
			"导出必须边查边写，一旦把整张结果集物化成 []map[string]any，"+
			"exportRowLimit=%d 就会在面板点一下导出时吃掉几百 MB，"+
			"这正是 2026-09-07 那次 OOM 的形状", large-small, small, large, exportRowLimit)
	}
}
