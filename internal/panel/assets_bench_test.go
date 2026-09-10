package panel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	webfs "github.com/dns-stack/dns-stack/web"
)

func BenchmarkStaticPerRequestWork(b *testing.B) {
	for i := 0; i < b.N; i++ {
		data, err := fs.ReadFile(webfs.Files, "assets/panel.js")
		if err != nil {
			b.Fatal(err)
		}
		sum := sha256.Sum256(data)
		_ = `"` + hex.EncodeToString(sum[:8]) + `"`
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(data)
		_ = zw.Close()
		_ = buf.Bytes()
	}
}

func BenchmarkStaticCachedLookup(b *testing.B) {
	assets()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item := assets()["assets/panel.js"]
		if item == nil || item.compressed == nil {
			b.Fatal("缓存未命中")
		}
	}
}

func BenchmarkStaticHandler(b *testing.B) {
	dir := b.TempDir()
	server := New(Config{ConfigPath: dir + "/config.env", AuthPath: dir + "/auth.json", DBPath: dir + "/collector.db"})
	handler := server.Handler()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := httptest.NewRequest("GET", "/assets/panel.js", nil)
		request.RemoteAddr = "127.0.0.1:1000"
		request.Header.Set("Accept-Encoding", "gzip")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			b.Fatalf("状态 %d", response.Code)
		}
	}
}
