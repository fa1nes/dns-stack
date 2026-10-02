package panel

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const gzipMinSize = 512

var selfStreamingPaths = []string{"/api/export"}

func streamsItsOwnBody(path string) bool {
	for _, prefix := range selfStreamingPaths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (s *Server) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/stream") || streamsItsOwnBody(r.URL.Path) ||
			!strings.HasPrefix(r.URL.Path, "/api/") || !clientAcceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		buf := &gzipBuffer{header: http.Header{}, raw: w}
		next.ServeHTTP(buf, r)
		status := buf.status
		if status == 0 {
			status = http.StatusOK
		}
		for key, values := range buf.header {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		body := buf.body.Bytes()
		if len(body) >= gzipMinSize && buf.header.Get("Content-Encoding") == "" &&
			status != http.StatusNotModified && status != http.StatusNoContent {
			var compressed bytes.Buffer
			zw := gzip.NewWriter(&compressed)
			_, _ = zw.Write(body)
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Add("Vary", "Accept-Encoding")
			w.Header().Set("Content-Length", strconv.Itoa(compressed.Len()))
			w.WriteHeader(status)
			_, _ = w.Write(compressed.Bytes())
			return
		}
		if n := buf.header.Get("Content-Length"); n != "" {
			w.Header().Set("Content-Length", n)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

type gzipBuffer struct {
	header http.Header
	status int
	body   bytes.Buffer
	raw    http.ResponseWriter
}

func (b *gzipBuffer) Unwrap() http.ResponseWriter { return b.raw }

func extendReadDeadline(w http.ResponseWriter, d time.Duration) {
	deadline := time.Time{}
	if d > 0 {
		deadline = time.Now().Add(d)
	}
	_ = http.NewResponseController(w).SetReadDeadline(deadline)
}

func (b *gzipBuffer) Header() http.Header { return b.header }

func (b *gzipBuffer) WriteHeader(status int) {

	if b.status == 0 {
		b.status = status
	}
}

func (b *gzipBuffer) Write(p []byte) (int, error) { return b.body.Write(p) }

func clientAcceptsGzip(r *http.Request) bool {
	for _, value := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.TrimSpace(strings.SplitN(value, ";", 2)[0]) == "gzip" {
			return true
		}
	}
	return false
}
