package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFlushCacheAsksForTheDomainAndReportsOldBinaries(t *testing.T) {
	var asked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RawQuery
		_, _ = w.Write([]byte("3"))
	}))
	defer server.Close()
	previous := FlushURL
	defer func() { FlushURL = previous }()

	FlushURL = server.URL + "/ctl/flush"
	removed, err := FlushCache(context.Background(), "sb.sb")
	if err != nil || removed != 3 || asked != "domain=sb.sb" {
		t.Fatalf("FlushCache = %d, %v, 查询串 %q", removed, err, asked)
	}
	if _, err := FlushCache(context.Background(), ""); err != nil || asked != "" {
		t.Fatalf("不带域名应当清空全部，实际查询串 %q, %v", asked, err)
	}

	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	FlushURL = old.URL + "/ctl/flush"
	if _, err := FlushCache(context.Background(), "sb.sb"); err == nil || !strings.Contains(err.Error(), "v0.2.1") {
		t.Fatalf("旧版 mosproxy 没有这个接口时应当说清楚原因，实际 %v", err)
	}
}
