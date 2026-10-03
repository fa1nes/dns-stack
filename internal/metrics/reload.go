package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ReloadURL = "http://127.0.0.1:8888/ctl/reload"

var FlushURL = "http://127.0.0.1:8888/ctl/flush"

func get(ctx context.Context, target string) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func Reload(ctx context.Context) int {
	code, _ := get(ctx, ReloadURL)
	return code
}

func FlushCache(ctx context.Context, domain string) (int, error) {
	target := FlushURL
	if domain != "" {
		target += "?domain=" + url.QueryEscape(domain)
	}
	code, body := get(ctx, target)
	switch code {
	case http.StatusOK:
		removed, err := strconv.Atoi(body)
		if err != nil {
			return 0, fmt.Errorf("mosproxy 清缓存返回了看不懂的内容: %q", body)
		}
		return removed, nil
	case 0:
		return 0, fmt.Errorf("连不上 mosproxy 管理接口")
	case http.StatusNotFound:
		return 0, fmt.Errorf("mosproxy 版本太旧，没有清缓存接口（需要 v0.2.1 以上）")
	default:
		return 0, fmt.Errorf("mosproxy 清缓存返回 HTTP %d: %s", code, body)
	}
}
