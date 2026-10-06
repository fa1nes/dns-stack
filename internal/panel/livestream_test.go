package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type streamMessage struct {
	id      string
	events  []map[string]any
	skipped float64
}

func streamMessages(t *testing.T, body string) []streamMessage {
	t.Helper()
	var out []streamMessage
	for _, block := range strings.Split(body, "\n\n") {
		var msg streamMessage
		var data string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "id: "):
				msg.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		if data == "" {
			continue
		}
		var payload struct {
			Events  []map[string]any `json:"events"`
			Skipped float64          `json:"skipped"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("流里的 data 不是 JSON: %q", data)
		}
		msg.events, msg.skipped = payload.Events, payload.Skipped
		out = append(out, msg)
	}
	return out
}

func openStream(t *testing.T, server *Server, target string, header map[string]string) []streamMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	request := localRequest(http.MethodGet, target).WithContext(ctx)
	for key, value := range header {
		request.Header.Set(key, value)
	}
	return streamMessages(t, serve(server, request).Body.String())
}

func eventIDs(messages []streamMessage) []int {
	var ids []int
	for _, msg := range messages {
		for _, event := range msg.events {
			ids = append(ids, int(event["id"].(float64)))
		}
	}
	return ids
}

func TestQueryStreamResumesFromLastEventID(t *testing.T) {
	messages := openStream(t, newExportServer(t), "/api/queries/stream", map[string]string{"Last-Event-ID": "1"})
	if got := fmt.Sprint(eventIDs(messages)); got != "[2 3]" {
		t.Fatalf("断线重连带 Last-Event-ID: 1，补发的是 %s，期望 [2 3]——不续传的话断线期间的请求全部丢失", got)
	}
	if messages[len(messages)-1].id != "3" {
		t.Errorf("最后一条消息的 id 是 %q，期望 3；没有 id 浏览器重连时就带不回断点", messages[len(messages)-1].id)
	}
}

func TestQueryStreamFiltersOnTheServer(t *testing.T) {
	messages := openStream(t, newExportServer(t), "/api/queries/stream?after_id=1&route=foreign", nil)
	if got := fmt.Sprint(eventIDs(messages)); got != "[3]" {
		t.Fatalf("按 route=foreign 过滤后推送了 %s，期望只有 [3]", got)
	}
}

func TestQueryStreamSkipsAheadInsteadOfFallingBehind(t *testing.T) {
	server := newExportServer(t)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(server.cfg.DBPath))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if _, err := db.Exec("INSERT INTO query_events(ts,domain,qtype,rcode,resp_by,route) VALUES (1700000100,'burst.example',1,0,'cache','cache')"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	messages := openStream(t, server, "/api/queries/stream?after_id=1", nil)
	ids := eventIDs(messages)
	if len(messages) != 1 || len(ids) != streamBatchCap {
		t.Fatalf("一次积压 252 条，收到 %d 条消息 / %d 行，期望 1 条消息、%d 行", len(messages), len(ids), streamBatchCap)
	}
	if ids[0] != 54 || ids[len(ids)-1] != 253 {
		t.Errorf("推送的是 id %d..%d，期望最新的 54..253；从旧往新追，流量一大就永远追不上", ids[0], ids[len(ids)-1])
	}
	if messages[0].skipped != 52 {
		t.Errorf("skipped = %v，期望 52；跳过了却不说，页面看起来就像没有这些请求", messages[0].skipped)
	}
}

func TestOverviewIsComputedOnceForEveryTabThatAsksAtOnce(t *testing.T) {
	var cache sharedResult
	var computed atomic.Int32
	release := make(chan struct{})
	compute := func() (int, []byte) {
		computed.Add(1)
		<-release
		return http.StatusOK, []byte("{}\n")
	}
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := cache.get(context.Background(), now, overviewShareTTL, compute); status != http.StatusOK {
				t.Errorf("status = %d", status)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := computed.Load(); n != 1 {
		t.Fatalf("8 个标签页同时刷新，概览算了 %d 次；每次都要拉起两个 root 子进程", n)
	}
	cache.get(context.Background(), now.Add(overviewShareTTL/2), overviewShareTTL, compute)
	if n := computed.Load(); n != 1 {
		t.Fatalf("TTL 内又算了一次（共 %d 次）", n)
	}
	cache.get(context.Background(), now.Add(overviewShareTTL), overviewShareTTL, compute)
	if n := computed.Load(); n != 2 {
		t.Fatalf("过了 TTL 没有重算（共 %d 次），面板数字会停住", n)
	}
}

func TestLatencySplitsCacheHitsFromRecursion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "latency.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE query_events (id INTEGER PRIMARY KEY, ts INTEGER, route TEXT, elapsed_ms REAL)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		route, ms := "cache", 0.3
		if i%10 == 0 {
			route, ms = "cn", 200+float64(i)
		}
		if _, err := db.Exec("INSERT INTO query_events (ts, route, elapsed_ms) VALUES (?, ?, ?)", 5000+i, route, ms); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := latencyStats(context.Background(), db, 0)
	if err != nil {
		t.Fatal(err)
	}
	byRoute := stats["by_route"].(map[string]any)
	cache := byRoute["cache"].(map[string]any)
	cn := byRoute["cn"].(map[string]any)
	if stats["p50"] != 0.3 || cache["p50"] != 0.3 || cn["p50"] != 240.0 || cn["n"] != 10 {
		t.Fatalf("总体 p50=%v 缓存 p50=%v 递归 p50=%v (n=%v)，期望 0.3 / 0.3 / 240 (10)——"+
			"九成请求是缓存命中，只看总体中位数，递归慢了十倍也看不出来", stats["p50"], cache["p50"], cn["p50"], cn["n"])
	}
	if _, ok := byRoute["foreign"]; ok {
		t.Error("没有香港样本却给了一组分位数")
	}
}
