package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type inbox struct {
	mu       sync.Mutex
	messages []map[string]string
	status   int
}

func (b *inbox) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.status != 0 {
			w.WriteHeader(b.status)
			return
		}
		b.messages = append(b.messages, body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestAlertsFireOnceWhenThingsBreakAndOnceWhenTheyRecover(t *testing.T) {
	box := &inbox{}
	opt := Options{Webhook: box.server(t).URL, StatePath: filepath.Join(t.TempDir(), "alert-state"), Host: "cn"}
	steps := [][]string{
		nil,
		{"foreign-hk 离线"},
		{"foreign-hk 离线"},
		{"foreign-hk 离线"},
		{"foreign-hk 离线", "分流链缺失"},
		nil,
		nil,
	}
	for _, problems := range steps {
		opt.Problems = problems
		if _, err := Notify(context.Background(), opt); err != nil {
			t.Fatal(err)
		}
	}
	if len(box.messages) != 3 {
		t.Fatalf("发出 %d 条，期望 3 条（出现、加重、恢复）——看门狗每分钟跑一次，"+
			"状态不变时不能重复发，否则一次故障会刷出上百条：%v", len(box.messages), box.messages)
	}
	if !strings.Contains(box.messages[0]["body"], "foreign-hk") || !strings.Contains(box.messages[2]["title"], "已恢复") {
		t.Errorf("内容不对：%v", box.messages)
	}
}

func TestAFailedSendIsRetriedNextRunInsteadOfForgotten(t *testing.T) {
	box := &inbox{status: http.StatusBadGateway}
	opt := Options{Webhook: box.server(t).URL, StatePath: filepath.Join(t.TempDir(), "alert-state"),
		Problems: []string{"foreign-hk 离线"}}
	if _, err := Notify(context.Background(), opt); err == nil {
		t.Fatal("告警通道返回 502 却没有报错")
	}
	box.status = 0
	sent, err := Notify(context.Background(), opt)
	if err != nil || !sent || len(box.messages) != 1 {
		t.Fatalf("通道恢复后应当补发这条告警，sent=%v err=%v 收到 %d 条——"+
			"如果发送失败也记下状态，这次故障就永远不会再通知", sent, err, len(box.messages))
	}
}

func TestWithoutAWebhookNothingIsSentAndNoErrorIsRaised(t *testing.T) {
	opt := Options{StatePath: filepath.Join(t.TempDir(), "alert-state"), Problems: []string{"x"}}
	sent, err := Notify(context.Background(), opt)
	if sent || err != nil {
		t.Fatalf("没配告警通道时应当静默跳过，sent=%v err=%v", sent, err)
	}
	box := &inbox{}
	opt.Webhook = box.server(t).URL
	if sent, err := Notify(context.Background(), opt); !sent || err != nil || len(box.messages) != 1 {
		t.Fatalf("后来配上告警通道，已经存在的异常应当马上补发一条，sent=%v err=%v 收到 %d 条——"+
			"没通道时也记下状态的话，这条异常就被当成「已经通知过」永远不发了", sent, err, len(box.messages))
	}
}
