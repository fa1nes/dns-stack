package helper

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/config"
)

func TestAlertWebhookIsValidatedSavedAndTested(t *testing.T) {
	h := newTestHelper(t)
	for _, bad := range []string{"ftp://example.com/x", "https://example.com/a b", "https://example.com/\"x"} {
		if r := h.opSetAlertWebhook(map[string]any{"webhook": bad}); r["ok"] == true {
			t.Errorf("%q 不该被接受", bad)
		}
	}
	if r := h.opAlertTest(nil); r["ok"] == true {
		t.Fatal("没设地址时测试消息不该报成功")
	}
	var got map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer server.Close()
	if r := h.opSetAlertWebhook(map[string]any{"webhook": server.URL + "/push/secret-key"}); r["ok"] != true {
		t.Fatalf("合法地址应当保存: %v", r)
	}
	if v := config.Value(h.configPath, "ALERT_WEBHOOK"); v != server.URL+"/push/secret-key" {
		t.Fatalf("config.env 里是 %q", v)
	}
	if v := config.Value(h.configPath, "DOH_PATH"); v == "" {
		t.Fatal("改告警地址把别的配置项弄丢了")
	}
	if r := h.opAlertTest(nil); r["ok"] != true {
		t.Fatalf("测试消息应当发出: %v", r)
	}
	if !strings.Contains(got["title"], "测试") {
		t.Fatalf("推送端收到的是 %v", got)
	}
	if r := h.opSetAlertWebhook(map[string]any{"webhook": ""}); r["ok"] != true || config.Value(h.configPath, "ALERT_WEBHOOK") != "" {
		t.Fatalf("留空应当关闭推送: %v", r)
	}
}

func TestUpgradeCommandOnlyAcceptsKnownTargets(t *testing.T) {
	cmd, target, ok := upgradeCommand("/opt/dns-stack/bin/dns-stack-go", map[string]any{"target": "mosproxy"}, true)
	if !ok || target != "mosproxy" || strings.Join(cmd, " ") != "/opt/dns-stack/bin/dns-stack-go upgrade --json --mosproxy --check" {
		t.Fatalf("mosproxy 检查命令不对: %v %s %v", cmd, target, ok)
	}
	if _, _, ok := upgradeCommand("/x/dns-stack-go", map[string]any{"target": "--restart=all"}, false); ok {
		t.Fatal("未知 target 不能拼进命令行")
	}
}
