package helper

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/alert"
	"github.com/dns-stack/dns-stack/internal/config"
)

func (h *Helper) opSetAlertWebhook(args map[string]any) result {
	webhook := strings.TrimSpace(stringArg(args, "webhook"))
	if !alert.ValidWebhook(webhook) {
		return rejectResult("推送地址要是 http:// 或 https:// 开头的完整网址，不超过 512 个字符，不能带空格或引号")
	}
	configEditMu.Lock()
	err := config.Upsert(h.configPath, map[string]string{"ALERT_WEBHOOK": webhook})
	configEditMu.Unlock()
	if err != nil {
		return failure("写入 config.env 失败: " + err.Error())
	}
	if webhook == "" {
		h.log("告警推送: 已关闭")
		return result{"ok": true, "returncode": 0, "stdout": "已关闭告警推送", "stderr": ""}
	}
	h.log("告警推送: " + alert.MaskWebhook(webhook))
	return result{"ok": true, "returncode": 0, "stdout": "告警推送地址已保存", "stderr": ""}
}

func (h *Helper) opAlertTest(map[string]any) result {
	webhook := strings.TrimSpace(h.configValue("ALERT_WEBHOOK"))
	if webhook == "" {
		return rejectResult("还没有设置告警推送地址")
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := alert.SendTest(ctx, webhook, host, &http.Client{Timeout: 15 * time.Second}); err != nil {
		return failure("测试消息没发出去：" + err.Error())
	}
	return result{"ok": true, "returncode": 0, "stdout": "测试消息已发出，去推送端看看有没有收到", "stderr": ""}
}
