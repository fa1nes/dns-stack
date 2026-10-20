package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/statefile"
)

type Options struct {
	Webhook   string
	StatePath string
	Host      string
	Problems  []string
	Client    *http.Client
}

func Notify(ctx context.Context, opt Options) (bool, error) {
	if opt.Webhook == "" {
		return false, nil
	}
	problems := append([]string(nil), opt.Problems...)
	sort.Strings(problems)
	current := strings.Join(problems, "\n")
	previous, _ := os.ReadFile(opt.StatePath)
	if string(previous) == current {
		return false, nil
	}
	if err := send(ctx, opt, problems); err != nil {
		return false, err
	}
	return true, statefile.WriteAtomic(opt.StatePath, []byte(current), 0o644)
}

func send(ctx context.Context, opt Options, problems []string) error {
	title := fmt.Sprintf("dns-stack %s：%d 项异常", opt.Host, len(problems))
	body := strings.Join(problems, "\n")
	if len(problems) == 0 {
		title = fmt.Sprintf("dns-stack %s：已恢复", opt.Host)
		body = "此前报告的异常已全部消失"
	}
	return post(ctx, opt.Webhook, opt.Client, title, body)
}

func post(ctx context.Context, webhook string, client *http.Client, title, body string) error {
	payload, err := json.Marshal(map[string]string{"title": title, "body": body})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("告警通道返回 %d", resp.StatusCode)
	}
	return nil
}

func SendTest(ctx context.Context, webhook, host string, client *http.Client) error {
	return post(ctx, webhook, client, fmt.Sprintf("dns-stack %s：测试消息", host),
		"收到这条说明告警通道是通的。真正的告警只在异常出现、变化、恢复时各发一条")
}

func ValidWebhook(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n\"'`") {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
}

func MaskWebhook(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	path := parsed.Path
	if len(path) > 6 {
		path = path[:4] + "…"
	}
	return parsed.Scheme + "://" + parsed.Host + path
}
