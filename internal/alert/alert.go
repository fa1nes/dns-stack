package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	payload, err := json.Marshal(map[string]string{"title": title, "body": body})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opt.Webhook, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	client := opt.Client
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
