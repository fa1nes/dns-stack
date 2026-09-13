package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/netfetch"
	"github.com/dns-stack/dns-stack/internal/resolve"
	"github.com/dns-stack/dns-stack/internal/rulesync"
)

const (
	bundleMaxBytes  = 64 << 20
	reloadTimeout   = 10 * time.Second
	healthTimeout   = 5 * time.Second
	defaultRecurPot = 5335
)

func cmdSyncRules(args []string) error {
	fs := flag.NewFlagSet("sync-rules", flag.ContinueOnError)
	stateDir := fs.String("state", envOrDefault("DNS_STACK_STATE", "/var/lib/dns-stack"), "状态目录")
	configPath := fs.String("config", envOrDefault("CONFIG_FILE", config.DefaultPath), "配置文件")
	force := fs.Bool("force", false, "跳过骤降保护与同版本冲突保护（校验与失败回滚仍然生效）")
	rollback := fs.Bool("rollback", false, "回滚到上一份历史规则包")
	only := fs.String("only", "", "只跑其中一项: bundle 或 cdn")
	timeout := fs.Duration("timeout", 5*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}

	keys := config.ReadKeys(*configPath,
		"GITHUB_RAW_BASE", "GITHUB_MIRROR_1", "GITHUB_MIRROR_2",
		"MOSPROXY_API", "RULE_BUNDLE_HISTORY_KEEP", "RECURSIVE_PORT",
		"CDN_RULES_BASE", "DNS_STACK_BINARY_REPO", "GITHUB_BRANCH")

	opt := rulesync.Options{
		StateDir:    *stateDir,
		Force:       *force,
		HistoryKeep: atoiOr(keys["RULE_BUNDLE_HISTORY_KEEP"], 0),
		Log:         func(format string, a ...any) { fmt.Printf("[信息] "+format+"\n", a...) },
	}
	for _, key := range []string{"GITHUB_RAW_BASE", "GITHUB_MIRROR_1", "GITHUB_MIRROR_2"} {
		if v := strings.TrimSpace(keys[key]); v != "" {
			opt.Sources = append(opt.Sources, v)
		}
	}

	client := netfetch.Client("")
	opt.Fetch = func(ctx context.Context, url string) ([]byte, error) {
		return netfetch.Bytes(ctx, client, url, bundleMaxBytes)
	}
	api := strings.TrimSpace(keys["MOSPROXY_API"])
	if api == "" {
		api = "127.0.0.1:8888"
	}
	opt.Reload = func(ctx context.Context) error { return reloadMosproxy(ctx, client, api) }
	port := atoiOr(keys["RECURSIVE_PORT"], defaultRecurPot)
	opt.Health = func(ctx context.Context) error { return probeResolver(ctx, port) }

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *rollback {
		return rulesync.Rollback(ctx, opt)
	}
	if len(opt.Sources) == 0 {
		return fmt.Errorf("GITHUB_RAW_BASE 未配置，没有任何规则源")
	}

	var failed []string
	if *only != "cdn" {
		res, err := rulesync.Sync(ctx, opt)
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("规则包: %v", err))
		case res.Applied:
			fmt.Printf("[成功] 规则包已同步并重载 (版本 %d, 来源 %s)\n", res.GeneratedAt, res.Source)
			for _, name := range sortedNames(res.Counts) {
				fmt.Printf("        %s: %d 条\n", name, res.Counts[name])
			}
		default:
			fmt.Printf("[信息] 规则包未变更: %s\n", res.Reason)
		}
	}
	if *only != "bundle" {
		cdnOpt := opt
		cdnOpt.Sources = cdnRuleSources(keys)
		if len(cdnOpt.Sources) == 0 {
			fmt.Println("[信息] CDN 规则集未配置来源，跳过（CDN 命中判据会整体弃权）")
			fmt.Println("        它由代码仓库的 cdn-rules Action 生成，和规则包不在同一个仓库；")
			fmt.Println("        在 config.env 里配 CDN_RULES_BASE 或 DNS_STACK_BINARY_REPO 即可")
			if len(failed) > 0 {
				return fmt.Errorf("%s", strings.Join(failed, "; "))
			}
			return nil
		}
		res, err := rulesync.SyncCDN(ctx, cdnOpt)
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("CDN 规则集: %v", err))
		case res.Applied:
			fmt.Printf("[成功] CDN 规则集已同步 (provider %d, 前缀 %d, 来源 %s)\n",
				res.Providers, res.Prefixes, res.Source)
		default:
			fmt.Printf("[信息] CDN 规则集未变更: %s\n", res.Reason)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%s", strings.Join(failed, "; "))
	}
	return nil
}

func cdnRuleSources(keys map[string]string) []string {
	if base := strings.TrimSpace(keys["CDN_RULES_BASE"]); base != "" {
		return []string{strings.TrimRight(base, "/")}
	}
	repo := strings.TrimSpace(keys["DNS_STACK_BINARY_REPO"])
	if repo == "" {
		return nil
	}
	branch := strings.TrimSpace(keys["GITHUB_BRANCH"])
	if branch == "" {
		branch = "main"
	}
	return []string{
		"https://raw.githubusercontent.com/" + repo + "/" + branch,
		"https://cdn.jsdelivr.net/gh/" + repo + "@" + branch,
	}
}

func reloadMosproxy(ctx context.Context, client *http.Client, api string) error {
	ctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+api+"/ctl/reload", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mosproxy /ctl/reload 返回 HTTP %d", resp.StatusCode)
	}
	return nil
}

func probeResolver(ctx context.Context, port int) error {
	c, err := resolve.NewClient("127.0.0.1", port, healthTimeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	answer := c.Query(ctx, "example.com", dnswire.TypeA)
	if answer.Status != resolve.StatusOK {
		return fmt.Errorf("本机递归对 example.com 返回状态 %d", answer.Status)
	}
	if v4, _ := resolve.Addresses(answer); len(v4) == 0 {
		return fmt.Errorf("本机递归对 example.com 没有返回 A 记录")
	}
	return nil
}

func sortedNames(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func atoiOr(text string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || v < 0 {
		return fallback
	}
	return v
}
