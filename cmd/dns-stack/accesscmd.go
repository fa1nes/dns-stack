package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/pipeline"
)

func accessStore(stateDir string) access.Store {
	if stateDir == "" {
		stateDir = envOrDefault("DNS_STACK_STATE", "/var/lib/dns-stack")
	}
	return access.Store{StateDir: stateDir}
}

func cmdBlocklist(args []string) error {
	fs := flag.NewFlagSet("blocklist", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	noReload := fs.Bool("no-reload", false, "只改文件，不让 mosproxy 重载")
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := accessStore(*stateDir)
	if err := store.EnsureFiles(); err != nil {
		return err
	}
	rest := fs.Args()

	switch sub {
	case "", "list":
		entries, err := store.Blocklist()
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("黑名单为空（没有域名被拦截）")
			return nil
		}
		for _, item := range entries {
			fmt.Println(item)
		}
		fmt.Printf("\n共 %d 条\n", len(entries))
		return nil
	case "add":
		if len(rest) == 0 {
			return fmt.Errorf("用法: dns-stack blocklist add <域名>...")
		}
		added, err := store.AddBlocked(rest)
		if err != nil {
			return err
		}
		if len(added) == 0 {
			fmt.Println("这些域名已经在黑名单里，未改动")
			return nil
		}
		fmt.Printf("已加入 %d 条: %s\n", len(added), strings.Join(added, " "))
	case "remove":
		if len(rest) == 0 {
			return fmt.Errorf("用法: dns-stack blocklist remove <域名>...")
		}
		removed, err := store.RemoveBlocked(rest)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Println("这些域名不在黑名单里，未改动")
			return nil
		}
		fmt.Printf("已移除 %d 条: %s\n", len(removed), strings.Join(removed, " "))
	default:
		return fmt.Errorf("用法: dns-stack blocklist <list|add|remove> [域名...]")
	}
	if *noReload {
		fmt.Println("（--no-reload：mosproxy 尚未重载，下次 reload 后生效）")
		return nil
	}
	return reloadForAccess()
}

func reloadForAccess() error {
	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8888/ctl/reload", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("[警告] mosproxy 重载失败，改动下次重载后生效: %v\n", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[警告] mosproxy 重载返回 HTTP %d，改动下次重载后生效\n", resp.StatusCode)
		return nil
	}
	fmt.Println("mosproxy 已重载，改动即刻生效")
	return nil
}

func cmdACL(args []string) error {
	fs := flag.NewFlagSet("acl", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configPath := fs.String("config", config.DefaultPath, "配置文件")
	preview := fs.Bool("preview", false, "只打印将要下发的 nft 脚本")
	yes := fs.Bool("yes", false, "跳过确认")
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := accessStore(*stateDir)
	if err := store.EnsureFiles(); err != nil {
		return err
	}
	rest := fs.Args()
	ctx := context.Background()
	keys := config.ReadKeys(*configPath, "DOH_PORT", "DOT_PORT", "NFT_TABLE")
	table := keys["NFT_TABLE"]
	if table == "" {
		table = "dns_route"
	}

	switch sub {
	case "", "list", "status":
		entries, err := store.ACL()
		if err != nil {
			return err
		}
		installed := pipeline.ACLInstalled(ctx, table)
		switch {
		case len(entries) == 0 && !installed:
			fmt.Println("访问控制未启用：授权网段为空，入口对全网开放")
		case len(entries) == 0 && installed:
			fmt.Println("[警告] acl.txt 为空但内核里仍有访问控制链——执行 dns-stack acl disable 清理")
		default:
			for _, prefix := range entries {
				fmt.Println(prefix)
			}
			fmt.Printf("\n共 %d 条授权网段，内核链: %s\n", len(entries), installedText(installed))
		}
		if sub == "status" && installed {
			if text, err := pipeline.ACLStatus(ctx, table); err == nil {
				fmt.Println()
				fmt.Println(strings.TrimRight(text, "\n"))
			}
		}
		return nil
	case "add":
		if len(rest) == 0 {
			return fmt.Errorf("用法: dns-stack acl add <CIDR>...")
		}
		if _, err := store.AddACL(rest); err != nil {
			return err
		}
	case "remove":
		if len(rest) == 0 {
			return fmt.Errorf("用法: dns-stack acl remove <CIDR>...")
		}
		if _, err := store.RemoveACL(rest); err != nil {
			return err
		}
	case "set":
		if _, err := store.SetACL(rest); err != nil {
			return err
		}
	case "disable":
		if err := pipeline.ACLDisable(ctx, table); err != nil {
			return err
		}
		fmt.Println("访问控制链已移除，入口恢复对全网开放（acl.txt 保留，用 apply 可再次启用）")
		return nil
	case "apply":
	default:
		return fmt.Errorf("用法: dns-stack acl <list|status|add|remove|set|apply|disable> [CIDR...]")
	}

	entries, err := store.ACL()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if err := pipeline.ACLDisable(ctx, table); err != nil {
			return err
		}
		fmt.Println("授权网段已清空，访问控制链已移除，入口对全网开放")
		return nil
	}
	cfg := pipeline.ACLConfig{
		Table:    table,
		DoHPort:  atoiOr(keys["DOH_PORT"], 443),
		DoTPort:  atoiOr(keys["DOT_PORT"], 853),
		Prefixes: entries,
	}
	script, err := cfg.Render()
	if err != nil {
		return err
	}
	if *preview {
		fmt.Print(script)
		return nil
	}
	if !*yes {
		fmt.Printf("即将只放行这 %d 个网段访问 DoH(%d)/DoT(%d)，其余一律丢弃。\n",
			len(entries), cfg.DoHPort, cfg.DoTPort)
		fmt.Println("回环与隧道网段始终放行（否则本机自检会被自己挡死）。")
		fmt.Println("⚠️ 家宽等动态地址会变，变了就连不上自己的 DNS——出事时用 SSH 跑 dns-stack acl disable。")
		fmt.Print("确认继续？[y/N] ")
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("已取消，未改动内核")
			return nil
		}
	}
	if err := cfg.Apply(ctx); err != nil {
		return err
	}
	fmt.Printf("访问控制已生效：%d 个授权网段，保护端口 %d/%d\n", len(entries), cfg.DoHPort, cfg.DoTPort)
	return nil
}

func installedText(installed bool) string {
	if installed {
		return "已安装"
	}
	return "未安装（改动尚未下发，执行 dns-stack acl apply）"
}

var _ = time.Second
