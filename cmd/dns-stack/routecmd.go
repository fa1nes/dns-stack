package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/metrics"
	"github.com/dns-stack/dns-stack/internal/pipeline"
	"github.com/dns-stack/dns-stack/internal/statefile"
)

const routingLock = "/run/lock/dns-stack-routing-data.lock"

var routeListNames = map[access.RouteList]string{access.RouteCN: "国内解析", access.RouteHK: "香港解析"}

func cmdRoute(args []string) error {
	fs := flag.NewFlagSet("route", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	noApply := fs.Bool("no-apply", false, "只改名单文件，不立即生效")
	usage := fmt.Errorf("用法: dns-stack route [list] | route <add|remove> <cn|hk> <域名>...")
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	var list access.RouteList
	if sub == "add" || sub == "remove" {
		if len(args) == 0 {
			return usage
		}
		parsed, err := access.ParseRouteList(args[0])
		if err != nil {
			return err
		}
		list, args = parsed, args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := accessStore(*state)
	names := fs.Args()

	var changed, touched []string
	switch sub {
	case "list":
		for _, l := range []access.RouteList{access.RouteCN, access.RouteHK} {
			entries, err := store.Routes(l)
			if err != nil {
				return err
			}
			fmt.Printf("%s（%d 条）\n", routeListNames[l], len(entries))
			for _, item := range entries {
				fmt.Println("  " + item)
			}
		}
		return nil
	case "add":
		if len(names) == 0 {
			return usage
		}
		added, moved, err := store.AddRoutes(list, names)
		if err != nil {
			return err
		}
		if len(added) == 0 {
			fmt.Printf("这些域名已经在%s名单里，未改动\n", routeListNames[list])
			return nil
		}
		fmt.Printf("已加入%s：%s\n", routeListNames[list], strings.Join(added, " "))
		if len(moved) > 0 {
			fmt.Printf("同时移出了另一张名单：%s\n", strings.Join(moved, " "))
		}
		touched = added
		changed = []string{string(list)}
		if len(moved) > 0 {
			changed = append(changed, string(list.Other()))
		}
	case "remove":
		if len(names) == 0 {
			return usage
		}
		removed, err := store.RemoveRoutes(list, names)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Printf("这些域名不在%s名单里，未改动\n", routeListNames[list])
			return nil
		}
		fmt.Printf("已移出%s：%s\n", routeListNames[list], strings.Join(removed, " "))
		touched = removed
		changed = []string{string(list)}
	default:
		return usage
	}
	if *noApply {
		fmt.Println("（--no-apply：名单已保存，下一轮分流流水线或 dns-stack reload 后生效）")
		return nil
	}
	return applyRoutes(*state, *conf, changed, touched, os.Stdout)
}

func applyRoutes(state, conf string, changed, touched []string, out io.Writer) error {
	ctx := context.Background()
	for _, list := range changed {
		switch access.RouteList(list) {
		case access.RouteHK:
			if code := metrics.Reload(ctx); code != 200 {
				return fmt.Errorf("mosproxy 重载失败（HTTP %d），香港解析名单已保存，下次重载后生效", code)
			}
			fmt.Fprintln(out, "mosproxy 已重载香港解析名单")
		case access.RouteCN:
			if err := rebuildAuthorityRoutes(ctx, state, conf, out); err != nil {
				return err
			}
		}
	}
	for _, name := range touched {
		flushEverywhere(ctx, name, out)
	}
	fmt.Fprintln(out, "已生效")
	return nil
}

func rebuildAuthorityRoutes(ctx context.Context, state, conf string, out io.Writer) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		unlock, err := statefile.TryLock(routingLock)
		if err == nil {
			defer unlock()
			break
		}
		if !errors.Is(err, statefile.ErrLocked) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("分流流水线一直在运行，名单已保存，15 分钟内的下一轮会让它生效")
		}
		time.Sleep(2 * time.Second)
	}
	var log strings.Builder
	cfg := pipeline.LoadConfig(state, conf)
	report, err := pipeline.Run(ctx, pipeline.Options{
		StateDir: state, Only: []string{"cn-authority"}, Force: true, Out: &log,
	}, pipeline.NewRuntime(cfg, &log), pipeline.Steps())
	if err != nil || report.Failed > 0 {
		lines := strings.Split(strings.TrimSpace(log.String()), "\n")
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		return fmt.Errorf("重建国内权威路由失败，名单已保存，下一轮流水线会重试：%v %s", err, strings.Join(lines, " / "))
	}
	fmt.Fprintln(out, "国内权威路由与 ECS 白名单已更新")
	return nil
}

func flushEverywhere(ctx context.Context, name string, out io.Writer) {
	unbound := exec.CommandContext(ctx, "unbound-control", "-c", "/etc/unbound/unbound.conf", "flush_zone", name)
	if err := unbound.Run(); err != nil {
		fmt.Fprintf(out, "[警告] Unbound 缓存没清掉（%s）: %v\n", name, err)
	}
	if _, err := metrics.FlushCache(ctx, name); err != nil {
		fmt.Fprintf(out, "[警告] mosproxy 缓存没清掉（%s）: %v\n", name, err)
	}
}
