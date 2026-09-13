package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

const selfTestAddr = "192.0.2.1"

type expectList []string

func (e *expectList) String() string { return strings.Join(*e, ",") }

func (e *expectList) Set(v string) error {
	*e = append(*e, v)
	return nil
}

func cmdCDNRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: dns-stack cdn-rules <build|verify|lookup> [参数]")
	}
	switch args[0] {
	case "build":
		return cdnRulesBuild(args[1:])
	case "verify":
		return cdnRulesVerify(args[1:])
	case "lookup":
		return cdnRulesLookup(args[1:])
	default:
		return fmt.Errorf("未知子命令: %s", args[0])
	}
}

func cdnRulesBuild(args []string) error {
	fs := flag.NewFlagSet("cdn-rules build", flag.ContinueOnError)
	mainland := fs.String("mainland", "", "大陆网段基线文件(direct4.txt)")
	out := fs.String("out", "", "输出规则集路径")
	minPrefixes := fs.Int("min-prefixes", 1000, "前缀数下限，低于此值拒绝发布")
	timeout := fs.Duration("timeout", 10*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mainland == "" || *out == "" {
		return fmt.Errorf("--mainland 与 --out 都必填")
	}
	base, err := cidrutil.ReadPrefixFile(*mainland)
	if err != nil {
		return fmt.Errorf("读取大陆网段基线失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	now := time.Now()
	rep, err := cdnrules.Build(ctx, cdnrules.Options{
		Mainland:    base,
		Now:         now,
		MinPrefixes: *minPrefixes,
	})
	for _, w := range rep.Warnings {
		fmt.Fprintf(os.Stderr, "[警告] %s\n", w)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	temp := *out + ".part"
	f, err := os.Create(temp)
	if err != nil {
		return err
	}
	if err := cdnrules.Render(f, now, rep.Providers); err != nil {
		f.Close()
		os.Remove(temp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, *out); err != nil {
		os.Remove(temp)
		return err
	}
	fmt.Printf("规则集已写出: %s\n", *out)
	fmt.Printf("  provider %d 个，域名 %d 条，前缀 %d 条\n", len(rep.Providers), rep.Domains, rep.Prefixes)
	fmt.Printf("  有前缀证据: %s\n", strings.Join(rep.WithNets, " "))
	fmt.Printf("  暂无前缀证据(判据对其弃权): %s\n", strings.Join(rep.WithoutNets, " "))
	var mainlandIDs []string
	for _, p := range rep.Providers {
		if p.HasMainland() {
			mainlandIDs = append(mainlandIDs, fmt.Sprintf("%s(%d)", p.ID, len(p.Mainland)))
		}
	}
	sort.Strings(mainlandIDs)
	fmt.Printf("  有大陆节点段: %s\n", strings.Join(mainlandIDs, " "))
	return nil
}

func cdnRulesVerify(args []string) error {
	fs := flag.NewFlagSet("cdn-rules verify", flag.ContinueOnError)
	file := fs.String("file", "", "规则集路径")
	minProviders := fs.Int("min-providers", 1, "provider 数下限")
	minPrefixes := fs.Int("min-prefixes", 0, "前缀数下限")
	maxAge := fs.Duration("max-age", 0, "generated-at 允许的最大年龄，0 表示不检查")
	requireNets := fs.String("require-nets", "", "逗号分隔的 provider，必须有非空前缀，否则判为来源静默失效")
	var expects expectList
	fs.Var(&expects, "expect", "锚点断言 地址=provider，可重复")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file 必填")
	}
	set, err := cdnrules.Load(*file)
	if err != nil {
		return err
	}
	if _, _, _, hit := set.Owner(netip.MustParseAddr(selfTestAddr)); hit {
		return fmt.Errorf("自检失败: %s 是 TEST-NET-1，任何 CDN 都不该拥有它，规则集或查找逻辑已经污染", selfTestAddr)
	}
	fmt.Printf("自检通过: %s 未被任何 provider 认领\n", selfTestAddr)

	if n := len(set.Providers()); n < *minProviders {
		return fmt.Errorf("只有 %d 个 provider，低于下限 %d", n, *minProviders)
	}
	if n := set.PrefixCount(); n < *minPrefixes {
		return fmt.Errorf("只有 %d 条前缀，低于下限 %d", n, *minPrefixes)
	}
	if *maxAge > 0 {
		age := time.Since(set.GeneratedAt())
		if age > *maxAge {
			return fmt.Errorf("规则集已 %s 未更新，超过上限 %s", age.Round(time.Minute), *maxAge)
		}
	}
	var failed []string
	if strings.TrimSpace(*requireNets) != "" {
		have := make(map[string]int)
		for _, p := range set.Providers() {
			have[p.ID] = p.PrefixCount()
		}
		for _, id := range strings.Split(*requireNets, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			n, known := have[id]
			switch {
			case !known:
				failed = append(failed, fmt.Sprintf("provider %s 不在规则集里", id))
			case n == 0:
				failed = append(failed, fmt.Sprintf("provider %s 有前缀来源却一条都没收到，来源已静默失效", id))
			default:
				fmt.Printf("来源正常 %s: %d 条前缀\n", id, n)
			}
		}
	}
	for _, item := range expects {
		addrText, want, ok := strings.Cut(item, "=")
		if !ok {
			return fmt.Errorf("锚点格式应为 地址=provider，得到 %q", item)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(addrText))
		if err != nil {
			return fmt.Errorf("锚点地址无效 %q: %w", addrText, err)
		}
		owner, prefix, mainland, hit := set.Owner(addr)
		switch {
		case !hit:
			failed = append(failed, fmt.Sprintf("%s 未被任何 provider 认领，期望 %s", addr, want))
		case owner.ID != strings.TrimSpace(want):
			failed = append(failed, fmt.Sprintf("%s 归属 %s，期望 %s", addr, owner.ID, want))
		default:
			where := "境外"
			if mainland {
				where = "大陆"
			}
			fmt.Printf("锚点 %s -> %s %s %s\n", addr, owner.ID, prefix, where)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("锚点断言未通过:\n  %s", strings.Join(failed, "\n  "))
	}
	fmt.Printf("规则集正常: provider %d 个，域名 %d 条，前缀 %d 条，生成于 %s\n",
		len(set.Providers()), set.DomainCount(), set.PrefixCount(),
		set.GeneratedAt().Local().Format("2006-01-02 15:04:05"))
	return nil
}

func cdnRulesLookup(args []string) error {
	fs := flag.NewFlagSet("cdn-rules lookup", flag.ContinueOnError)
	file := fs.String("file", "", "规则集路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if *file == "" || len(rest) != 2 {
		return fmt.Errorf("用法: dns-stack cdn-rules lookup --file <规则集> <域名> <IP>")
	}
	set, err := cdnrules.Load(*file)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(rest[1])
	if err != nil {
		return fmt.Errorf("IP 无效: %w", err)
	}
	d := set.Classify(rest[0], addr)
	fmt.Printf("域名 %s\n", d.Name)
	fmt.Printf("  域名归属: %s\n", orDash(d.Provider))
	fmt.Printf("  地址归属: %s %s\n", orDash(d.Owner), orDash(prefixText(d.Prefix)))
	fmt.Printf("  判据: %s (%s)\n", d.Verdict, d.Verdict.Label())
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func prefixText(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}
