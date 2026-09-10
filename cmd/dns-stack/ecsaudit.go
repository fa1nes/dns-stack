package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dns-stack/dns-stack/internal/authority"
	"github.com/dns-stack/dns-stack/internal/cnauth"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

var coreCNDomains = []string{
	"qq.com", "weixin.qq.com", "jd.com", "taobao.com", "tmall.com",
	"alipay.com", "aliyun.com", "bilibili.com", "doubao.com", "douyin.com",
	"baidu.com", "163.com", "zhihu.com", "xiaohongshu.com", "meituan.com",
	"iqiyi.com", "youku.com", "weibo.com", "csdn.net", "bytedance.com",
	"mi.com", "huawei.com", "oppo.com", "vivo.com", "lenovo.com",
	"12306.cn", "gov.cn", "icbc.com.cn", "ccb.com", "unionpay.com",
}

type ecsAuditSets struct {
	whitelist *ipset.Set
	direct    *ipset.Set
	cnAuth    *ipset.Set
	shared    *ipset.Set
	manual    []string
}

func (s ecsAuditSets) sourceOf(addr netip.Addr) string {
	switch {
	case s.direct.Contains(addr):
		return "direct4"
	case s.shared.Contains(addr):
		return "shared-excluded"
	case s.cnAuth.Contains(addr):
		return "cn-authority"
	}
	return "orphan"
}

func (s ecsAuditSets) manualMatch(name string) bool {
	for rest := name; rest != ""; {
		for _, manual := range s.manual {
			if rest == manual {
				return true
			}
		}
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		rest = rest[dot+1:]
	}
	return false
}

func loadPrefixSet(path string) *ipset.Set {
	file, err := os.Open(path)
	if err != nil {
		return ipset.New(nil)
	}
	defer file.Close()
	loaded, err := ipset.LoadReader(file, ipset.LoadOptions{})
	if err != nil {
		return ipset.New(nil)
	}
	return loaded.Set
}

func loadDomainList(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimRight(strings.TrimSpace(sc.Text()), "."))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func cmdECSAudit(args []string) error {
	fs := flag.NewFlagSet("ecs-audit", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	ecsConf := fs.String("ecs-conf", envOr("ECS_CONF",
		"/etc/unbound/unbound.conf.d/dns-stack-ecs.conf"), "Unbound ECS 白名单配置")
	resolver := fs.String("resolver", "127.0.0.1", "递归器地址")
	port := fs.Int("port", 5335, "递归器端口")
	workers := fs.Int("workers", 12, "并发查询数")
	quick := fs.Bool("quick", false, "只查内置核心域名，不读 cn.txt/gfw.txt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	chnroute := filepath.Join(*state, "chnroute")
	whitelist, err := cnauth.LoadECSWhitelist(*ecsConf)
	if err != nil {
		return fmt.Errorf("ECS 白名单不可用（这不代表没问题，代表判断不了）: %w", err)
	}
	if len(whitelist) == 0 {
		return fmt.Errorf("ECS 白名单为空或无法解析: %s", *ecsConf)
	}
	ranges := make([]ipset.Range, 0, len(whitelist))
	for _, prefix := range whitelist {
		if r, ok := ipset.PrefixRange(prefix); ok {
			ranges = append(ranges, r)
		}
	}
	sets := ecsAuditSets{
		whitelist: ipset.New(ranges),
		direct:    loadPrefixSet(filepath.Join(chnroute, "direct4.txt")),
		cnAuth:    loadPrefixSet(filepath.Join(chnroute, "cn-authority.txt")),
		shared:    loadPrefixSet(filepath.Join(chnroute, "shared-excluded.txt")),
		manual:    loadDomainList(filepath.Join(*state, "manual-cn-zones.txt")),
	}
	if sets.direct.Len() == 0 {
		return fmt.Errorf("direct4 为空或无法解析")
	}

	cnDomains := coreCNDomains
	var gfwDomains []string
	if !*quick {
		cnDomains = mergeSorted(coreCNDomains, loadDomainList(filepath.Join(*state, "cn.txt")))
		gfwDomains = loadDomainList(filepath.Join(*state, "gfw.txt"))
	}

	client, err := resolve.NewClient(*resolver, *port, resolve.DefaultTimeout)
	if err != nil {
		return err
	}
	ctx := context.Background()
	fmt.Printf("# ECS 白名单 %d 条网段\n\n", len(whitelist))

	fmt.Printf("── A. 国内域名：权威未全部进 ECS 白名单（%d 个待查）\n", len(cnDomains))
	missCount := auditDomains(ctx, client, cnDomains, *workers, func(name string, zone authority.ZoneAuthority) bool {
		missing := map[string][]netip.Addr{}
		total := 0
		for ns, addrs := range zone.ByName {
			for _, addr := range addrs {
				total++
				if !sets.whitelist.Contains(addr) {
					missing[ns] = append(missing[ns], addr)
				}
			}
		}
		if len(missing) == 0 {
			return false
		}
		fmt.Printf("  ⚠️ %s  %d/%d 台权威收不到 ECS\n      %s\n",
			name, len(missing), total, describe(missing, nil))
		return true
	})
	fmt.Printf("  小计: %d 个域名存在漏发\n\n", missCount)

	var leakCount, riskCount int
	byBucket := map[string]int{}
	if len(gfwDomains) > 0 {
		fmt.Printf("── B. 境外域名：权威误入 ECS 白名单（%d 个待查）\n", len(gfwDomains))
		leakCount = auditDomains(ctx, client, gfwDomains, *workers, func(name string, zone authority.ZoneAuthority) bool {
			leaked := map[string][]netip.Addr{}
			kinds := map[string]struct{}{}
			for ns, addrs := range zone.ByName {
				for _, addr := range addrs {
					if sets.whitelist.Contains(addr) {
						leaked[ns] = append(leaked[ns], addr)
						kinds[sets.sourceOf(addr)] = struct{}{}
					}
				}
			}
			if len(leaked) == 0 {
				return false
			}
			bucket := classifyLeak(sets, name, kinds)
			byBucket[bucket]++
			if bucket == "risk" {
				riskCount++
			}
			fmt.Printf("  %s %s\n      %s\n", bucket, name, describe(leaked, sets.sourceOf))
			return true
		})
		fmt.Printf("  小计: %d 个域名存在白名单命中\n", leakCount)
	}
	fmt.Printf("# 审计完成：A 类漏发 %d 个，B 类命中 %d 个，B 类真实风险 %d 个\n",
		missCount, leakCount, riskCount)
	fmt.Printf("# B 类来源分布：%v\n", byBucket)
	if riskCount > 0 {
		os.Exit(1)
	}
	return nil
}

func classifyLeak(sets ecsAuditSets, name string, kinds map[string]struct{}) string {
	if sets.manualMatch(name) {
		return "manual-cn"
	}
	for kind := range kinds {
		if kind != "direct4" && kind != "shared-excluded" {
			return "risk"
		}
	}
	return "explicit-safe"
}

func auditDomains(
	ctx context.Context, client *resolve.Client, names []string, workers int,
	report func(string, authority.ZoneAuthority) bool,
) int {
	if workers < 1 {
		workers = 1
	}
	if workers > len(names) {
		workers = len(names)
	}
	var cursor atomic.Int64
	var hits atomic.Int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				index := int(cursor.Add(1)) - 1
				if index >= len(names) {
					return
				}
				name := names[index]
				zone := authority.Authorities(ctx, client, name)
				if len(zone.ByName) == 0 {
					continue
				}
				mu.Lock()
				if report(name, zone) {
					hits.Add(1)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return int(hits.Load())
}

func describe(byName map[string][]netip.Addr, source func(netip.Addr) string) string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		for _, addr := range byName[name] {
			if source == nil {
				parts = append(parts, fmt.Sprintf("%s=%s", name, addr))
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%s[%s]", name, addr, source(addr)))
		}
	}
	return strings.Join(parts, ", ")
}

func mergeSorted(groups ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, group := range groups {
		for _, name := range group {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
