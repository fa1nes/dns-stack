package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"io"

	"github.com/dns-stack/dns-stack/internal/anycast"
	"github.com/dns-stack/dns-stack/internal/authority"
	"github.com/dns-stack/dns-stack/internal/cnauth"
	"github.com/dns-stack/dns-stack/internal/collect"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/ecszone"
	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/helper"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/panel"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("dns-stack %s\n", version)
	case "domain-check":
		err = cmdDomainCheck(args)
	case "ipset-check":
		err = cmdIPSetCheck(args)
	case "geoip-check":
		err = cmdGeoIPCheck(args)
	case "geoip-verify":
		err = cmdGeoIPVerify(args)
	case "infra-check":
		err = cmdInfraCheck(args)
	case "authority-check":
		err = cmdAuthorityCheck(args)
	case "collect":
		err = cmdCollect(args)
	case "classify":
		err = cmdClassify(args)
	case "shared-anycast":
		err = cmdSharedAnycast(args)
	case "ecs-zone":
		err = cmdECSZone(args)
	case "cn-authority":
		err = cmdCNAuthority(args)
	case "chnroute":
		err = cmdChnroute(args)
	case "polluted-evidence":
		err = cmdPollutedEvidence(args)
	case "rules":
		err = cmdRules(args)
	case "migration-export":
		err = cmdMigrationExport(args)
	case "migration-restore":
		err = cmdMigrationRestore(args)
	case "direct4-audit":
		err = cmdDirect4Audit(args)
	case "ecs-orphans":
		err = cmdECSOrphans(args)
	case "ecs-audit":
		err = cmdECSAudit(args)
	case "ecs-forward":
		err = cmdECSForward(args)
	case "doh-probe":
		err = cmdDoHProbe(args)
	case "helper-probe":
		err = cmdHelperProbe(args)
	case "helper":
		err = cmdHelper(args)
	case "panel":
		err = cmdPanel(args)
	case "panel-auth":
		err = cmdPanelAuth(args)
	case "status":
		err = cmdStatus(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[错误] %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dns-stack — 自建 DNS 解析栈

用法:
  dns-stack <子命令> [参数]

子命令:
  status          一屏看完本机全部模块：分组、状态、上次/下次运行（--json 输出机器可读）
  domain-check    对每行域名输出形态判据结果
  ipset-check     加载 CIDR 集合并对每行 IP 输出是否命中
  geoip-check     查询 IP 归属并输出 JSON 或标签
  geoip-verify    校验归属库能否解析、类型是否正确、国家码/ASN 抽查是否可信
  infra-check     解析 Unbound infra 快照并输出区域、权威 IP、rto
  authority-check 按权威服务器位置判定每行域名（必须跑在境外节点）
  shared-anycast  生成共享 anycast 权威清单，供 cn-authority 排除
  ecs-zone        按省+运营商生成 mosproxy 的 ECS 缓存分片表
  cn-authority    由 infra 记录生成直连路由集与 ECS 白名单(含累积保留)
  chnroute        由 APNIC 委派记录生成 direct4(qqwry 补充 + 反向排除)
  polluted-evidence 聚合污染 IP 观测证据(TTL/门槛)并汇总 CIDR
  rules           规则包清洗与校验(域名形态/CIDR 汇总/不重叠/父子覆盖)
  migration-export  导出迁移包(与面板「导出迁移数据」共用同一份清单，一条密钥都不含)
  migration-restore 从面板导出的迁移包恢复数据(按清单白名单写入，可 --dry-run)
  direct4-audit   多个归属库交叉验证 direct4，产出争议(不发 ECS)与晋级(可作大陆证据)清单
  ecs-orphans     审计 ECS 白名单孤儿：区分 TTL 内累积保留与真孤儿，按境外归属计数并卡阈值
  ecs-audit       ECS 全链路 A/B 审计：A 类国内域名权威漏发、B 类境外域名权威误入白名单
  ecs-forward     直查 mosproxy DoT，验证客户端子网是否真的转发给上游（分片表内外对照）
  doh-probe       向本机 DoH 入口发一个真实查询，输出 ok/bad
  helper-probe    经 helper socket 取日志，数出其中未脱敏的全局 IPv4 个数（-1 表示查不了）
  collect         消费 mosproxy 日志流(consume-stdin) / 统计 / 拉取候选
  classify        规则构建节点全流程：候选拉取、双视角分类、权威位置分类、规则包构建与发布
                  (pipeline 子命令一次跑完全流程，direct4/PSL/解析客户端全程复用)
  helper          以 root 运行受限管理助手，监听 unix socket 供面板调用
  panel           启动嵌入式 DNS 管理面板
  panel-auth      设置面板密码 / 关闭二次认证（需 root，直接写 auth.json）
  version         显示版本
`)
}

func cmdCollect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: dns-stack collect <consume-stdin|stats|pull-batch> [参数]")
	}
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	dbPath := fs.String("db", os.Getenv("DNS_STACK_DB"), "collector SQLite 路径")
	stateDir := fs.String("state", os.Getenv("DNS_STACK_STATE"), "状态目录")
	limit := fs.Int("limit", 2000, "pull-batch 单次上限")
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch sub {
	case "consume-stdin":

		return collect.NewConsumer(*dbPath, *stateDir, os.Stdout).Run(os.Stdin)
	case "stats":
		db, err := collect.OpenDB(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		stats, err := collect.ReadStats(db)
		if err != nil {
			return err
		}
		return writeCompactJSON(stats)
	case "pull-batch":

		db, err := collect.OpenDB(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		rows, err := collect.PullBatch(db, *limit, time.Now().Unix())
		if err != nil {
			return err
		}
		return writeCompactJSON(map[string]any{
			"domains":        rows,
			"polluted_cidrs": collect.LoadPollutedCIDRs(*stateDir),
			"cn_cidrs":       collect.LoadCNCIDRs(*stateDir),
		})
	}
	return fmt.Errorf("未知子命令: collect %s", sub)
}

func writeCompactJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

type mainlandSet struct{ set *ipset.Set }

func (m mainlandSet) IsMainland(addr netip.Addr) bool {
	return addr.Is4() && ipset.IsGlobalAddr(addr) && m.set.Contains(addr)
}

func cmdAuthorityCheck(args []string) error {
	fs := flag.NewFlagSet("authority-check", flag.ContinueOnError)
	directPath := fs.String("direct4", "", "direct4 文件（APNIC delegated 快照）")
	pslPath := fs.String("psl", "", "PSL 文件，留空则按默认顺序查找")
	resolver := fs.String("resolver", "127.0.0.1", "境外递归器地址")
	port := fs.Int("port", 5335, "境外递归器端口")
	concurrency := fs.Int("concurrency", 8, "并发判定数")
	timeout := fs.Duration("timeout", resolve.DefaultTimeout, "单次查询超时")
	collapse := fs.Bool("collapse", false, "对判为 cn 的域名做同 IP 子域折叠")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*directPath) == "" {
		return fmt.Errorf("必须指定 --direct4，缺少大陆网段快照时拒绝判定")
	}
	directFile, err := os.Open(*directPath)
	if err != nil {
		return err
	}
	direct, err := ipset.LoadReader(directFile, ipset.LoadOptions{GlobalOnly: true})
	_ = directFile.Close()
	if err != nil {
		return err
	}
	if direct.Set.Len() == 0 {
		return fmt.Errorf("direct4 中没有有效的全局 IPv4 网段，拒绝判定")
	}
	var psl *domain.PSL
	var note string
	if *pslPath != "" {
		psl, note = domain.LoadPSL([]string{*pslPath})
	} else {
		psl, note = domain.LoadPSL(nil)
	}

	if psl == nil {
		return fmt.Errorf("缺少有效的 Public Suffix List，拒绝执行权威判定")
	}
	fmt.Fprintf(os.Stderr, "[信息] %s\n", note)

	client, err := resolve.NewClient(*resolver, *port, *timeout)
	if err != nil {
		return err
	}
	var names []string
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, strings.Fields(line)[0])
	}
	if err := sc.Err(); err != nil {
		return err
	}

	ctx := context.Background()
	verdicts := authority.ClassifyMany(ctx, client, mainlandSet{direct.Set}, names, psl, *concurrency)
	type item struct {
		Domain         string   `json:"domain"`
		Zone           string   `json:"zone"`
		Verdict        string   `json:"verdict"`
		Reason         string   `json:"reason"`
		AuthorityIPs   []string `json:"authority_ips"`
		CNAuthorityIPs []string `json:"cn_authority_ips"`
	}
	addrStrings := func(values []netip.Addr) []string {
		out := make([]string, 0, len(values))
		for _, v := range values {
			out = append(out, v.String())
		}
		return out
	}
	items := make([]item, 0, len(verdicts))
	var cn []string
	for _, v := range verdicts {
		items = append(items, item{
			Domain: v.Domain, Zone: v.Zone, Verdict: v.Verdict, Reason: v.Reason,
			AuthorityIPs: addrStrings(v.AuthorityIPs), CNAuthorityIPs: addrStrings(v.CNAuthorityIPs),
		})
		if v.Verdict == authority.VerdictCN {
			cn = append(cn, v.Domain)
		}
	}
	payload := map[string]any{"verdicts": items}
	if *collapse {
		payload["cn_collapsed"] = authority.CollapseByResolution(ctx, client, cn, *concurrency)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func cmdInfraCheck(args []string) error {
	fs := flag.NewFlagSet("infra-check", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := infra.Parse(os.Stdin)
	if err != nil {
		return err
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, e := range s.Pairs() {
		rto := "-1"
		if e.HasRTO {
			rto = fmt.Sprintf("%d", e.RTO)
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", e.Zone, e.IP, rto)
	}
	fmt.Fprintf(os.Stderr, "[信息] 有效 %d 条，跳过 %d 条，区域 %d 个\n", len(s.Entries), s.Skipped, len(s.Zones()))
	return nil
}

func mosproxyReload(api string) int {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("http://" + api + "/ctl/reload")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func verifyWithReload(api, outPath, backup string, hadOld bool) error {
	switch code := mosproxyReload(api); {
	case code == 0:
		fmt.Println("[信息] mosproxy 管理接口连不上（服务未运行？），本次跳过 reload 验证。文件已落盘，下次启动时生效")
		return nil
	case code == 200:
		fmt.Println("[成功] mosproxy 已热加载新的分片表（reload 通过 = 文件可被正确解析）")
		return nil
	default:
		fmt.Fprintf(os.Stderr, "[错误] mosproxy reload 返回 %d，新分片表可能无法解析。正在回滚\n", code)
		if !hadOld {
			os.Remove(outPath)
			return fmt.Errorf("首次生成即失败，已移除新文件")
		}
		if err := os.Rename(backup, outPath); err != nil {
			return err
		}
		if recheck := mosproxyReload(api); recheck == 200 {
			return fmt.Errorf("已回滚到上一版分片表，reload 恢复正常，确认是本次生成的内容有问题")
		} else {
			return fmt.Errorf("回滚后 reload 仍返回 %d，问题不在本次生成的分片表，请立即检查 mosproxy 日志", recheck)
		}
	}
}

func loadDisputedForZone(path string, maxAge time.Duration, strict bool) (*ipset.Set, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	snapshot, err := geoaudit.LoadSnapshot(path)
	if err != nil {
		if strict {
			return nil, fmt.Errorf("读不到多源争议清单 %s: %w", path, err)
		}
		fmt.Printf("[警告] 读不到多源争议清单 %s（%v）\n", path, err)
		fmt.Printf("[警告]   本轮不做跨库交叉，被多源判为境外的段仍会拿到中国 zone 标记\n")
		return nil, nil
	}
	if snapshot.Kind != geoaudit.KindDisputed {
		return nil, fmt.Errorf("%s 声明的 kind 是 %q，期望 %q，拒绝按错误的方向使用",
			path, snapshot.Kind, geoaudit.KindDisputed)
	}
	age := snapshot.Age(time.Now())
	if snapshot.GeneratedAt == 0 || age > maxAge {
		if strict {
			return nil, fmt.Errorf("多源争议清单已陈旧 %v（上限 %v）", age.Round(time.Hour), maxAge)
		}
		fmt.Printf("[警告] 多源争议清单已陈旧 %v（上限 %v），仍按旧内容交叉；检查 dns-stack-geo-cross.timer\n",
			age.Round(time.Hour), maxAge)
	}
	fmt.Printf("[信息] 多源争议清单 %d 条前缀 / %d 个地址，来源 %s，agreement=%d\n",
		snapshot.Prefixes, snapshot.Set.AddressCount(),
		strings.Join(snapshot.Sources, ","), snapshot.Agreement)
	return snapshot.Set, nil
}

func cmdECSZone(args []string) error {
	fs := flag.NewFlagSet("ecs-zone", flag.ContinueOnError)
	direct := fs.String("direct4", envOr("DIRECT_LIST", "/var/lib/dns-stack/chnroute/direct4.txt"), "direct4 列表")
	cnip := fs.String("cnip", envOr("CNIP_DB", "/var/lib/dns-stack/geoip/qqwry.ipdb"), "qqwry 归属库")
	out := fs.String("out", envOr("ECS_ZONE_FILE", "/var/lib/dns-stack/ecs-ip-zone.txt"), "输出文件")
	api := fs.String("api", envOr("MOSPROXY_API", "127.0.0.1:8888"), "mosproxy 管理接口")
	disputedPath := fs.String("disputed", envOr("GEO_DISPUTED_FILE",
		"/var/lib/dns-stack/chnroute/geo-disputed.txt"), "多源争议网段文件，不打标这些段")
	requireCross := fs.Bool("require-cross", false, "争议清单缺失或陈旧时直接失败，而不是降级为不交叉")
	defaultMaxAge := 48 * time.Hour
	if seconds, err := strconv.Atoi(envOr("GEO_CROSS_MAX_AGE_SEC", "")); err == nil && seconds > 0 {
		defaultMaxAge = time.Duration(seconds) * time.Second
	}
	maxAge := fs.Duration("cross-max-age", defaultMaxAge, "争议清单允许的最大陈旧时长")
	dryRun := fs.Bool("dry-run", false, "只统计不写文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*cnip); err != nil {
		return fmt.Errorf("归属库不存在: %s", *cnip)
	}
	intervals, err := ecszone.LoadDirectIntervals(*direct)
	if err != nil {
		return fmt.Errorf("无法读取大陆网段列表 %s: %w", *direct, err)
	}
	if len(intervals) == 0 {
		return fmt.Errorf("大陆网段列表为空，拒绝生成")
	}
	disputed, err := loadDisputedForZone(*disputedPath, *maxAge, *requireCross)
	if err != nil {
		return err
	}
	rows, stats, err := ecszone.Build(ecszone.BuildOptions{
		DBPath: *cnip, Direct: intervals, Disputed: disputed,
	})
	if err != nil {
		return err
	}
	raw, skipped := stats.Raw, stats.SkippedNoZone
	if len(rows) == 0 {
		return fmt.Errorf("没有任何网段被打标，拒绝生成空文件")
	}
	merged, clipped := ecszone.MergeRows(rows)
	if index, bad := ecszone.FirstOverlap(merged); bad {
		a, b := merged[index], merged[index+1]
		return fmt.Errorf("自检发现重叠区间，拒绝写入: %s-%s[%s] vs %s-%s[%s]",
			ecszone.FormatAddr(a.Lo), ecszone.FormatAddr(a.Hi), a.Zone,
			ecszone.FormatAddr(b.Lo), ecszone.FormatAddr(b.Hi), b.Zone)
	}
	if clipped > 0 {
		fmt.Printf("[警告] 裁剪了 %d 处跨 zone 重叠（保留起点更早的一条）。数量持续偏高说明归属库的分段出了问题\n", clipped)
	}

	old := ecszone.CountDataLines(*out)
	if old >= 100 && len(merged) < old*6/10 {
		return fmt.Errorf("打标网段从 %d 条骤降到 %d 条，拒绝覆盖，多半是归属库出了问题", old, len(merged))
	}

	zones := map[string]int{}
	for _, row := range merged {
		zones[row.Zone]++
	}
	if *dryRun {
		fmt.Printf("[信息] (dry-run) 将打标 %d 段（合并前 %d），覆盖 %d 个 zone，跳过 %d 段，多源交叉剔除 %d 段 / %d 个地址\n",
			len(merged), raw, len(zones), skipped, stats.DisputedSpans, stats.DisputedCutSum)
		return nil
	}

	_, hadOld := os.Stat(*out)
	backup := *out + ".prev"
	if hadOld == nil {
		data, err := os.ReadFile(*out)
		if err == nil {
			os.WriteFile(backup, data, 0o644)
		}
	}
	temp := *out + ".tmp"
	if err := os.WriteFile(temp, []byte(ecszone.Render(merged)), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, *out); err != nil {
		os.Remove(temp)
		return err
	}
	if err := verifyWithReload(*api, *out, backup, hadOld == nil); err != nil {
		return err
	}

	fmt.Printf("[成功] 已打标 %d 段（合并前 %d），覆盖 %d 个 zone\n", len(merged), raw, len(zones))
	fmt.Printf("[信息] 跳过 %d 段：云厂商/企业段没有接入运营商，缓存分片退回按 /24\n", skipped)
	if stats.DisputedSpans > 0 {
		fmt.Printf("[信息] 多源交叉剔除 %d 段 / %d 个地址：qqwry 说是大陆，但至少两个独立库判为境外，缓存分片退回按 /24\n",
			stats.DisputedSpans, stats.DisputedCutSum)
	}
	covered, total := ecszone.DirectCoverage(merged, intervals)
	if total > 0 {
		fmt.Printf("[信息] 分片表覆盖 direct4 的 %d%%（%d/%d 个地址）\n", covered*100/total, covered, total)
	}
	type pair struct {
		zone string
		n    int
	}
	list := make([]pair, 0, len(zones))
	for zone, n := range zones {
		list = append(list, pair{zone, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].zone < list[j].zone
	})
	for i, item := range list {
		if i >= 8 {
			break
		}
		fmt.Printf("[信息]   %s: %d 段\n", item.zone, item.n)
	}
	return nil
}

func cmdSharedAnycast(args []string) error {
	fs := flag.NewFlagSet("shared-anycast", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	out := fs.String("out", "", "输出路径(默认 <state>/chnroute/shared-anycast.txt)")
	ctl := fs.String("ctl", envOr("UNBOUND_CTL", "unbound-control"), "unbound-control 路径")
	dryRun := fs.Bool("dry-run", false, "只报告不写文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	geo := geoip.NewGeoDB(
		filepath.Join(*state, "geoip", "GeoLite2-ASN.mmdb"),
		filepath.Join(*state, "geoip", "GeoLite2-City.mmdb"),
		filepath.Join(*state, "geoip", "qqwry.ipdb"))
	report, err := anycast.Run(context.Background(), anycast.Config{
		StateDir: *state, OutPath: *out, UnboundCtl: *ctl, GeoIP: geo, DryRun: *dryRun,
		DBIP: geoip.NewDBIP(
			filepath.Join(*state, "geoip", "dbip-asn.mmdb"),
			filepath.Join(*state, "geoip", "dbip-city.mmdb")),
		IPInfo: geoip.NewIPInfo(filepath.Join(*state, "geoip", "ipinfo-lite.mmdb")),
	})
	if err != nil {
		return err
	}
	if report.Note != "" {
		fmt.Printf("[警告] %s，按 fail-open 处理(不排除任何权威)\n", anycastNote(report.Note))
	}
	fmt.Printf("infra 权威 IP %d 个 -> 服务墙内区域的境外权威 %d 个 -> 判定共享 anycast %d 个\n",
		report.InfraIPs, report.Candidates, len(report.Shared))
	if len(report.ByOrg) > 0 {
		labels := make([]string, 0, len(report.ByOrg))
		for label := range report.ByOrg {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		parts := make([]string, 0, len(labels))
		for _, label := range labels {
			parts = append(parts, fmt.Sprintf("%s=%d", label, report.ByOrg[label]))
		}
		fmt.Println("  分布: " + strings.Join(parts, ", "))
	}
	if report.Kept > 0 {
		fmt.Printf("  人工保留 %d 条\n", report.Kept)
	}
	if len(report.BySource) > 0 {
		names := make([]string, 0, len(report.BySource))
		for name := range report.BySource {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("%s=%d", name, report.BySource[name]))
		}
		fmt.Println("  各源命中: " + strings.Join(parts, ", "))
	}
	if *dryRun {
		for _, item := range report.Shared {
			tail := "  拖带=无"
			if len(item.Outside) > 0 {
				tail = "  拖带=" + strings.Join(item.Outside, ",")
			}
			fmt.Printf("  %-18s %-11s 因=%s%s\n", item.IP, item.Label, item.Because, tail)
		}
	}
	return nil
}

func anycastNote(note string) string {
	switch note {
	case "geoip-unavailable":
		return "ASN 归属库不可用"
	case "direct4-unavailable":
		return "direct4 不可读"
	case "cn-zones-unavailable":
		return "墙内区域清单不可读"
	case "infra-empty":
		return "infra cache 为空，保留现有清单不动"
	}
	return note
}

func envOr(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}

func cmdHelper(args []string) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	sock := fs.String("socket", "", "unix socket 路径")
	config := fs.String("config", "", "配置文件路径")
	root := fs.String("stack-root", "", "源码树根目录")
	auth := fs.String("auth", "", "面板认证文件路径")
	cli := fs.String("cli", "", "dns-stack CLI 路径")
	goBin := fs.String("go-bin", "", "dns-stack Go 二进制路径（分类、ECS 分片等子命令都由它执行）")
	logPath := fs.String("log", "", "审计日志路径")
	sanitizeOnly := fs.Bool("sanitize", false, "从 stdin 读文本，按面板展示前的规则脱敏后写 stdout，然后退出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sanitizeOnly {
		text, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		_, err = os.Stdout.WriteString(helper.Sanitize(string(text), fallbackPath(*config, helper.DefaultConfigPath)))
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("helper 必须以 root 运行：它代面板执行特权操作，非 root 下每个写操作都会失败，而失败点分散在各个操作里、很难指回权限")
	}
	return helper.New(helper.Config{
		SocketPath: *sock, ConfigPath: *config, StackRoot: *root, AuthPath: *auth,
		CLIPath: *cli, GoBin: *goBin, LogPath: *logPath,
	}).Serve()
}

func fallbackPath(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func cmdPanel(args []string) error {
	fs := flag.NewFlagSet("panel", flag.ContinueOnError)

	addr := fs.String("addr", "", "监听地址(默认依次读 PANEL_LISTEN 环境变量、config.env 的 PANEL_LISTEN，最后 127.0.0.1:8080)")
	db := fs.String("db", os.Getenv("DNS_STACK_DB"), "collector SQLite 路径")
	config := fs.String("config", os.Getenv("DNS_STACK_CONFIG"), "配置文件路径")
	auth := fs.String("auth", os.Getenv("DNS_STACK_AUTH"), "认证文件路径")
	state := fs.String("state", os.Getenv("DNS_STACK_STATE"), "状态目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s := panel.New(panel.Config{Addr: panel.ResolveListen(*addr, *config), DBPath: *db, ConfigPath: *config, AuthPath: *auth, StateDir: *state})

	if err := s.PreStartCheck(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

func cmdGeoIPCheck(args []string) error {
	fs := flag.NewFlagSet("geoip-check", flag.ContinueOnError)
	asnPath := fs.String("asn", "", "MaxMind ASN 数据库")
	cityPath := fs.String("city", "", "MaxMind City 数据库")
	cnipPath := fs.String("cnip", "", "qqwry IPDB 数据库")
	asJSON := fs.Bool("json", false, "输出 JSON 数组")
	only := fs.Bool("only-given", false, "只加载显式给出的数据库，其余留空而不套用默认路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ips := fs.Args()
	if len(ips) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if s := strings.TrimSpace(sc.Text()); s != "" {
				ips = append(ips, s)
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
	newDB := geoip.NewGeoDB
	if *only {
		newDB = geoip.NewGeoDBExact
	}
	db := newDB(*asnPath, *cityPath, *cnipPath)
	if *asJSON {
		items := make([]map[string]any, 0, len(ips))
		for _, ip := range ips {
			items = append(items, db.Lookup(ip).JSON())
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(items)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, ip := range ips {
		r := db.Lookup(ip)
		fmt.Fprintf(out, "%s\t%s\t%s\n", ip, r.Label, r.ASOrg)
	}
	return nil
}

func cmdIPSetCheck(args []string) error {
	fs := flag.NewFlagSet("ipset-check", flag.ExitOnError)
	list := fs.String("list", "", "CIDR 列表文件")
	ecsConf := fs.String("ecs-conf", "", "改为读取 Unbound ECS 白名单（send-client-subnet 行）")
	globalOnly := fs.Bool("global-only", false, "只收全局可路由的 IPv4")
	statsOnly := fs.Bool("stats", false, "只输出条数与地址总数")
	showMatch := fs.Bool("show-match", false, "命中时输出覆盖该地址的前缀而不是 0/1")
	overlap := fs.Bool("overlap", false, "输入按网段读入，判断是否与集合区间相交（不只是首地址落在集合内）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list == "" && *ecsConf == "" {
		return fmt.Errorf("必须指定 --list 或 --ecs-conf")
	}

	var res *ipset.LoadResult
	if *ecsConf != "" {
		whitelist, err := cnauth.LoadECSWhitelist(*ecsConf)
		if err != nil {
			return err
		}
		ranges := make([]ipset.Range, 0, len(whitelist))
		for _, prefix := range whitelist {
			if r, ok := ipset.PrefixRange(prefix); ok {
				ranges = append(ranges, r)
			}
		}
		res = &ipset.LoadResult{Set: ipset.New(ranges), Total: len(whitelist)}
	} else {
		f, err := os.Open(*list)
		if err != nil {
			return err
		}
		res, err = ipset.LoadReader(f, ipset.LoadOptions{GlobalOnly: *globalOnly})
		f.Close()
		if err != nil {
			return err
		}
	}
	prefixes := res.Set.Prefixes()
	fmt.Fprintf(os.Stderr, "[信息] 收下 %d 条，跳过 %d 条，合并后 %d 个区间 / %d 条 CIDR，覆盖 %d 个地址\n",
		res.Total, res.Skipped, res.Set.Len(), len(prefixes), res.Set.AddressCount())
	if *statsOnly {
		fmt.Printf("%d\t%d\n", len(prefixes), res.Set.AddressCount())
		return nil
	}

	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if *overlap {
			hit := 0
			if prefix, err := netip.ParsePrefix(strings.Fields(line)[0]); err == nil {
				if r, ok := ipset.PrefixRange(prefix.Masked()); ok && res.Set.Overlaps(r.Lo, r.Hi) {
					hit = 1
				}
			} else if addr, err := netip.ParseAddr(strings.Fields(line)[0]); err == nil && res.Set.Contains(addr) {
				hit = 1
			}
			fmt.Fprintf(out, "%s\t%d\n", line, hit)
			continue
		}
		addr, err := netip.ParseAddr(strings.Fields(line)[0])
		hit := err == nil && res.Set.Contains(addr)
		if *showMatch {
			fmt.Fprintf(out, "%s\t%s\n", line, coveringPrefix(prefixes, addr, hit))
			continue
		}
		value := 0
		if hit {
			value = 1
		}
		fmt.Fprintf(out, "%s\t%d\n", line, value)
	}
	return in.Err()
}

func coveringPrefix(prefixes []netip.Prefix, addr netip.Addr, hit bool) string {
	if !hit {
		return ""
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return prefix.String()
		}
	}
	return ""
}

func cmdDomainCheck(args []string) error {
	fs := flag.NewFlagSet("domain-check", flag.ExitOnError)
	pslPath := fs.String("psl", "", "PSL 文件路径，留空则按默认顺序查找")
	quiet := fs.Bool("quiet", false, "不输出 PSL 来源说明")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var psl *domain.PSL
	var note string
	if *pslPath != "" {
		psl, note = domain.LoadPSL([]string{*pslPath})
	} else {
		psl, note = domain.LoadPSL(nil)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "[信息] %s\n", note)
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.Fields(line)[0]
		defect := domain.ZoneDefect(name, psl)
		if defect == "" {
			defect = "-"
		}
		fmt.Fprintf(out, "%s\t%s\n", domain.Normalize(name), defect)
	}
	return in.Err()
}
