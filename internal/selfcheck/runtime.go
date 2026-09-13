package selfcheck

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/pipeline"
	"github.com/dns-stack/dns-stack/internal/resolve"
	"github.com/dns-stack/dns-stack/internal/stack"

	_ "modernc.org/sqlite"
)

const (
	offshoreResolver  = "10.100.0.3"
	recursivePort     = 5335
	offshoreProbeName = "www.wikipedia.org"
	mosproxyMetrics   = "http://127.0.0.1:8888/metrics"
	collectorWindow   = time.Hour
	minDirectEntries  = 1000
	authorityRatioPct = 40
)

func shellOut(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func checkFailedUnits(ctx context.Context, report *Report) {
	c := &checker{report: report, group: "模块健康"}
	out, err := shellOut(ctx, "systemctl", "list-units", "dns-stack-*",
		"--state=failed", "--no-legend", "--plain")
	if err != nil {
		c.skip("无失败单元", "查不到 systemd 单元状态")
		return
	}
	var failed []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			failed = append(failed, fields[0])
		}
	}
	if len(failed) == 0 {
		c.ok("无失败单元", "含 timer 触发的一次性任务")
		return
	}
	c.fail("无失败单元", "%s——排查 systemctl status <单元> && journalctl -u <单元> -n 30",
		strings.Join(failed, " "))
}

func checkResolverPair(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "解析链路"}
	if _, err := shellOut(ctx, "unbound-control", "-c", "/etc/unbound/unbound.conf", "status"); err != nil {
		c.fail("Unbound 响应", "unbound-control 无响应: %v", err)
	} else {
		c.ok("Unbound 响应", "unbound-control 正常")
	}
	probe := func(name, server, domain string, timeout time.Duration) bool {
		client, err := resolve.NewClient(server, recursivePort, timeout)
		if err != nil {
			c.skip(name, "解析器地址无效: %v", err)
			return false
		}
		answer := client.Query(ctx, domain, dnswire.TypeA)
		v4, _ := resolve.Addresses(answer)
		return answer.Status == resolve.StatusOK && len(v4) > 0
	}
	c.assert(probe("本机递归解析", "127.0.0.1", "example.com", 3*time.Second),
		"本机递归解析", "example.com 有 A 记录", "example.com 查不到 A 记录")
	c.assert(probe("香港递归可用", offshoreResolver, "example.com", 6*time.Second),
		"香港递归可用", "降级备份就绪",
		"本机 Unbound 一旦故障将无降级目标——排查香港机 unbound 服务")
	c.assert(probe("境外域名解析", "127.0.0.1", offshoreProbeName, 8*time.Second),
		"境外域名解析", offshoreProbeName+" 解析正常",
		"依次检查 wg0 隧道 / 分流链 / 香港 NAT")
}

func checkNFTSets(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver || !pipeline.HasNFT() {
		return
	}
	c := &checker{report: report, group: "出口分流"}
	cfg := pipeline.LoadConfig(opt.StateDir, opt.ConfigFile)
	rt := pipeline.NewRuntime(cfg, nil)
	direct := rt.NFTSetCount(ctx, cfg.DirectSet)
	if direct < minDirectEntries {
		c.fail("大陆 IP 集合规模", "仅 %d 段（下限 %d），国内递归查询会被误导进隧道", direct, minDirectEntries)
		return
	}
	authority := rt.NFTSetCount(ctx, cfg.AuthoritySet)
	baseline := countRows(filepath.Join(opt.StateDir, "chnroute", "cn-authority.txt"))
	if baseline >= 20 && authority < baseline*authorityRatioPct/100 {
		c.fail("墙内权威集合规模",
			"仅 %d 段(基线 %d 段)，国内域名会走隧道拿境外 CDN 节点——恢复: systemctl restart dns-stack-recursive-routing",
			authority, baseline)
		return
	}
	c.ok("出口分流集合", "大陆 %d 段 / 墙内权威 %d 段", direct, authority)
}

func checkCollector(ctx context.Context, opt Options, report *Report, now time.Time) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "查询采集"}
	dbPath := filepath.Join(opt.StateDir, "collector.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)&mode=ro")
	if err != nil {
		c.skip("事件落库", "打不开 %s", dbPath)
		return
	}
	defer db.Close()
	cutoff := now.Add(-collectorWindow).Unix()
	var fresh int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM query_events WHERE ts > ?", cutoff).Scan(&fresh); err != nil {
		c.skip("事件落库", "读不到 query_events: %v", err)
		return
	}
	if fresh == 0 {
		c.warn("事件落库",
			"近 %s 没有事件落库（可能只是无人查询）——确认 SELECT MAX(ts) FROM query_events",
			humanAge(collectorWindow))
		return
	}
	c.ok("事件落库", "近 %s 落库 %d 条", humanAge(collectorWindow), fresh)
}

func checkThrottling(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "查询采集"}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mosproxyMetrics, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.skip("限流未被打满", "取不到 mosproxy 限流指标(管理 API 无响应?)")
		return
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	counters := map[string]int{"rejected_cc_total": -1, "rejected_qps_total": -1}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, want := counters[fields[0]]; !want {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			counters[fields[0]] = int(value)
		}
	}
	cc, qps := counters["rejected_cc_total"], counters["rejected_qps_total"]
	if cc < 0 && qps < 0 {
		c.skip("限流未被打满", "指标里没有 rejected_cc_total / rejected_qps_total")
		return
	}
	if cc > 0 || qps > 0 {
		c.warn("限流未被打满",
			"曾有查询被拒(累计 并发 %d / QPS %d)——limit 是全局配额，打满时自己的查询也会被拒",
			max(cc, 0), max(qps, 0))
		return
	}
	c.ok("限流未被打满", "并发/QPS 配额均未触顶")
}

func checkBinaryProvenance(opt Options, report *Report) {
	c := &checker{report: report, group: "模块健康"}
	binary := "/opt/dns-stack/bin/dns-stack-go"
	recorded, err := readRecordedSum(binary + ".sha256")
	if err != nil {
		c.skip("二进制来自 CI 产物", "读不到 %s.sha256，无法核对来源", binary)
		return
	}
	actual, err := fileSum(binary)
	if err != nil {
		c.skip("二进制来自 CI 产物", "算不出 %s 的校验和: %v", binary, err)
		return
	}
	c.assert(actual == recorded, "二进制来自 CI 产物",
		fmt.Sprintf("sha256 与安装时记录一致(%s)", recorded[:12]),
		fmt.Sprintf("sha256 与安装时记录不符(记录 %s，实际 %s)——这台机器不编译，"+
			"二进制只应来自 CI Release，被替换过就说明有人绕过了这条约定",
			recorded[:12], actual[:12]))
}
