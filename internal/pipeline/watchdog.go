package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultFWMark         = "0x1d5"
	DefaultRoutingUnit    = "dns-stack-recursive-routing.service"
	DefaultMinSetEntries  = 1000
	DefaultMaxRepairs     = 5
	DefaultAuthorityRatio = 40
)

type WatchdogConfig struct {
	Config     Config
	FWMark     string
	Unit       string
	MinEntries int
	MaxRepairs int
	AuthRatio  int
}

type Health struct {
	Problems  []string
	TunnelUp  bool
	Repaired  bool
	FailCount int
}

func (h Health) OK() bool { return len(h.Problems) == 0 }

func (h Health) Summary() string { return strings.Join(h.Problems, "; ") }

func (w WatchdogConfig) markPattern() *regexp.Regexp {
	mark := strings.TrimPrefix(w.FWMark, "0x")
	return regexp.MustCompile(`0x0*` + regexp.QuoteMeta(mark) + `\b`)
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func (w WatchdogConfig) failStatePath() string {
	return w.Config.Path("routing-watchdog.fail")
}

func readFailCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func writeFailCount(path string, n int) {
	os.WriteFile(path, []byte(strconv.Itoa(n)+"\n"), 0o644)
}

func (w WatchdogConfig) Diagnose(ctx context.Context, rt *Runtime) Health {
	mark := w.markPattern()
	var problems []string

	chain, _ := run(ctx, "nft", "list", "chain", "inet", w.Config.NFTTable, "output")
	if !regexp.MustCompile(`meta mark set ` + mark.String()).MatchString(chain) {
		problems = append(problems, "分流链缺失或无打标规则")
	}
	nat, _ := run(ctx, "nft", "list", "chain", "inet", w.Config.NFTTable, "postrouting")
	if !(mark.MatchString(nat) && strings.Contains(nat, "masquerade")) {
		problems = append(problems, "NAT 源地址改写链缺失")
	}
	rules, _ := run(ctx, "ip", "rule", "show")
	if !regexp.MustCompile(`fwmark ` + mark.String()).MatchString(rules) {
		problems = append(problems, "fwmark 策略路由规则缺失")
	}
	if rt.NFTSetCount(ctx, w.Config.DirectSet) < w.MinEntries {
		problems = append(problems, "大陆 IP 集合过小或为空")
	}
	baseline := countPrefixes(w.Config.Chnroute("cn-authority.txt"))
	if baseline >= 20 {
		if rt.NFTSetCount(ctx, w.Config.AuthoritySet) < baseline*w.AuthRatio/100 {
			problems = append(problems,
				"墙内权威集合过小或为空(国内域名会走隧道拿境外节点)")
		}
	}

	_, tunnelErr := run(ctx, "ip", "link", "show", w.Config.TunnelIf)
	return Health{
		Problems:  problems,
		TunnelUp:  tunnelErr == nil,
		FailCount: readFailCount(w.failStatePath()),
	}
}

func (w WatchdogConfig) flushPoisonedCache(ctx context.Context, rt *Runtime) {
	if _, err := run(ctx, "unbound-control", "flush_zone", "."); err != nil {
		rt.Warnf("清空 Unbound 缓存失败——故障期间的污染答案可能仍在缓存中")
		rt.Warnf("  请手工执行: unbound-control flush_zone .")
		return
	}
	rt.Infof("已清空 Unbound 缓存(故障期间可能缓存了污染答案)")
}

func (w WatchdogConfig) Check(ctx context.Context, rt *Runtime) (Health, error) {
	health := w.Diagnose(ctx, rt)
	state := w.failStatePath()

	if health.OK() {
		if health.FailCount != 0 {
			rt.Infof("分流已恢复正常")
			w.flushPoisonedCache(ctx, rt)
			writeFailCount(state, 0)
		}
		return health, nil
	}

	if !health.TunnelUp {
		rt.Infof("隧道 %s 未就绪，等待 wg-quick 拉起(不计入失败次数)", w.Config.TunnelIf)
		rt.Infof("  %s", health.Summary())
		return health, nil
	}

	if health.FailCount >= w.MaxRepairs {
		return health, fmt.Errorf(
			"已连续 %d 次修复失败，停止自动重建，等待人工处理：%s（排查 journalctl -u %s -n 50；处理完后 rm -f %s）",
			health.FailCount, health.Summary(), w.Unit, state)
	}

	attempt := health.FailCount + 1
	writeFailCount(state, attempt)
	rt.Warnf("检测到分流异常，尝试重建(第 %d 次)：%s", attempt, health.Summary())

	if _, err := run(ctx, "systemctl", "restart", w.Unit); err != nil {
		return health, fmt.Errorf("重建命令执行失败 systemctl restart %s: %w", w.Unit, err)
	}
	after := w.Diagnose(ctx, rt)
	if !after.OK() {
		return after, fmt.Errorf("重建后仍未恢复：%s", after.Summary())
	}
	w.flushPoisonedCache(ctx, rt)
	writeFailCount(state, 0)
	health.Repaired = true
	rt.Infof("分流已重建并验证通过")
	return health, nil
}
