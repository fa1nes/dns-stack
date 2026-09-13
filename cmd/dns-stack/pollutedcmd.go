package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/polluted"
)

func cmdCollectPolluted(args []string) error {
	fs := flag.NewFlagSet("collect-polluted", flag.ContinueOnError)
	stateDir := fs.String("state", envOrDefault("DNS_STACK_STATE", "/var/lib/dns-stack"), "状态目录")
	configPath := fs.String("config", envOrDefault("CONFIG_FILE", config.DefaultPath), "配置文件")
	rounds := fs.Int("rounds", polluted.DefaultRounds, "探测轮数")
	maxAge := fs.Int("max-age-days", 30, "证据过期天数")
	minObs := fs.Int("min-observations", 2, "计入所需的最少独立观测次数")
	timeout := fs.Duration("timeout", 20*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys := config.ReadKeys(*configPath, "TRUSTED_SERVER", "TRUSTED_PORT")
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	_, err := polluted.Collect(ctx, polluted.CollectOptions{
		StateDir:        *stateDir,
		TrustedServer:   keys["TRUSTED_SERVER"],
		TrustedPort:     atoiOr(keys["TRUSTED_PORT"], polluted.DefaultTrustedPort),
		Rounds:          *rounds,
		MaxAgeDays:      *maxAge,
		MinObservations: *minObs,
		Out:             os.Stdout,
	})
	return err
}

func cmdPollutedEvidence(args []string) error {
	fs := flag.NewFlagSet("polluted-evidence", flag.ContinueOnError)
	raw := fs.String("raw", "", "本轮探测到的原始应答地址，必填")
	evidence := fs.String("evidence", "", "现有证据 JSON")
	oldOutput := fs.String("old-output", "", "上一版 polluted-ip.txt，用于冷启动与新增计数")
	activeOut := fs.String("active-out", "", "生效地址列表输出，必填")
	evidenceOut := fs.String("evidence-out", "", "证据 JSON 输出，必填")
	cidrOut := fs.String("cidr-out", "", "CIDR 汇总输出")
	stats := fs.String("stats", "", "统计输出(observed added total raw_unique)")
	maxAge := fs.Int("max-age-days", 30, "证据过期天数")
	minObs := fs.Int("min-observations", 2, "计入所需的最少独立观测次数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *raw == "" || *activeOut == "" || *evidenceOut == "" {
		return fmt.Errorf("必须指定 --raw、--active-out 与 --evidence-out")
	}
	var clock func() time.Time
	if forced, err := strconv.ParseInt(envOr("FAKE_NOW_TS", ""), 10, 64); err == nil && forced > 0 {
		clock = func() time.Time { return time.Unix(forced, 0) }
	}
	_, err := polluted.Run(polluted.Options{
		RawPath:         *raw,
		EvidencePath:    *evidence,
		OldOutputPath:   *oldOutput,
		ActiveOutPath:   *activeOut,
		EvidenceOutPath: *evidenceOut,
		CIDROutPath:     *cidrOut,
		StatsPath:       *stats,
		MaxAgeDays:      *maxAge,
		MinObservations: *minObs,
		Now:             clock,
	})
	return err
}
