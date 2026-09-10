package main

import (
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/dns-stack/dns-stack/internal/polluted"
)

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
