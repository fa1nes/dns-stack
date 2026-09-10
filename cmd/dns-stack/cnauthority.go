package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dns-stack/dns-stack/internal/cnauth"
)

func envDuration(key string, def time.Duration) time.Duration {
	if seconds, err := strconv.Atoi(envOr(key, "")); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return def
}

func cmdCNAuthority(args []string) error {
	fs := flag.NewFlagSet("cn-authority", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	pairs := fs.String("pairs", "", "(区域, 权威地址, rto) 记录文件，必填")
	direct := fs.String("direct4", "", "direct4 列表(默认 <state>/chnroute/direct4.txt)")
	manual := fs.String("manual", "", "人工补充区域(默认 <state>/manual-cn-zones.txt)")
	shared := fs.String("shared", "", "共享 anycast 清单(默认 <state>/chnroute/shared-anycast.txt)")
	disputed := fs.String("disputed", "", "多源争议清单(默认 <state>/chnroute/geo-disputed.txt)")
	promoted := fs.String("promoted", "", "多源晋级清单(默认 <state>/chnroute/geo-promoted.txt)")
	psl := fs.String("psl", envOr("PSL_FILE", ""), "Public Suffix List 路径")
	result := fs.String("out", "", "权威网段输出(默认 <state>/chnroute/cn-authority.txt)")
	matched := fs.String("matched", "", "墙内区域清单输出(默认 <state>/chnroute/cn-zones-matched.txt)")
	ecsOut := fs.String("ecs-out", "", "ECS 白名单输出，必填")
	prevECS := fs.String("ecs-prev", "", "现网 ECS 白名单，用于累积保留")
	ecsState := fs.String("ecs-state", "", "ECS 累积状态(默认 <state>/chnroute/ecs-accum-state.tsv)")
	sharedOut := fs.String("shared-excluded-out", envOr("SHARED_EXCLUDED_OUTPUT", ""), "共享 anycast 排除清单输出")
	agg := fs.Int("aggregate", 24, "大陆权威聚合前缀")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pairs == "" {
		return fmt.Errorf("必须指定 --pairs")
	}
	if *ecsOut == "" {
		return fmt.Errorf("必须指定 --ecs-out")
	}
	chn := func(name string) string { return filepath.Join(*state, "chnroute", name) }
	if *direct == "" {
		*direct = chn("direct4.txt")
	}
	if *manual == "" {
		*manual = filepath.Join(*state, "manual-cn-zones.txt")
	}
	if *shared == "" {
		*shared = chn("shared-anycast.txt")
	}
	if *disputed == "" {
		*disputed = chn("geo-disputed.txt")
	}
	if *promoted == "" {
		*promoted = chn("geo-promoted.txt")
	}
	if *result == "" {
		*result = chn("cn-authority.txt")
	}
	if *matched == "" {
		*matched = chn("cn-zones-matched.txt")
	}
	if *ecsState == "" {
		*ecsState = chn("ecs-accum-state.tsv")
	}
	var pslPaths []string
	if *psl != "" {
		pslPaths = []string{*psl}
	}
	var clock func() time.Time
	if forced, err := strconv.ParseInt(envOr("FAKE_NOW_TS", ""), 10, 64); err == nil && forced > 0 {
		clock = func() time.Time { return time.Unix(forced, 0) }
	}

	_, err := cnauth.Run(cnauth.Options{
		Direct4Path:       *direct,
		PairsPath:         *pairs,
		ManualPath:        *manual,
		SharedPath:        *shared,
		DisputedPath:      *disputed,
		PromotedPath:      *promoted,
		PSLPaths:          pslPaths,
		ResultPath:        *result,
		MatchedPath:       *matched,
		ECSOutPath:        *ecsOut,
		PrevECSPath:       *prevECS,
		ECSStatePath:      *ecsState,
		SharedExcludedOut: *sharedOut,
		Aggregate:         *agg,
		AccumTTL:          envDuration("ECS_ACCUM_TTL_SEC", cnauth.DefaultAccumTTL),
		SharedMaxAge:      envDuration("SHARED_ANYCAST_MAX_AGE_SEC", cnauth.DefaultSharedMaxAge),
		CrossMaxAge:       envDuration("GEO_CROSS_MAX_AGE_SEC", cnauth.DefaultCrossMaxAge),
		Now:               clock,
	})
	return err
}
