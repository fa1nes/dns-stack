package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/dns-stack/dns-stack/internal/chnroute"
)

func cmdChnroute(args []string) error {
	fs := flag.NewFlagSet("chnroute", flag.ContinueOnError)
	apnic := fs.String("apnic", "", "APNIC delegated 记录文件，必填")
	cnip := fs.String("cnip", envOr("CNIP_DB", "/var/lib/dns-stack/geoip/qqwry.ipdb"), "qqwry 归属库，用于补充与反向排除")
	out := fs.String("out", "", "direct4 输出路径，必填")
	excluded := fs.String("excluded-out", "", "反向排除清单输出(默认与 --out 同目录的 direct4-excluded.txt)")
	stats := fs.String("stats", "", "统计输出(NETWORKS/CN_ADDRESSES)")
	noReverse := fs.Bool("no-reverse-exclude", false, "关闭反向排除")
	maxRatio := fs.Float64("exclude-max-ratio", 0, "反向排除命中比例上限(百分比)，0 表示用默认值 5")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apnic == "" || *out == "" {
		return fmt.Errorf("必须指定 --apnic 与 --out")
	}
	if *excluded == "" {
		*excluded = filepath.Join(filepath.Dir(*out), "direct4-excluded.txt")
	}
	reverse := !*noReverse
	if value := envOr("CHNROUTE_REVERSE_EXCLUDE", ""); value != "" {
		reverse = value == "1"
	}
	ratio := *maxRatio
	if ratio == 0 {
		if parsed, err := strconv.ParseFloat(envOr("CHNROUTE_EXCLUDE_MAX_RATIO", ""), 64); err == nil && parsed > 0 {
			ratio = parsed
		}
	}
	_, err := chnroute.Run(chnroute.Options{
		APNICPath:     *apnic,
		CNIPPath:      *cnip,
		OutPath:       *out,
		ExcludedPath:  *excluded,
		StatsPath:     *stats,
		ReverseExlude: reverse,
		MaxDropRatio:  ratio,
	})
	return err
}
