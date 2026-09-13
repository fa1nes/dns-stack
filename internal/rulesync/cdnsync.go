package rulesync

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
)

const (
	FileCDNDirect = "cdn-direct.txt"

	cdnSelfTestAddr  = "192.0.2.1"
	cdnShrinkPercent = 20
)

type CDNResult struct {
	Applied     bool
	GeneratedAt int64
	Source      string
	Providers   int
	Prefixes    int
	Reason      string
}

func CDNPath(stateDir string) string { return filepath.Join(stateDir, FileCDNDirect) }

func SyncCDN(ctx context.Context, opt Options) (CDNResult, error) {
	if opt.StateDir == "" {
		return CDNResult{}, fmt.Errorf("状态目录未配置")
	}
	if opt.Fetch == nil {
		return CDNResult{}, fmt.Errorf("未提供下载器")
	}
	dest := CDNPath(opt.StateDir)

	var (
		bestBody []byte
		bestSet  *cdnrules.Set
		bestSrc  string
	)
	for _, src := range opt.Sources {
		src = strings.TrimRight(strings.TrimSpace(src), "/")
		if src == "" {
			continue
		}
		body, err := opt.Fetch(ctx, src+"/"+FileCDNDirect)
		if err != nil {
			opt.logf("CDN 规则集下载失败 %s: %v", src, err)
			continue
		}
		set, err := validateCDN(body)
		if err != nil {
			opt.logf("CDN 规则集校验失败 %s: %v", src, err)
			continue
		}
		if bestSet == nil || set.GeneratedAt().After(bestSet.GeneratedAt()) {
			bestBody, bestSet, bestSrc = body, set, src
		}
	}
	if bestSet == nil {
		return CDNResult{Reason: "所有来源的 CDN 规则集都不可用，保留当前副本"}, nil
	}

	res := CDNResult{
		GeneratedAt: bestSet.GeneratedAt().Unix(),
		Source:      bestSrc,
		Providers:   len(bestSet.Providers()),
		Prefixes:    bestSet.PrefixCount(),
	}
	if old, err := os.ReadFile(dest); err == nil {
		if bytes.Equal(old, bestBody) {
			res.Reason = "内容无变化"
			return res, nil
		}
		if prev, err := cdnrules.Parse(bytes.NewReader(old)); err == nil {
			if bestSet.GeneratedAt().Before(prev.GeneratedAt()) {
				res.Reason = fmt.Sprintf("远端版本旧于本机(%s)，跳过", prev.GeneratedAt().Format("2006-01-02 15:04"))
				return res, nil
			}
			if !opt.Force && prev.PrefixCount() > 100 {
				floor := prev.PrefixCount() * (100 - cdnShrinkPercent) / 100
				if bestSet.PrefixCount() < floor {
					res.Reason = fmt.Sprintf("前缀数从 %d 骤降到 %d（下限 %d），保留旧规则集（确认无误用 --force）",
						prev.PrefixCount(), bestSet.PrefixCount(), floor)
					return res, nil
				}
			}
		}
	}
	if err := writeAtomic(dest, bestBody); err != nil {
		return res, err
	}
	res.Applied = true
	return res, nil
}

func validateCDN(body []byte) (*cdnrules.Set, error) {
	set, err := cdnrules.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(set.Providers()) == 0 {
		return nil, fmt.Errorf("规则集里一个 provider 都没有")
	}
	probe, err := netip.ParseAddr(cdnSelfTestAddr)
	if err != nil {
		return nil, err
	}
	if _, _, _, hit := set.Owner(probe); hit {
		return nil, fmt.Errorf("自检失败: %s 是 TEST-NET-1，任何 CDN 都不该拥有它", cdnSelfTestAddr)
	}
	return set, nil
}
