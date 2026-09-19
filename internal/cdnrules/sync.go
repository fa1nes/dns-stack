package cdnrules

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	FileName = "cdn-direct.txt"

	selfTestAddr  = "192.0.2.1"
	shrinkPercent = 20
)

type SyncOptions struct {
	StateDir string
	Sources  []string
	Force    bool
	Fetch    Fetcher
	Logf     func(format string, args ...any)
}

func (o SyncOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

type SyncResult struct {
	Applied     bool
	GeneratedAt int64
	Source      string
	Providers   int
	Prefixes    int
	Reason      string
}

func Path(stateDir string) string { return filepath.Join(stateDir, FileName) }

func Sync(ctx context.Context, opt SyncOptions) (SyncResult, error) {
	if opt.StateDir == "" {
		return SyncResult{}, fmt.Errorf("状态目录未配置")
	}
	if opt.Fetch == nil {
		return SyncResult{}, fmt.Errorf("未提供下载器")
	}
	dest := Path(opt.StateDir)

	var (
		bestBody []byte
		bestSet  *Set
		bestSrc  string
	)
	for _, src := range opt.Sources {
		src = strings.TrimRight(strings.TrimSpace(src), "/")
		if src == "" {
			continue
		}
		body, err := opt.Fetch(ctx, src+"/"+FileName)
		if err != nil {
			opt.logf("CDN 规则集下载失败 %s: %v", src, err)
			continue
		}
		set, err := validate(body)
		if err != nil {
			opt.logf("CDN 规则集校验失败 %s: %v", src, err)
			continue
		}
		if bestSet == nil || set.GeneratedAt().After(bestSet.GeneratedAt()) {
			bestBody, bestSet, bestSrc = body, set, src
		}
	}
	if bestSet == nil {
		return SyncResult{Reason: "所有来源的 CDN 规则集都不可用，保留当前副本"}, nil
	}

	res := SyncResult{
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
		if prev, err := Parse(bytes.NewReader(old)); err == nil {
			if bestSet.GeneratedAt().Before(prev.GeneratedAt()) {
				res.Reason = fmt.Sprintf("远端版本旧于本机(%s)，跳过",
					prev.GeneratedAt().Format("2006-01-02 15:04"))
				return res, nil
			}
			if !opt.Force && prev.PrefixCount() > 100 {
				floor := prev.PrefixCount() * (100 - shrinkPercent) / 100
				if bestSet.PrefixCount() < floor {
					res.Reason = fmt.Sprintf(
						"前缀数从 %d 骤降到 %d（下限 %d），保留旧规则集（确认无误用 --force）",
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

func validate(body []byte) (*Set, error) {
	set, err := Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(set.Providers()) == 0 {
		return nil, fmt.Errorf("规则集里一个 provider 都没有")
	}
	probe, err := netip.ParseAddr(selfTestAddr)
	if err != nil {
		return nil, err
	}
	if _, _, _, hit := set.Owner(probe); hit {
		return nil, fmt.Errorf("自检失败: %s 是 TEST-NET-1，任何 CDN 都不该拥有它", selfTestAddr)
	}
	return set, nil
}

func writeAtomic(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp := path + ".new"
	if err := os.WriteFile(temp, body, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}
