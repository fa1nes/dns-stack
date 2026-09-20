package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/anycast"
	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/chnroute"
	"github.com/dns-stack/dns-stack/internal/cnauth"
	"github.com/dns-stack/dns-stack/internal/ecszone"
	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

const (
	cdnRulesMaxBytes = 32 << 20
	geoDBStaleAfter  = 7 * 24 * time.Hour
)

func Steps() []Step {
	return []Step{
		{
			Name: "geoip", Label: "归属库更新", Every: 24 * time.Hour,
			Run: stepGeoIP,
		},
		{
			Name: "chnroute", Label: "大陆网段重建", Every: 24 * time.Hour,
			Run: stepChnroute, Critical: true,
		},
		{
			Name: "geo-cross", Label: "多源归属交叉校验", Every: 24 * time.Hour,
			Needs: []string{"chnroute"}, Run: stepGeoCross,
		},
		{
			Name: "anycast", Label: "共享 anycast 识别", Every: time.Hour,
			Needs: []string{"chnroute"}, Run: stepAnycast,
		},
		{
			Name: "cdn-rules", Label: "CDN 直连规则集", Every: 24 * time.Hour,
			Run: stepCDNRules,
		},
		{
			Name: "cn-authority", Label: "国内权威与 ECS 白名单", Every: 15 * time.Minute,
			Needs: []string{"chnroute", "geo-cross", "anycast"}, Run: stepCNAuthority,
		},
		{
			Name: "ecs-zone", Label: "ECS 缓存分片表", Every: 24 * time.Hour,
			Needs: []string{"chnroute", "geo-cross"}, Run: stepECSZone,
		},
	}
}

func stepCDNRules(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	var sources []string
	for _, key := range []string{"CDN_RULES_BASE", "CDN_RULES_MIRROR_1", "CDN_RULES_MIRROR_2"} {
		if value := strings.TrimSpace(cfg.Value(key)); value != "" {
			sources = append(sources, value)
		}
	}
	if len(sources) == 0 {
		rt.Warnf("CDN_RULES_BASE 未配置，ECS 白名单只能依赖静态 CDN 表")
		return nil
	}
	client := netfetchClient("")
	res, err := cdnrules.Sync(ctx, cdnrules.SyncOptions{
		StateDir: cfg.StateDir,
		Sources:  sources,
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			return netfetchBytes(ctx, client, url, cdnRulesMaxBytes)
		},
		Logf: rt.Warnf,
	})
	if err != nil {
		return err
	}
	switch {
	case res.Applied:
		rt.Infof("CDN 直连规则集已更新：%d 个 provider / %d 条前缀（来源 %s）",
			res.Providers, res.Prefixes, res.Source)
	case res.Reason != "":
		rt.Infof("CDN 直连规则集未变更：%s", res.Reason)
	}
	return nil
}

func geoipReleaseBase(cfg Config) string {
	if base := strings.TrimSpace(cfg.Value("GEOIP_RELEASE_BASE")); base != "" {
		return base
	}
	repo := pick(cfg.Value("GEOIP_RELEASE_REPO"), cfg.Value("DNS_STACK_BINARY_REPO"))
	if repo == "" {
		return ""
	}
	return "https://github.com/" + repo + "/releases/download/geoip-latest"
}

func stepGeoIP(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	dir := cfg.GeoDir()
	base := geoipReleaseBase(cfg)

	specs := []fetchSpec{
		{
			Kind: "asn", MinBytes: 3_000_000,
			URL:  pick(cfg.Value("GEOIP_ASN_URL"), "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-ASN.mmdb"),
			Dest: filepath.Join(dir, "GeoLite2-ASN.mmdb"),
		},
		{
			Kind: "cnip", MinBytes: 20_000_000,
			URL:  pick(cfg.Value("GEOIP_CNIP_URL"), "https://github.com/nmgliangwei/qqwry.ipdb/releases/latest/download/qqwry.ipdb"),
			Dest: filepath.Join(dir, "qqwry.ipdb"),
		},
	}
	if cfg.Value("GEOIP_ENABLE_CITY") == "1" {
		specs = append(specs, fetchSpec{
			Kind: "city", MinBytes: 20_000_000,
			URL:  pick(cfg.Value("GEOIP_CITY_URL"), "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"),
			Dest: filepath.Join(dir, "GeoLite2-City.mmdb"),
		})
	}
	if url := pick(cfg.Value("GEOIP_DBIP_ASN_URL"), suffixURL(base, "dbip-asn.mmdb")); url != "" {
		specs = append(specs, fetchSpec{Kind: "dbip_asn", URL: url, MinBytes: 3_000_000,
			Dest: filepath.Join(dir, "dbip-asn.mmdb")})
	}
	if url := pick(cfg.Value("GEOIP_DBIP_CITY_URL"), suffixURL(base, "dbip-city.mmdb")); url != "" {
		specs = append(specs, fetchSpec{Kind: "dbip_city", URL: url, MinBytes: 3_000_000,
			Dest: filepath.Join(dir, "dbip-city.mmdb")})
	}

	if rt.Preview {
		rt.Infof("预览模式：跳过归属库下载（%d 个来源）", len(specs))
		return nil
	}
	budget, cancel := context.WithTimeout(ctx, stepFetchBudget)
	defer cancel()
	var updated, unchanged, skipped []string
	for i := range specs {
		if budget.Err() != nil {
			skipped = append(skipped, specs[i].Kind)
			continue
		}
		specs[i].Verify = verifierFor(specs[i].Kind)
		result, err := rt.Fetch(budget, specs[i])
		if err != nil {
			rt.Warnf("%s 下载失败，保留现有库不变：%v", specs[i].Kind, err)
			continue
		}
		if result.NotChanged {
			unchanged = append(unchanged, specs[i].Kind)
			continue
		}
		updated = append(updated, fmt.Sprintf("%s(%dMB)", specs[i].Kind, result.Bytes/1024/1024))
	}
	if len(updated) > 0 {
		rt.InvalidateGeoDB()
		rt.Infof("已更新：%s", strings.Join(updated, " "))
	}
	if len(unchanged) > 0 {
		rt.Infof("已是最新：%s", strings.Join(unchanged, " "))
	}
	if len(skipped) > 0 {
		rt.Warnf("本步骤 %s 预算用尽，未尝试：%s（沿用现有库，下一轮重试）",
			stepFetchBudget, strings.Join(skipped, " "))
	}

	if !exists(filepath.Join(dir, "GeoLite2-ASN.mmdb")) && !exists(filepath.Join(dir, "qqwry.ipdb")) {
		return fmt.Errorf("两个主库都下载失败且本地没有副本，归属展示将不可用")
	}
	var sources, stale []string
	for _, item := range [][2]string{
		{"qqwry.ipdb", "qqwry"}, {"GeoLite2-City.mmdb", "MaxMind"}, {"dbip-city.mmdb", "DB-IP"},
	} {
		path := filepath.Join(dir, item[0])
		if !exists(path) {
			continue
		}
		sources = append(sources, item[1])
		if info, err := os.Stat(path); err == nil {
			if age := time.Since(info.ModTime()); age > geoDBStaleAfter {
				stale = append(stale, fmt.Sprintf("%s(%d天)", item[1], int(age.Hours()/24)))
			}
		}
	}
	if len(sources) < geoaudit.MinSources {
		rt.Warnf("多源交叉可用源只有 %d 个（至少 %d 个才能交叉验证），交叉判据会 fail-open",
			len(sources), geoaudit.MinSources)
	} else {
		rt.Infof("多源交叉可用源 %d 个：%s", len(sources), strings.Join(sources, " "))
	}
	if len(stale) > 0 {
		rt.Warnf("其中 %d 个库已超过 %d 天没更新：%s——交叉判据仍在用它们投票，先查下载是否一直失败",
			len(stale), int(geoDBStaleAfter.Hours()/24), strings.Join(stale, " "))
	}
	return nil
}

func verifierFor(kind string) func(string) error {
	return func(path string) error { return geoip.VerifyFile(kind, path) }
}

func suffixURL(base, name string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/" + name
}

func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func stepChnroute(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	raw := cfg.Chnroute("delegated-apnic-latest.txt")
	if _, err := rt.Fetch(ctx, fetchSpec{
		Kind: "apnic", URL: cfg.APNICURL, Dest: raw, MinBytes: 1_000_000,
		Verify: func(path string) error { return chnroute.VerifyDelegated(path, cfg.Int("CHNROUTE_MIN_ENTRIES", 5000)) },
	}); err != nil {
		return fmt.Errorf("APNIC 拉取失败，保留现有集合不变: %w", err)
	}

	out := cfg.Chnroute("direct4.txt")
	temp := out + ".new"
	report, err := chnroute.Run(chnroute.Options{
		APNICPath:     raw,
		CNIPPath:      filepath.Join(cfg.GeoDir(), "qqwry.ipdb"),
		OutPath:       temp,
		ExcludedPath:  cfg.Chnroute("direct4-excluded.txt"),
		ReverseExlude: cfg.Value("CHNROUTE_REVERSE_EXCLUDE") != "0",
		MaxDropRatio:  cfg.Float("CHNROUTE_EXCLUDE_MAX_RATIO", 0),
	})
	if err != nil {
		os.Remove(temp)
		return fmt.Errorf("chnroute 计算失败，保留现有集合不变: %w", err)
	}
	minAddresses := uint64(cfg.Int("CHNROUTE_MIN_ADDRESSES", 200_000_000))
	if report.CNAddresses < minAddresses {
		os.Remove(temp)
		return fmt.Errorf("大陆覆盖地址仅 %d 个，低于护栏阈值 %d，判定为数据异常，保留现有集合不变",
			report.CNAddresses, minAddresses)
	}

	file, err := os.Open(temp)
	if err != nil {
		return err
	}
	loaded, err := ipset.LoadReader(file, ipset.LoadOptions{GlobalOnly: true})
	file.Close()
	if err != nil {
		os.Remove(temp)
		return err
	}
	if rt.Preview {
		rt.Infof("预览：direct4 %d -> %d 条网段", countPrefixes(out), report.Networks)
		rt.Infof("预览模式：没有加载 nft 集合、没有覆盖 %s", out)
		os.Remove(temp)
		return nil
	}
	if err := rt.LoadNFTSet(ctx, cfg.DirectSet, loaded.Set.Prefixes()); err != nil {
		os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, out); err != nil {
		return err
	}
	rt.Infof("直连集合已更新：%d 条网段，覆盖 %d 个地址", report.Networks, report.CNAddresses)
	return nil
}

func stepGeoCross(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	report, err := geoaudit.Run(geoaudit.Config{
		Direct4Path: cfg.Chnroute("direct4.txt"),
		Sources:     geoaudit.DefaultSources(cfg.GeoDir()),
	})
	if err != nil {
		return err
	}
	if rt.Preview {
		rt.Infof("预览模式：没有覆盖争议/晋级清单")
	} else if err := geoaudit.WriteSnapshots(
		cfg.Chnroute("geo-disputed.txt"), cfg.Chnroute("geo-promoted.txt"), report); err != nil {
		return err
	}
	if report.FailOpen != "" {
		rt.Warnf("交叉判据 fail-open：%s", report.FailOpen)
	}
	rt.Infof("争议 %d 段（%d 地址）、晋级 %d 段（%d 地址），可用源 %s",
		len(report.Disputed), report.DisputedTotal,
		len(report.Promoted), report.PromotedTotal, strings.Join(report.Sources, ","))
	return nil
}

func stepAnycast(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	report, err := anycast.Run(ctx, anycast.Config{
		StateDir:   cfg.StateDir,
		OutPath:    cfg.Chnroute("shared-anycast.txt"),
		UnboundCtl: cfg.UnboundCtl,
		GeoIP:      rt.GeoDB(),
		DBIP: geoip.NewDBIP(
			filepath.Join(cfg.GeoDir(), "dbip-asn.mmdb"),
			filepath.Join(cfg.GeoDir(), "dbip-city.mmdb"),
		),
		DryRun: rt.Preview,
	})
	if err != nil {
		return err
	}
	if report.Note != "" {
		rt.Warnf("本轮未产出（%s），保留上一版清单", report.Note)
		return nil
	}
	if rt.Preview {
		rt.Infof("预览模式：共享 anycast 清单未落盘")
	}
	rt.Infof("infra %d 个地址，候选 %d 个，识别为共享 anycast %d 个",
		report.InfraIPs, report.Candidates, len(report.Shared))
	return nil
}

func stepCNAuthority(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	pairs, zones, err := rt.collectAuthorityPairs(ctx)
	if err != nil {
		return err
	}
	if zones == 0 {
		rt.Warnf("没有候选区域（Unbound 可能刚启动），本轮不改动集合")
		return nil
	}
	pairsPath := cfg.Chnroute(".pairs.tmp")
	if err := os.WriteFile(pairsPath, []byte(pairs), 0o644); err != nil {
		return err
	}
	defer os.Remove(pairsPath)

	resultPath := cfg.Chnroute("cn-authority.txt")
	tempResult := resultPath + ".new"
	tempECS := cfg.ECSConfPath + ".new"

	_, err = cnauth.Run(cnauth.Options{
		Direct4Path:       cfg.Chnroute("direct4.txt"),
		PairsPath:         pairsPath,
		ManualPath:        cfg.Path("manual-cn-zones.txt"),
		SharedPath:        cfg.Chnroute("shared-anycast.txt"),
		DisputedPath:      cfg.Chnroute("geo-disputed.txt"),
		PromotedPath:      cfg.Chnroute("geo-promoted.txt"),
		ResultPath:        tempResult,
		MatchedPath:       cfg.Chnroute("cn-zones-matched.txt"),
		ECSOutPath:        tempECS,
		PrevECSPath:       cfg.ECSConfPath,
		ECSStatePath:      cfg.Chnroute("ecs-accum-state.tsv"),
		SharedExcludedOut: cfg.Chnroute("shared-excluded.txt"),
		SteeredOutPath:    cfg.Chnroute("cdn-steered-zones.txt"),
		CDNRulesPath:      cfg.Path(cdnrules.FileName),
		Aggregate:         cfg.Aggregate,
		AccumTTL:          cfg.Duration("ECS_ACCUM_TTL_SEC", cnauth.DefaultAccumTTL),
		SharedMaxAge:      cfg.Duration("SHARED_ANYCAST_MAX_AGE_SEC", cnauth.DefaultSharedMaxAge),
		CrossMaxAge:       cfg.Duration("GEO_CROSS_MAX_AGE_SEC", cnauth.DefaultCrossMaxAge),
		Out:               rt.Out,
	})
	if err != nil {
		os.Remove(tempResult)
		os.Remove(tempECS)
		return err
	}

	if rt.Preview {
		rt.previewAuthority(resultPath, tempResult, tempECS)
		os.Remove(tempResult)
		os.Remove(tempECS)
		return nil
	}
	if err := rt.commitAuthoritySet(ctx, resultPath, tempResult); err != nil {
		os.Remove(tempECS)
		return err
	}
	return rt.commitECSConf(ctx, tempECS)
}

func stepECSZone(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	direct, err := ecszone.LoadDirectIntervals(cfg.Chnroute("direct4.txt"))
	if err != nil {
		return err
	}
	disputed, err := geoaudit.LoadSnapshot(cfg.Chnroute("geo-disputed.txt"))
	if err != nil {
		rt.Warnf("读不到争议清单，本轮分片表不做扣减：%v", err)
	}
	rows, stats, err := ecszone.Build(ecszone.BuildOptions{
		DBPath:   filepath.Join(cfg.GeoDir(), "qqwry.ipdb"),
		Direct:   direct,
		Disputed: disputed.Set,
	})
	if err != nil {
		return err
	}
	merged, clipped := ecszone.MergeRows(rows)
	if len(merged) == 0 {
		return fmt.Errorf("分片表为空，保留现有表不变")
	}
	covered, total := ecszone.DirectCoverage(merged, direct)
	out := cfg.Path("ecs-ip-zone.txt")
	if rt.Preview {
		rt.Infof("预览：分片表 %d -> %d 行，未覆盖 %s", ecszone.CountDataLines(out), len(merged), out)
	} else {
		temp := out + ".new"
		if err := os.WriteFile(temp, []byte(ecszone.Render(merged)), 0o644); err != nil {
			return err
		}
		if err := os.Rename(temp, out); err != nil {
			os.Remove(temp)
			return err
		}
	}
	percent := 0.0
	if total > 0 {
		percent = float64(covered) * 100 / float64(total)
	}
	rt.Infof("分片表 %d 行（原始 %d，重叠裁剪 %d，无 zone 跳过 %d）",
		len(merged), stats.Raw, clipped, stats.SkippedNoZone)
	rt.Infof("覆盖 direct4 地址空间 %.1f%%（%d / %d）", percent, covered, total)

	unidentified := cfg.Chnroute("ecs-zone-unidentified.txt")
	if rt.Preview {
		rt.Infof("预览：待识别网段 %d 个地址（未落盘）", stats.UnidentifiedCN)
	} else if err := os.WriteFile(unidentified,
		[]byte(ecszone.RenderUnidentified(stats.Unidentified, stats.UnidentifiedCN)), 0o644); err != nil {
		rt.Warnf("待识别网段清单写入失败：%v", err)
	} else if stats.UnidentifiedCN > 0 && !rt.Preview {
		rt.Infof("待识别网段已落盘 %s（%d 个大陆地址在归属库里查不到省份或运营商）",
			unidentified, stats.UnidentifiedCN)
	}
	if percent < 50 {
		rt.Warnf("覆盖率低于 50%%，未覆盖的大陆客户端拿不到 zone 缓存分片（不影响 ECS 发送，影响命中率）")
	}
	return nil
}
