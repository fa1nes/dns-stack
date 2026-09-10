package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dns-stack/dns-stack/internal/classify"
)

func cmdClassify(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: dns-stack classify <%s> [参数]", classifySubcommands)
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("classify "+sub, flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("DNS_STACK_CONFIG"), "config.env 路径")
	dbPath := fs.String("db", "", "classifier SQLite 路径（默认取 config.env）")
	stateDir := fs.String("state", "", "状态目录（默认取 config.env）")
	limit := fs.Int("limit", 0, "本轮处理上限，0 表示按子命令默认值")
	single := fs.String("domain", "", "只处理这一个域名")
	force := fs.Bool("force", false, "人工确认后跳过条目数骤降门禁，其余校验照常")
	maxAge := fs.Duration("max-age", 0, "复检到期阈值，默认取 config.env")
	withPublish := fs.Bool("publish", false, "流水线末尾执行发布")
	skipAuthority := fs.Bool("skip-authority", false, "流水线跳过权威位置扫描")
	authorityEvery := fs.Duration("authority-every", 6*time.Hour,
		"权威位置扫描的最小间隔，流水线自行判断是否到期（0 表示每轮都扫）")
	deferNotReady := fs.Bool("defer-not-ready", false, "发布门禁未就绪时退出码仍为 0")
	ack := fs.Bool("ack", false, "确认执行破坏性重置")
	resetCNCIDRs := fs.Bool("reset-cn-cidrs", false, "冷启动时连 CN CIDR 一起清空")
	resetPolluted := fs.Bool("reset-polluted", false, "重置时把污染 CIDR 一并置为非活跃")
	purgeObservations := fs.Bool("purge-observations", false, "重置时清空历史观测")
	reason := fs.String("reason", classify.ReasonBaselineInvalidated, "重置原因标记")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	cfg, err := classify.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	engine, err := classify.Open(cfg, time.Now)
	if err != nil {
		return err
	}
	defer engine.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch sub {
	case "pull":
		result, err := engine.Pull()
		if err != nil {
			return err
		}
		return emit(result)

	case "classify":
		report, err := engine.Classify(ctx, *single, orDefault(*limit, 200))
		if err != nil {
			return err
		}
		return emitAndExit(report, report.OK)

	case "classify-authority":
		report, err := engine.ClassifyAuthority(ctx, *limit)
		if err != nil {
			emit(report)
			return err
		}
		return emit(report)

	case "verify-rules":
		report, err := engine.VerifyRules(ctx, orDefault(*limit, 300), *maxAge)
		if err != nil {
			return err
		}
		return emitAndExit(report, report.OK)

	case "build-rules":
		summary, err := engine.BuildRules(*force)
		return emitGuard(summary, err, false)

	case "publish":
		summary, err := engine.BuildRules(false)
		if err != nil {
			return emitGuard(summary, err, *deferNotReady)
		}
		if err := engine.EnsureRepo(); err != nil {
			return err
		}
		result, err := engine.Publish(classify.PublishOptions{})
		if err != nil {
			return err
		}
		return emit(map[string]any{"ok": true, "build": summary, "publish": result})

	case "publish-cold-start":
		if !*ack {
			return fmt.Errorf("缺少 --ack，拒绝生成全动态冷启动规则包")
		}
		summary, err := engine.BuildColdStart(*resetCNCIDRs)
		if err != nil {
			return err
		}
		if err := engine.EnsureRepo(); err != nil {
			return err
		}
		result, err := engine.Publish(classify.PublishOptions{AllowFullReset: *resetCNCIDRs})
		if err != nil {
			return err
		}
		return emit(map[string]any{"ok": true, "build": summary, "publish": result})

	case "publish-ip-reset":
		if !*ack {
			return fmt.Errorf("缺少 --ack，拒绝重置 IP 规则")
		}
		summary, err := engine.BuildIPReset()
		if err != nil {
			return err
		}
		if err := engine.EnsureRepo(); err != nil {
			return err
		}
		result, err := engine.Publish(classify.PublishOptions{AllowIPReset: true})
		if err != nil {
			return err
		}
		return emit(map[string]any{"ok": true, "build": summary, "publish": result})

	case "pipeline":
		report, err := engine.RunPipeline(ctx, classify.PipelineOptions{
			Limit: orDefault(*limit, 200), Force: *force, Publish: *withPublish,
			SkipAuthority: *skipAuthority, AuthorityInterval: *authorityEvery,
		})
		emit(report)
		return err

	case "reset-auto-classifications":
		if !*ack {
			return fmt.Errorf("缺少 --ack，拒绝作废全部自动分类基线")
		}
		if _, err := engine.SyncManualRules(); err != nil {
			return err
		}
		count, err := engine.Store.InvalidateAutomatic(*reason, *purgeObservations, *resetPolluted)
		if err != nil {
			return err
		}
		return emit(map[string]any{
			"ok": true, "invalidated": count, "reason": *reason,
			"purged_observations": *purgeObservations, "reset_polluted": *resetPolluted,
		})

	case "reset-ip-cidrs":
		if !*ack {
			return fmt.Errorf("缺少 --ack，拒绝删除全部 IP CIDR")
		}
		deleted, err := engine.Store.PurgeCIDRs()
		if err != nil {
			return err
		}
		return emit(map[string]any{"ok": true, "deleted": deleted})

	case "update-reference-data":
		result := engine.UpdateReferenceData()
		if err := emit(result); err != nil {
			return err
		}
		if !result.OK {
			os.Exit(1)
		}
		return nil

	case "status":
		counts, err := engine.Store.Counts()
		if err != nil {
			return err
		}
		payload := map[string]any{"ok": true, "counts": counts}
		if *single != "" {
			history, err := engine.Store.History(*single, orDefault(*limit, 24))
			if err != nil {
				return err
			}
			payload["domain"] = *single
			payload["history"] = history
		}
		return emit(payload)
	}
	return fmt.Errorf("未知子命令: classify %s（可用: %s）", sub, classifySubcommands)
}

const classifySubcommands = "pull|classify|classify-authority|verify-rules|build-rules|publish|" +
	"publish-cold-start|publish-ip-reset|pipeline|reset-auto-classifications|reset-ip-cidrs|" +
	"update-reference-data|status"

func orDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func emit(payload any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func emitAndExit(payload any, ok bool) error {
	if err := emit(payload); err != nil {
		return err
	}
	if !ok {
		os.Exit(1)
	}
	return nil
}

func emitGuard(summary classify.BundleSummary, err error, deferred bool) error {
	if err == nil {
		return emit(map[string]any{"ok": true, "build": summary})
	}
	var guard *classify.GuardError
	if !errors.As(err, &guard) {
		return err
	}
	emit(map[string]any{"ok": deferred, "deferred": deferred, "message": guard.Error()})
	if !deferred {
		os.Exit(1)
	}
	return nil
}
