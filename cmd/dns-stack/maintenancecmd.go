package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/alert"
	"github.com/dns-stack/dns-stack/internal/metrics"
	"github.com/dns-stack/dns-stack/internal/pipeline"
)

func cmdMaintenance(args []string) error {
	fs := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	names := []string{}
	for _, step := range pipeline.MaintenanceSteps(pipeline.Config{}) {
		names = append(names, step.Name)
	}
	only := fs.String("only", "", "只跑指定步骤："+strings.Join(names, ","))
	force := fs.Bool("force", false, "忽略周期，强制执行")
	reload := fs.Bool("reload-mosproxy", false, "acme.sh 续签后的回调：让 mosproxy 用上新证书")
	syncPanel := fs.Bool("sync-panel-cert", false, "把证书副本同步给面板用户并重启面板")
	checkCert := fs.Bool("check-cert", false, "只检查证书状态，不续签")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := pipeline.LoadConfig(*state, *conf)
	rt := pipeline.NewRuntime(cfg, os.Stdout)

	if *reload {
		return pipeline.ReloadMosproxyCert(context.Background(), rt)
	}
	if *syncPanel {
		return pipeline.SyncPanelCert(context.Background(), rt)
	}
	if *checkCert {
		status, err := pipeline.InspectCert(pipeline.CertPath, pipeline.KeyPath,
			cfg.Value("PUBLIC_IPV4"), time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("[信息] 剩余 %d 天，到期 %s，SAN 含公网 IP=%v，私钥匹配=%v\n",
			status.DaysLeft, status.NotAfter.Local().Format("2006-01-02 15:04 MST"),
			status.SANHasIP, status.KeyMatch)
		return nil
	}

	var selected []string
	if strings.TrimSpace(*only) != "" {
		selected = strings.Split(*only, ",")
	}
	report, runErr := pipeline.Run(context.Background(), pipeline.Options{
		StateDir: *state,
		Only:     selected,
		Force:    *force,
		Out:      os.Stdout,
	}, rt, pipeline.MaintenanceSteps(cfg))
	fmt.Printf("[汇总] 执行 %d / 跳过 %d / 失败 %d\n", report.Ran, report.Skipped, report.Failed)
	return runErr
}

func cmdRoutingWatchdog(args []string) error {
	fs := flag.NewFlagSet("routing-watchdog", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	checkOnly := fs.Bool("check-only", false, "只诊断不修复")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := pipeline.LoadConfig(*state, *conf)
	rt := pipeline.NewRuntime(cfg, os.Stdout)
	watchdog := pipeline.NewWatchdog(cfg)
	watchdog.FWMark = envOr("FWMARK", pipeline.LoadRoutingConfig(cfg).FWMark)
	watchdog.Unit = envOr("UNIT", watchdog.Unit)
	ctx := context.Background()
	if *checkOnly {
		health := watchdog.Diagnose(ctx, rt)
		if prefixes, _ := (access.Store{StateDir: cfg.StateDir}).EnforcedACL(); len(prefixes) > 0 && !pipeline.ACLInstalled(ctx) {
			health.Problems = append(health.Problems, "访问控制表缺失（acl.txt 有授权网段，入口正对全网开放）")
		}
		if health.OK() {
			fmt.Println("[成功] 分流链路健康")
			return nil
		}
		return fmt.Errorf("分流异常：%s", health.Summary())
	}
	var problems []string
	if restored, aclErr := pipeline.RestoreACL(ctx, cfg); aclErr != nil {
		problems = append(problems, "访问控制表缺失且重新下发失败（入口正对全网开放）："+aclErr.Error())
	} else if restored {
		rt.Warnf("访问控制表不在内核里，已按 acl.txt 重新下发")
	}
	health, err := watchdog.Check(ctx, rt)
	if !health.Repaired {
		problems = append(problems, health.Problems...)
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	set, metricsErr := metrics.Fetch(probe, metrics.MosproxyURL)
	cancel()
	if metricsErr != nil {
		problems = append(problems, "mosproxy 指标接口无响应（DNS 入口可能已停止）")
	}
	for _, tag := range set.OfflineUpstreams() {
		problems = append(problems, "上游 "+tag+" 离线（mosproxy 健康检查失败）")
	}
	host, _ := os.Hostname()
	if _, alertErr := alert.Notify(ctx, alert.Options{
		Webhook: cfg.Value("ALERT_WEBHOOK"), StatePath: cfg.Path("alert-state"),
		Host: host, Problems: problems,
	}); alertErr != nil {
		fmt.Fprintf(os.Stderr, "[警告] 告警发送失败，下一轮重试: %v\n", alertErr)
	}
	return err
}
