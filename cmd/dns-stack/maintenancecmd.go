package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/alert"
	"github.com/dns-stack/dns-stack/internal/metrics"
	"github.com/dns-stack/dns-stack/internal/pipeline"
)

func cmdMaintenance(args []string) error {
	fs := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	names := make([]string, 0, len(pipeline.MaintenanceSteps()))
	for _, step := range pipeline.MaintenanceSteps() {
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
			status.DaysLeft, status.NotAfter.Format("2006-01-02 15:04"),
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
	}, rt, pipeline.MaintenanceSteps())
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
	watchdog.FWMark = envOr("FWMARK", watchdog.FWMark)
	watchdog.Unit = envOr("UNIT", watchdog.Unit)
	ctx := context.Background()
	if *checkOnly {
		health := watchdog.Diagnose(ctx, rt)
		if health.OK() {
			fmt.Println("[成功] 分流链路健康")
			return nil
		}
		return fmt.Errorf("分流异常：%s", health.Summary())
	}
	health, err := watchdog.Check(ctx, rt)
	var problems []string
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
