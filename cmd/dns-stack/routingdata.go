package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dns-stack/dns-stack/internal/pipeline"
)

func cmdRoutingData(args []string) error {
	fs := flag.NewFlagSet("routing-data", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	only := fs.String("only", "", "只跑指定步骤，逗号分隔："+strings.Join(pipeline.StepNames(pipeline.Steps()), ","))
	force := fs.Bool("force", false, "忽略周期，强制执行选中的步骤")
	dryRun := fs.Bool("dry-run", false, "只打印会执行哪些步骤，不真正执行")
	preview := fs.Bool("preview", false, "照常计算但不落盘：不改 nft、不改 ECS 配置、不 reload unbound")
	asJSON := fs.Bool("json", false, "输出 JSON 报告")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var selected []string
	if strings.TrimSpace(*only) != "" {
		selected = strings.Split(*only, ",")
	}
	steps := pipeline.Steps()
	known := map[string]bool{}
	for _, step := range steps {
		known[step.Name] = true
	}
	for _, name := range selected {
		if !known[strings.TrimSpace(name)] {
			return fmt.Errorf("未知步骤 %q，可选：%s",
				strings.TrimSpace(name), strings.Join(pipeline.StepNames(steps), ", "))
		}
	}

	out := os.Stdout
	cfg := pipeline.LoadConfig(*state, *conf)
	rt := pipeline.NewRuntime(cfg, out)
	rt.Preview = *preview
	report, runErr := pipeline.Run(context.Background(), pipeline.Options{
		StateDir: *state,
		Only:     selected,
		Force:    *force,
		DryRun:   *dryRun,
		Preview:  *preview,
		Out:      out,
	}, rt, steps)

	if *asJSON {
		if err := writeCompactJSON(report); err != nil {
			return err
		}
		return runErr
	}
	fmt.Printf("[汇总] 执行 %d / 跳过 %d / 失败 %d / 阻断 %d\n",
		report.Ran, report.Skipped, report.Failed, report.Blocked)
	return runErr
}
