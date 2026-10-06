package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dns-stack/dns-stack/internal/pipeline"
)

func cmdRoutingSetup(args []string) error {
	fs := flag.NewFlagSet("routing-setup", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configFile := fs.String("config", "", "配置文件")
	preview := fs.Bool("preview", false, "只打印将要下发的 nft 脚本，不动内核")
	if err := fs.Parse(args); err != nil {
		return err
	}
	action := "apply"
	if rest := fs.Args(); len(rest) > 0 {
		action = rest[0]
	}
	cfg := pipeline.LoadConfig(*stateDir, *configFile)
	rt := pipeline.NewRuntime(cfg, os.Stdout)
	rt.Preview = *preview
	rc := pipeline.LoadRoutingConfig(cfg)
	ctx := context.Background()
	switch action {
	case "apply":
		return rc.Apply(ctx, rt)
	case "revert":
		return rc.Revert(ctx, rt)
	case "status":
		return rc.Status(ctx, rt)
	default:
		return fmt.Errorf("用法: dns-stack routing-setup [apply|revert|status] [--preview]")
	}
}
