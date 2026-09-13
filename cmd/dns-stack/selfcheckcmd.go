package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/selfcheck"
	"github.com/dns-stack/dns-stack/internal/stack"
)

func cmdSelfCheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", "/etc/dns-stack/config.env"), "配置文件")
	role := fs.String("role", "", "角色，留空则从配置读取")
	quick := fs.Bool("quick", false, "跳过需要真实解析的判据")
	full := fs.Bool("full", false, "追加投产校验：备份新鲜度、DoH/DoT 入口、权限、conntrack 水位、面板鉴权")
	asJSON := fs.Bool("json", false, "输出 JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role == "" {
		*role = config.ReadKeys(*conf, "ROLE")["ROLE"]
	}
	if *role == "" {
		*role = stack.RoleCNResolver
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	report, err := selfcheck.Run(ctx, selfcheck.Options{
		StateDir:   *state,
		ConfigFile: *conf,
		Role:       *role,
		Quick:      *quick,
		Full:       *full,
		Out:        os.Stdout,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeCompactJSON(report); err != nil {
			return err
		}
		return report.Err()
	}
	selfcheck.Render(report, os.Stdout)
	return report.Err()
}
