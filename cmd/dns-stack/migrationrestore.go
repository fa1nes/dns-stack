package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dns-stack/dns-stack/internal/panel"
)

func cmdMigrationExport(args []string) error {
	fs := flag.NewFlagSet("migration-export", flag.ContinueOnError)
	out := fs.String("out", "", "输出的 tar.gz 路径，留空写 stdout")
	state := fs.String("state", envOr("STATE_DIR", panel.DefaultStateDir), "状态目录")
	ecs := fs.String("ecs-conf", envOr("ECS_CONF_FILE", ""), "Unbound ECS 白名单路径")
	config := fs.String("config", envOr("DNS_STACK_CONFIG", ""), "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sink := io.Writer(os.Stdout)
	var file *os.File
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return err
		}
		temp := *out + ".tmp"
		created, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		file, sink = created, created
		defer func() {
			if file != nil {
				file.Close()
				os.Remove(temp)
			}
		}()
	}

	cfg := panel.Config{StateDir: *state, ECSConfPath: *ecs, ConfigPath: *config}
	manifest, err := panel.WriteMigrationBundle(sink, cfg, time.Now())
	if err != nil {
		return err
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(*out+".tmp", *out); err != nil {
			return err
		}
		file = nil
		fmt.Fprintf(os.Stderr, "[成功] 迁移包已写入 %s\n", *out)
	}
	fmt.Fprintf(os.Stderr, "[信息] 收录 %d 个文件，缺失 %d 个，显式排除 %d 项\n",
		len(manifest.Files), len(manifest.Missing), len(manifest.Excluded))
	return nil
}

func cmdMigrationRestore(args []string) error {
	fs := flag.NewFlagSet("migration-restore", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "迁移包 tar.gz 路径，必填")
	state := fs.String("state", envOr("STATE_DIR", panel.DefaultStateDir), "状态目录")
	ecs := fs.String("ecs-conf", envOr("ECS_CONF_FILE", ""), "Unbound ECS 白名单路径")
	dryRun := fs.Bool("dry-run", false, "只报告将要写入什么，不落盘")
	noBackup := fs.Bool("no-backup", false, "不备份被覆盖的原文件")
	asJSON := fs.Bool("json", false, "以 JSON 输出报告")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundle == "" {
		return fmt.Errorf("必须指定 --bundle")
	}
	f, err := os.Open(*bundle)
	if err != nil {
		return err
	}
	defer f.Close()

	cfg := panel.Config{StateDir: *state, ECSConfPath: *ecs}
	opt := panel.RestoreOptions{DryRun: *dryRun, Now: time.Now()}
	if !*dryRun && !*noBackup {
		opt.BackupDir = filepath.Join(*state,
			"migration-restore-backup-"+time.Now().Format("20060102150405"))
	}

	report, err := panel.RestoreMigrationBundle(f, cfg, opt)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	written, unchanged := 0, 0
	for _, item := range report.Applied {
		switch item.Action {
		case "written", "would-write":
			written++
		case "unchanged":
			unchanged++
		}
	}
	verb := "已写入"
	if *dryRun {
		verb = "将写入"
	}
	fmt.Printf("[信息] 迁移包 generated-at=%d version=%d\n", report.GeneratedAt, report.Version)
	fmt.Printf("[信息] %s %d 个文件，%d 个内容相同未动\n", verb, written, unchanged)
	for _, item := range report.Applied {
		if item.Action == "unchanged" {
			continue
		}
		fmt.Printf("[信息]   %-44s -> %s (%d 字节)\n", item.Path, item.Target, item.Bytes)
	}
	for _, item := range report.Skipped {
		fmt.Printf("[警告]   跳过 %-40s %s\n", item.Path, item.Reason)
	}
	if report.BackupDir != "" {
		fmt.Printf("[信息] 被覆盖的原文件已备份到 %s\n", report.BackupDir)
	}
	if written == 0 && unchanged == 0 {
		return fmt.Errorf("没有任何文件被恢复，包里可能一个受支持的条目都没有")
	}
	return nil
}
