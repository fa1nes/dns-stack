package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dns-stack/dns-stack/internal/backup"
)

func backupConfig(stateDir, configFile string) backup.Config {
	cfg := backup.DefaultConfig()
	if stateDir != "" {
		cfg.StateDir = stateDir
	}
	if configFile != "" {
		cfg.ConfigFile = configFile
	}
	cfg.Out = os.Stdout
	return cfg
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configFile := fs.String("config", "", "配置文件")
	includeSecrets := fs.Bool("include-secrets", false, "包含机密文件(强制 age 加密)")
	automatic := fs.Bool("automatic", false, "定时任务调用：周日生成 weekly 前缀")
	timeout := fs.Duration("timeout", 30*time.Minute, "整体超时")
	prune := fs.Bool("prune", false, "只按保留策略清理旧备份，不生成新备份")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prune {
		res := backupConfig(*stateDir, *configFile).PruneWithConfig()
		if len(res.Removed) == 0 {
			fmt.Println("没有超出保留策略的备份，未删除任何文件")
			return nil
		}
		fmt.Printf("已删除 %d 份旧备份，回收 %.1f MB\n",
			len(res.Removed), float64(res.Bytes)/1024/1024)
		for _, name := range res.Removed {
			fmt.Println("  " + name)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	path, err := backupConfig(*stateDir, *configFile).Backup(ctx, *includeSecrets, *automatic)
	if err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configFile := fs.String("config", "", "配置文件")
	mode := fs.String("mode", "", "导出模式: config|state|full")
	includeLogs := fs.Bool("include-logs", false, "包含日志")
	timeout := fs.Duration("timeout", 30*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode == "" {
		if rest := fs.Args(); len(rest) > 0 {
			*mode = rest[0]
		}
	}
	if *mode == "" {
		return fmt.Errorf("必须指定 --mode config|state|full")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	path, err := backupConfig(*stateDir, *configFile).Export(ctx, *mode, *includeLogs)
	if err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}

func cmdVerifyPackage(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configFile := fs.String("config", "", "配置文件")
	identity := fs.String("identity", "", "age 私钥路径")
	timeout := fs.Duration("timeout", 30*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pkg := ""
	if rest := fs.Args(); len(rest) > 0 {
		pkg = rest[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	_, err := backupConfig(*stateDir, *configFile).VerifyPackage(ctx, pkg, *identity)
	if err != nil {
		return fmt.Errorf("迁移包校验未通过，请勿用它执行 import: %w", err)
	}
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	stateDir := fs.String("state", "", "状态目录")
	configFile := fs.String("config", "", "配置文件")
	noRollback := fs.Bool("no-rollback", false, "失败时不自动回滚（回滚流程内部使用）")
	timeout := fs.Duration("timeout", 60*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("用法: dns-stack import [选项] <迁移包路径>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	return backupConfig(*stateDir, *configFile).Import(ctx, rest[0], !*noRollback)
}
