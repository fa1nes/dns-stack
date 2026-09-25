package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/backup"
	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/stack"
)

func cmdDBMigrate(args []string) error {
	fs := flag.NewFlagSet("db-migrate", flag.ContinueOnError)
	stateDir := fs.String("state", "/var/lib/dns-stack", "状态目录")
	configFile := fs.String("config", config.DefaultPath, "配置文件")
	backupDir := fs.String("backup-dir", "/var/backups/dns-stack", "备份目录")
	timeout := fs.Duration("timeout", 30*time.Minute, "整体超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	role := config.ReadKeys(*configFile, "ROLE")["ROLE"]
	if role != stack.RoleCNResolver {
		return fmt.Errorf("db-migrate 仅适用于国内解析节点")
	}
	writers := []string{"dns-stack-panel", "mosproxy"}

	var stopped []string
	defer func() {
		for _, unit := range stopped {
			exec.Command("systemctl", "restart", unit+".service").Run()
		}
	}()
	for _, unit := range writers {
		if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit+".service").Run() == nil {
			if err := exec.CommandContext(ctx, "systemctl", "stop", unit+".service").Run(); err != nil {
				return fmt.Errorf("停止 %s 失败: %w", unit, err)
			}
			stopped = append(stopped, unit)
		}
	}

	dest := filepath.Join(*backupDir, "schema-migration-"+time.Now().Format("20060102150405"))
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	databases, err := findDatabases(*stateDir)
	if err != nil {
		return err
	}
	if len(databases) == 0 {
		return fmt.Errorf("%s 下没有任何 .db 文件，没有可迁移的库", *stateDir)
	}
	for _, path := range databases {
		rel, _ := filepath.Rel(*stateDir, path)
		target := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := backup.SnapshotSQLite(path, target); err != nil {
			return fmt.Errorf("备份 %s 失败: %w", rel, err)
		}
		fmt.Printf("[数据库迁移] 已备份 %s\n", rel)
	}

	probe := []string{"collect", "stats"}
	cmd := exec.CommandContext(ctx, selfBinary(), probe...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s 库迁移失败: %w", strings.Join(probe, " "), err)
	}
	fmt.Println("[数据库迁移] 已按当前 schema 打开各数据库（缺表会自动建、旧列会就地迁移）")

	for _, path := range databases {
		if !backup.IntegrityOK(path) {
			return fmt.Errorf("完整性检查失败: %s", path)
		}
	}
	fmt.Printf("[数据库迁移] 迁移完成；备份位于 %s\n", dest)
	return nil
}

func findDatabases(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".db") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
