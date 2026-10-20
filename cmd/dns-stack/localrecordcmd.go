package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/access"
	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/metrics"
	"github.com/dns-stack/dns-stack/internal/pipeline"
	"github.com/dns-stack/dns-stack/internal/stack"
	"github.com/dns-stack/dns-stack/internal/statefile"
)

const localRecordsConf = "/etc/unbound/unbound.conf.d/dns-stack-local.conf"

type localRecordEnv struct {
	store    access.Store
	confPath string
	out      io.Writer
	run      func(ctx context.Context, name string, args ...string) (string, error)
	flush    func(ctx context.Context, name string) error
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func cmdLocalRecord(args []string) error {
	fs := flag.NewFlagSet("local-record", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	usage := fmt.Errorf("用法: dns-stack local-record [list] | add <域名> <A|AAAA> <IP> | remove <域名> [类型 [IP]] | sync")
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	var positional, flags []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if role := config.ReadKeys(*conf, "ROLE")["ROLE"]; sub != "list" && role != stack.RoleCNResolver {
		return fmt.Errorf("本地记录只在国内节点上生效，本机角色是 %q", role)
	}
	env := localRecordEnv{
		store: accessStore(*state), confPath: localRecordsConf, out: os.Stdout, run: runCommand,
		flush: func(ctx context.Context, name string) error { _, err := metrics.FlushCache(ctx, name); return err },
	}
	ctx := context.Background()
	switch sub {
	case "list":
		return env.list()
	case "add":
		if len(positional) != 3 {
			return usage
		}
		return env.add(ctx, positional[0], positional[1], positional[2])
	case "remove":
		if len(positional) < 1 || len(positional) > 3 {
			return usage
		}
		for len(positional) < 3 {
			positional = append(positional, "")
		}
		return env.remove(ctx, positional[0], positional[1], positional[2])
	case "sync":
		return env.sync(ctx)
	}
	return usage
}

func (e localRecordEnv) list() error {
	records, err := e.store.LocalRecords()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(e.out, "没有本地记录")
		return nil
	}
	for _, record := range records {
		fmt.Fprintln(e.out, record)
	}
	fmt.Fprintf(e.out, "\n共 %d 条\n", len(records))
	return nil
}

func (e localRecordEnv) add(ctx context.Context, name, kind, value string) error {
	record, err := access.ParseLocalRecord(name, kind, value)
	if err != nil {
		return err
	}
	shadow, err := e.store.Shadowing(record.Name)
	if err != nil {
		return err
	}
	if shadow != "" {
		return fmt.Errorf("%s 会先命中%s，查询到不了本机 Unbound，本地记录不会生效；先把它移出那份名单", record.Name, shadow)
	}
	added, err := e.store.AddLocalRecord(record)
	if err != nil {
		return err
	}
	if !added {
		fmt.Fprintf(e.out, "%s 已经存在，未改动\n", record)
		return nil
	}
	if err := e.writeConf(ctx); err != nil {
		if _, undo := e.store.RemoveLocalRecords(record.Name, record.Type, record.Value); undo != nil {
			err = errors.Join(err, fmt.Errorf("撤回名单也失败: %w", undo))
		}
		return err
	}
	fmt.Fprintf(e.out, "已加入: %s\n", record)
	e.applyName(ctx, record.Name)
	return nil
}

func (e localRecordEnv) remove(ctx context.Context, name, kind, value string) error {
	removed, err := e.store.RemoveLocalRecords(name, kind, value)
	if err != nil {
		return err
	}
	if len(removed) == 0 {
		fmt.Fprintln(e.out, "没有匹配的本地记录，未改动")
		return nil
	}
	if err := e.writeConf(ctx); err != nil {
		return err
	}
	for _, record := range removed {
		fmt.Fprintf(e.out, "已移除: %s\n", record)
	}
	e.applyName(ctx, removed[0].Name)
	return nil
}

func (e localRecordEnv) sync(ctx context.Context) error {
	records, err := e.store.LocalRecords()
	if err != nil {
		return err
	}
	if err := e.writeConf(ctx); err != nil {
		return err
	}
	names := map[string]bool{}
	for _, record := range records {
		if !names[record.Name] {
			names[record.Name] = true
			e.applyName(ctx, record.Name)
		}
	}
	fmt.Fprintf(e.out, "已同步 %d 条本地记录\n", len(records))
	return nil
}

func (e localRecordEnv) writeConf(ctx context.Context) error {
	records, err := e.store.LocalRecords()
	if err != nil {
		return err
	}
	previous, readErr := os.ReadFile(e.confPath)
	if err := statefile.WriteAtomic(e.confPath, []byte(access.RenderUnboundLocal(records)), 0o644); err != nil {
		return fmt.Errorf("写 %s 失败: %w", e.confPath, err)
	}
	out, err := e.run(ctx, "unbound-checkconf")
	if err == nil {
		return nil
	}
	if readErr == nil {
		_ = statefile.WriteAtomic(e.confPath, previous, 0o644)
	} else {
		_ = os.Remove(e.confPath)
	}
	return fmt.Errorf("新配置没通过 unbound-checkconf，已换回原配置: %s", strings.TrimSpace(out))
}

func (e localRecordEnv) applyName(ctx context.Context, name string) {
	ctl := []string{"-c", "/etc/unbound/unbound.conf"}
	records, err := e.store.LocalRecords()
	if err != nil {
		fmt.Fprintf(e.out, "[警告] 读名单失败，Unbound 下次重启后生效: %v\n", err)
		return
	}
	failed := false
	if out, err := e.run(ctx, "unbound-control", append(ctl, "local_data_remove", name)...); err != nil {
		fmt.Fprintf(e.out, "[警告] unbound-control local_data_remove 失败: %v %s\n", err, out)
		failed = true
	}
	for _, record := range access.RecordsFor(records, name) {
		if out, err := e.run(ctx, "unbound-control", append(ctl, "local_data", record.UnboundData())...); err != nil {
			fmt.Fprintf(e.out, "[警告] unbound-control local_data 失败: %v %s\n", err, out)
			failed = true
		}
	}
	if failed {
		fmt.Fprintln(e.out, "配置已写好，Unbound 重启后生效")
	}
	if err := e.flush(ctx, name); err != nil {
		fmt.Fprintf(e.out, "[警告] mosproxy 缓存没清掉（%s），旧答案最多再用一个 TTL: %v\n", name, err)
	}
	if !failed {
		fmt.Fprintln(e.out, "已生效（未重载 Unbound，缓存保留）")
	}
}
