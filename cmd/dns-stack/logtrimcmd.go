package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

func cmdTrimLogs(args []string) error {
	fs := flag.NewFlagSet("trim-logs", flag.ContinueOnError)
	dir := fs.String("dir", "/var/log/dns-stack", "日志目录")
	keepBytes := fs.Int64("keep-bytes", 2<<20, "每份日志保留的末尾字节数")
	dropStale := fs.Bool("drop-stale", false, "删除已不属于任何现存模块的僵尸日志")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dropStale {
		removed, freed, err := dropStaleLogs(*dir)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Println("没有僵尸日志")
		} else {
			fmt.Printf("已删除 %d 份僵尸日志，回收 %.1f MB: %s\n",
				len(removed), float64(freed)/1024/1024, strings.Join(removed, " "))
		}
	}
	result, err := trimDirectory(*dir, *keepBytes)
	if err != nil {
		return err
	}
	fmt.Printf("已截断 %d 份日志，每份保留末尾 %d 字节\n", result.Trimmed, *keepBytes)
	return nil
}

const staleLogMinAge = 14 * 24 * time.Hour

func dropStaleLogs(dir string) ([]string, int64, error) {
	live := map[string]bool{}
	for _, module := range stack.All() {
		if module.LogFile != "" {
			live[module.LogFile] = true
		}
	}
	if len(live) == 0 {
		return nil, 0, fmt.Errorf("模块清单里没有任何模块声明 LogFile，" +
			"「不在清单里就删」会把还在用的日志一并删掉，拒绝执行")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	open := openLogFiles()
	var removed []string
	var freed int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".log") || live[name] {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) < staleLogMinAge {
			continue
		}
		if open[path] {
			continue
		}
		if err := os.Remove(path); err != nil {
			continue
		}
		removed = append(removed, name)
		freed += info.Size()
	}
	return removed, freed, nil
}

func openLogFiles() map[string]bool {
	out := map[string]bool{}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, proc := range procs {
		if !proc.IsDir() || proc.Name()[0] < '0' || proc.Name()[0] > '9' {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", proc.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", proc.Name(), "fd", fd.Name()))
			if err == nil && strings.HasSuffix(target, ".log") {
				out[strings.TrimSuffix(target, " (deleted)")] = true
			}
		}
	}
	return out
}
