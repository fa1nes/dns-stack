package main

import (
	"flag"
	"fmt"

	"github.com/dns-stack/dns-stack/internal/logtrim"
)

func cmdTrimLogs(args []string) error {
	fs := flag.NewFlagSet("trim-logs", flag.ContinueOnError)
	dir := fs.String("dir", "/var/log/dns-stack", "日志目录")
	keepBytes := fs.Int64("keep-bytes", 2*1024*1024, "每份日志保留的末尾字节数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result, err := logtrim.TrimDirectory(*dir, *keepBytes)
	if err != nil {
		return err
	}
	fmt.Printf("已截断 %d 份日志，每份最多保留 %d 字节\n", result.Trimmed, *keepBytes)
	return nil
}
