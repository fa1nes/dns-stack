package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/collect"
	"github.com/dns-stack/dns-stack/internal/geoip"
)

func cmdQueryLog(args []string) error {
	fs := flag.NewFlagSet("query-log", flag.ContinueOnError)
	stateDir := fs.String("state", envOr("DNS_STACK_STATE", "/var/lib/dns-stack"), "状态目录")
	dbPath := fs.String("db", "", "collector SQLite 路径，默认 <state>/collector.db")
	since := fs.Duration("since", 24*time.Hour, "回看时长")
	kind := fs.String("kind", "", "递归类型: blocked|refused|cache|forward|recursive")
	domain := fs.String("domain", "", "域名模糊匹配")
	subnet := fs.String("subnet", "", "来源子网模糊匹配")
	exitPath := fs.String("exit", "", "出口路径: direct|tunnel|hongkong")
	limit := fs.Int("limit", collect.DefaultLogLimit, "返回条数上限")
	asJSON := fs.Bool("json", false, "输出 JSON")
	csvOut := fs.String("csv", "", "导出 CSV 到指定文件")
	breakdown := fs.Bool("breakdown", false, "只输出按递归类型的计数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		path = filepath.Join(*stateDir, "collector.db")
	}
	db, err := collect.OpenDB(path)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now().Add(-*since)

	if *breakdown {
		counts, err := collect.KindBreakdown(ctx, db, start)
		if err != nil {
			return err
		}
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(counts)
		}
		var total int64
		for _, item := range counts {
			total += item.Count
		}
		fmt.Printf("近 %s 共 %d 条查询\n\n", *since, total)
		for _, item := range counts {
			share := 0.0
			if total > 0 {
				share = float64(item.Count) * 100 / float64(total)
			}
			fmt.Printf("  %-12s %-8s %8d  %5.1f%%\n", item.Label, item.Kind, item.Count, share)
		}
		return nil
	}

	if *csvOut != "" && *limit < collect.MaxLogExport {
		*limit = collect.MaxLogExport
	}
	rows, err := collect.QueryLog(ctx, db, collect.LogFilter{
		Since: start, Kind: *kind, Domain: *domain,
		ClientSubnet: *subnet, ExitPath: *exitPath, Limit: *limit,
	})
	if err != nil {
		return err
	}
	geo := geoip.NewGeoDB(
		filepath.Join(*stateDir, "geoip", "GeoLite2-ASN.mmdb"),
		filepath.Join(*stateDir, "geoip", "GeoLite2-City.mmdb"),
		filepath.Join(*stateDir, "geoip", "qqwry.ipdb"))
	set, _ := cdnrules.Load(cdnrules.Path(*stateDir))
	collect.Annotate(rows, geo, set)

	if *csvOut != "" {
		file, err := os.Create(*csvOut)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := collect.WriteLogCSV(file, rows); err != nil {
			return err
		}
		fmt.Printf("已导出 %d 条到 %s\n", len(rows), *csvOut)
		return nil
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("没有符合条件的记录")
		return nil
	}
	fmt.Printf("%-19s %-34s %-6s %-10s %-19s %-9s %-8s\n",
		"时间", "域名", "类型", "递归类型", "来源子网(ECS)", "出口", "耗时ms")
	for _, row := range rows {
		fmt.Printf("%-19s %-34s %-6s %-10s %-19s %-9s %8.1f\n",
			time.Unix(row.TS, 0).Format("2006-01-02 15:04:05"),
			truncate(row.Domain, 34), row.QType, row.KindLabel,
			orDash(row.ClientSubnet), orDash(row.ExitPath), row.ElapsedMS)
	}
	fmt.Printf("\n共 %d 条\n", len(rows))
	return nil
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}
