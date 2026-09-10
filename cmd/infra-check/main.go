package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/dns-stack/dns-stack/internal/infra"
)

func main() {
	fs := flag.NewFlagSet("infra-check", flag.ExitOnError)
	_ = fs.Parse(os.Args[1:])
	s, err := infra.Parse(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, e := range s.Pairs() {
		rto := "-1"
		if e.HasRTO {
			rto = fmt.Sprintf("%d", e.RTO)
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", e.Zone, e.IP, rto)
	}
	fmt.Fprintf(os.Stderr, "[信息] 有效 %d 条，跳过 %d 条，区域 %d 个\n", len(s.Entries), s.Skipped, len(s.Zones()))
}
