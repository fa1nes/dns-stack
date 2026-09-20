package helper

import (
	"strings"
	"testing"
)

func TestCLIFlagsNeverPrecedeTheSubcommand(t *testing.T) {
	h := newTestHelper(t)
	var seen [][]string
	h.onRun = func(argv []string) { seen = append(seen, argv) }

	args := map[string]any{
		"confirm": true, "days": "7", "keep": "7d", "ttl": "60",
		"domains": "a.example", "prefixes": "203.0.113.0/24",
		"domain": "a.example", "unit": "mosproxy", "server": "local-unbound",
	}
	for op, run := range h.operations() {
		seen = nil
		func() {
			defer func() { _ = recover() }()
			run(args)
		}()
		for _, argv := range seen {
			if len(argv) < 2 || !strings.Contains(argv[0], "dns-stack") {
				continue
			}
			if strings.HasPrefix(argv[1], "-") {
				t.Errorf("%s 执行 %v —— 子命令位置上是旗标 %q。\n"+
					"dns-stack 按 os.Args[1] 分派，这条命令只会返回「未知子命令」，"+
					"而且失败是静默的：面板只显示一行看不懂的错误",
					op, argv, argv[1])
			}
		}
	}
}
