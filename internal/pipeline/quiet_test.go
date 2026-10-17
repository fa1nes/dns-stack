package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuietRunPrintsOnlyWhatChanged(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	opt := options(t, now)
	opt.Quiet = true
	var out bytes.Buffer
	opt.Out = &out

	count, addr, fail := 6800, "52.46.182.252", false
	steps := []Step{
		{Name: "daily", Label: "每日步骤", Every: 24 * time.Hour, Run: func(context.Context, *Runtime) error { return nil }},
		{Name: "authority", Label: "国内权威", Run: func(ctx context.Context, rt *Runtime) error {
			fmt.Fprintf(rt.Out, "  ECS 白名单已更新：%d 条（耗时 %.3fs）\n", count, float64(count)/1000)
			fmt.Fprintf(rt.Out, "[信息]   地址：%s\n", addr)
			if fail {
				return errors.New("权威探测全部超时")
			}
			return nil
		}},
	}
	run := func() string {
		out.Reset()
		opt.Now = func() time.Time { now = now.Add(15 * time.Minute); return now }
		if _, err := Run(context.Background(), opt, NewRuntime(Config{}, nil), steps); err != nil && !fail {
			t.Fatal(err)
		}
		return out.String()
	}

	first := run()
	if !strings.Contains(first, "ECS 白名单已更新：6800 条") || strings.Contains(first, "地址") || strings.Contains(first, "[跳过]") {
		t.Fatalf("应只打印动作行（[信息] 细节进文件），且跳过的步骤不出声:\n%s", first)
	}

	count = 6801
	if second := run(); second != "" {
		t.Fatalf("只有计数变了，应当一行都不打印（汇总由调用方写）:\n%s", second)
	}

	addr = "52.46.187.197"
	if third := run(); !strings.Contains(third, "已更新：6801") || !strings.Contains(third, "[成功] 国内权威") {
		t.Fatalf("地址变了，本轮要出现在日志里:\n%s", third)
	}

	fail = true
	if fourth := run(); !strings.Contains(fourth, "[失败] 国内权威") || !strings.Contains(fourth, "地址：52.46.187.197") {
		t.Fatalf("失败时必须带上细节:\n%s", fourth)
	}

	fail = false
	if fifth := run(); !strings.Contains(fifth, "[成功] 国内权威") {
		t.Fatalf("失败那轮不能刷新摘要，恢复后的第一轮仍要打印:\n%s", fifth)
	}
	run()
	saved, err := os.ReadFile(filepath.Join(opt.StateDir, ".stamps", "authority.log"))
	if err != nil || !strings.Contains(string(saved), "地址：52.46.187.197") {
		t.Fatalf("被省略的那轮完整输出应留在 .stamps/authority.log: %v %q", err, saved)
	}
}

func TestQuietKeepsDailyStepsVerbose(t *testing.T) {
	opt := options(t, time.Unix(1_800_000_000, 0))
	opt.Quiet = true
	opt.Force = true
	var out bytes.Buffer
	opt.Out = &out
	steps := []Step{{Name: "geoip", Label: "归属库更新", Every: 24 * time.Hour, Run: func(ctx context.Context, rt *Runtime) error {
		fmt.Fprintln(rt.Out, "下载 3 个库")
		return nil
	}}}
	for i := 0; i < 2; i++ {
		out.Reset()
		if _, err := Run(context.Background(), opt, NewRuntime(Config{}, &out), steps); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "下载 3 个库") {
			t.Fatalf("每天一次的步骤不省略输出（第 %d 轮）:\n%s", i+1, out.String())
		}
	}
}

func TestQuietReportListsUnchangedSteps(t *testing.T) {
	opt := options(t, time.Unix(1_800_000_000, 0))
	opt.Quiet = true
	steps := []Step{step("a", 0, nil, nil)}
	if _, err := Run(context.Background(), opt, NewRuntime(Config{}, nil), steps); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), opt, NewRuntime(Config{}, nil), steps)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.SameSteps(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("第二轮 a 应被记为与上次相同: %v", got)
	}
}
