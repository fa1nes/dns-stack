package pipeline

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func step(name string, every time.Duration, needs []string, run func() error) Step {
	return Step{
		Name: name, Label: name, Every: every, Needs: needs,
		Run: func(ctx context.Context, rt *Runtime) error {
			if run == nil {
				return nil
			}
			return run()
		},
	}
}

func options(t *testing.T, now time.Time) Options {
	t.Helper()
	return Options{
		StateDir: t.TempDir(),
		Out:      io.Discard,
		Now:      func() time.Time { return now },
	}
}

func statusOf(report Report, name string) Status {
	for _, item := range report.Steps {
		if item.Name == name {
			return item.Status
		}
	}
	return ""
}

func TestFailedUpstreamBlocksDownstreamInsteadOfUsingStaleData(t *testing.T) {
	ran := false
	steps := []Step{
		step("chnroute", time.Hour, nil, func() error { return errors.New("APNIC 拉取失败") }),
		step("cn-authority", time.Hour, []string{"chnroute"}, func() error {
			ran = true
			return nil
		}),
	}
	report, err := Run(context.Background(), options(t, time.Now()), nil, steps)
	if err == nil {
		t.Fatal("上游失败时整轮应当报错")
	}
	if ran {
		t.Error("上游失败后下游仍然执行了——那会拿上一版 direct4 去算权威集合")
	}
	if got := statusOf(report, "cn-authority"); got != StatusBlocked {
		t.Errorf("下游状态应当是 blocked，得到 %q", got)
	}
}

func TestStepIsSkippedUntilItsPeriodElapses(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	opt := options(t, base)
	calls := 0
	steps := []Step{step("geoip", 24*time.Hour, nil, func() error { calls++; return nil })}

	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("首轮应当执行，calls=%d", calls)
	}

	opt.Now = func() time.Time { return base.Add(6 * time.Hour) }
	report, err := Run(context.Background(), opt, nil, steps)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("周期未到不该重复执行，calls=%d", calls)
	}
	if got := statusOf(report, "geoip"); got != StatusSkipped {
		t.Errorf("状态应当是 skipped，得到 %q", got)
	}

	opt.Now = func() time.Time { return base.Add(25 * time.Hour) }
	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("周期到了应当再执行一次，calls=%d", calls)
	}
}

func TestForceIgnoresThePeriod(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	opt := options(t, base)
	calls := 0
	steps := []Step{step("geoip", 24*time.Hour, nil, func() error { calls++; return nil })}

	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatal(err)
	}
	opt.Force = true
	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("--force 应当忽略周期，calls=%d", calls)
	}
}

func TestFailedStepDoesNotAdvanceItsStamp(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	opt := options(t, base)
	fail := true
	steps := []Step{step("geoip", 24*time.Hour, nil, func() error {
		if fail {
			return errors.New("boom")
		}
		return nil
	})}

	if _, err := Run(context.Background(), opt, nil, steps); err == nil {
		t.Fatal("应当报错")
	}
	stamp := filepath.Join(opt.stampDir(), "geoip")
	if _, err := os.Stat(stamp); !os.IsNotExist(err) {
		t.Fatal("失败的步骤不该写时间戳，否则失败会被当成成功而跳过一整个周期")
	}

	fail = false
	opt.Now = func() time.Time { return base.Add(time.Minute) }
	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatalf("上轮失败后下一轮应当立刻重试: %v", err)
	}
	if !readStamp(stamp).Equal(base.Add(time.Minute)) {
		t.Error("成功后应当写入时间戳")
	}
}

func TestOutOfOrderDependencyIsRejectedUpFront(t *testing.T) {
	steps := []Step{
		step("cn-authority", time.Hour, []string{"chnroute"}, nil),
		step("chnroute", time.Hour, nil, nil),
	}
	if _, err := Run(context.Background(), options(t, time.Now()), nil, steps); err == nil {
		t.Fatal("依赖排在后面应当在执行前就被拒绝")
	}
}

func TestOnlySelectsASingleStep(t *testing.T) {
	geoipRan, chnrouteRan := false, false
	steps := []Step{
		step("geoip", time.Hour, nil, func() error { geoipRan = true; return nil }),
		step("chnroute", time.Hour, nil, func() error { chnrouteRan = true; return nil }),
	}
	opt := options(t, time.Now())
	opt.Only = []string{"chnroute"}
	if _, err := Run(context.Background(), opt, nil, steps); err != nil {
		t.Fatal(err)
	}
	if geoipRan {
		t.Error("--only chnroute 不该执行 geoip")
	}
	if !chnrouteRan {
		t.Error("--only chnroute 应当执行 chnroute")
	}
}

func TestRealStepsAreTopologicallyOrdered(t *testing.T) {
	if err := validate(Steps()); err != nil {
		t.Fatalf("生产流水线定义本身不是拓扑序: %v", err)
	}
}

func TestCNAuthorityDependsOnEveryUpstreamItReads(t *testing.T) {
	var target Step
	for _, item := range Steps() {
		if item.Name == "cn-authority" {
			target = item
		}
	}
	for _, need := range []string{"chnroute", "geo-cross", "anycast"} {
		found := false
		for _, have := range target.Needs {
			if have == need {
				found = true
			}
		}
		if !found {
			t.Errorf("cn-authority 读 %s 的产物，必须声明依赖，否则会拿到上一轮的旧清单", need)
		}
	}
}
