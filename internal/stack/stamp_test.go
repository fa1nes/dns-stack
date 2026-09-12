package stack

import (
	"testing"
	"time"
)

func TestTimerStampParsesWhatSystemdActuallyPrints(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("本机没有时区库: %v", err)
	}
	previous := time.Local
	time.Local = shanghai
	t.Cleanup(func() { time.Local = previous })

	want := time.Date(2026, 9, 12, 1, 30, 46, 0, shanghai).Unix()
	for _, value := range []string{
		"Sat 2026-09-12 01:30:46 CST",
		"2026-09-12 01:30:46 CST",
		"Sat 2026-09-12 01:30:46",
		"Sat 2026-09-12 01:30:46.123456 CST",
	} {
		if got := TimerStamp(value); got != want {
			t.Errorf("TimerStamp(%q) = %d，期望 %d", value, got, want)
		}
	}
}

func TestServiceStampAcceptsUnixAndHumanForms(t *testing.T) {
	if got := ServiceStamp("@1789147846"); got != 1789147846 {
		t.Errorf("--timestamp=unix 形式应直接取值，得到 %d", got)
	}
	if got := ServiceStamp("1789147846"); got != 1789147846 {
		t.Errorf("裸秒数应直接取值，得到 %d", got)
	}
	if ServiceStamp("Sat 2026-09-12 01:30:46 CST") == 0 {
		t.Error("默认的人类可读时间戳必须能解析，否则「已运行多久」永远是空")
	}
}

func TestAbsentStampsAreZeroNotEpoch(t *testing.T) {
	for _, value := range []string{"", "n/a", "infinity", "0", "[not set]", "whenever"} {
		if got := TimerStamp(value); got != 0 {
			t.Errorf("TimerStamp(%q) 应为 0，得到 %d", value, got)
		}
		if got := ServiceStamp(value); got != 0 {
			t.Errorf("ServiceStamp(%q) 应为 0，得到 %d", value, got)
		}
	}
}

func TestRawMicrosecondsStillWork(t *testing.T) {
	if got := TimerStamp("1789147846000000"); got != 1789147846 {
		t.Errorf("裸微秒应折算成秒，得到 %d", got)
	}
}

func TestTimerStampFeedsTheOverdueVerdict(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("本机没有时区库: %v", err)
	}
	previous := time.Local
	time.Local = shanghai
	t.Cleanup(func() { time.Local = previous })

	module := Module{Unit: "dns-stack-chnroute", Kind: KindJob, Every: 24 * time.Hour}
	last := TimerStamp("Sat 2026-09-12 01:30:46 CST")
	if last == 0 {
		t.Fatal("解析失败会让每个定时任务都报「从未运行过」")
	}
	now := time.Unix(last, 0).Add(6 * time.Hour)
	state, note := Evaluate(module, Status{
		Active: "waiting", TimerActive: "active", LastResult: "success", LastRun: last,
	}, now)
	if state != StateOK {
		t.Fatalf("6 小时前跑过的日更任务应判正常，得到 %s/%q", state, note)
	}
}
