package stack

import (
	"testing"
	"time"
)

var now = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func jobModule(every time.Duration) Module {
	return Module{Unit: "job", Name: "任务", Kind: KindJob, Every: every}
}

func at(offset time.Duration) int64 { return now.Add(-offset).Unix() }

func TestNeverTriggeredTimerIsFlagged(t *testing.T) {
	state, note := Evaluate(jobModule(24*time.Hour),
		Status{Active: "waiting", TimerActive: "active"}, now)
	if state != StateWarn || note != "从未运行过" {
		t.Fatalf("装好但从未触发的 timer 必须报警，得到 %s/%q", state, note)
	}
}

func TestEnabledButUnstartedTimerIsFlagged(t *testing.T) {
	state, note := Evaluate(jobModule(24*time.Hour),
		Status{Active: "inactive", TimerActive: "inactive", LastRun: at(time.Hour)}, now)
	if state != StateWarn {
		t.Fatalf("timer 未启动时即使产物很新也要报警，得到 %s/%q", state, note)
	}
}

func TestOverdueJobIsFlaggedAndFreshOneIsNot(t *testing.T) {
	module := jobModule(24 * time.Hour)
	fresh, _ := Evaluate(module, Status{Active: "waiting", TimerActive: "active",
		LastRun: at(20 * time.Hour), LastResult: "success"}, now)
	if fresh != StateOK {
		t.Fatalf("周期内运行过的任务不该报警，得到 %s", fresh)
	}
	stale, note := Evaluate(module, Status{Active: "waiting", TimerActive: "active",
		LastRun: at(96 * time.Hour), LastResult: "success"}, now)
	if stale != StateWarn || note != "已经 4 天没有运行" {
		t.Fatalf("超出 3 倍周期必须报警，得到 %s/%q", stale, note)
	}
}

func TestFrequentJobKeepsAnHourOfSlack(t *testing.T) {
	module := jobModule(5 * time.Minute)
	if budget := module.Overdue(); budget != time.Hour {
		t.Fatalf("高频任务的宽限期不得低于 1 小时，否则一次重启就误报，得到 %v", budget)
	}
	state, _ := Evaluate(module, Status{Active: "waiting", TimerActive: "active",
		LastRun: at(40 * time.Minute), LastResult: "success"}, now)
	if state != StateOK {
		t.Fatalf("5 分钟周期的任务 40 分钟没跑仍在宽限内，得到 %s", state)
	}
}

func TestFailedRunIsNotHiddenByFreshTimestamp(t *testing.T) {
	state, note := Evaluate(jobModule(6*time.Hour), Status{Active: "waiting",
		TimerActive: "active", LastRun: at(time.Minute), LastResult: "exit-code"}, now)
	if state != StateWarn || note != "上次执行结果为 exit-code" {
		t.Fatalf("刚跑过但失败的任务不能算正常，得到 %s/%q", state, note)
	}
}

func TestDaemonStates(t *testing.T) {
	daemon := Module{Unit: "d", Name: "常驻", Kind: KindDaemon}
	for _, item := range []struct {
		active string
		want   string
	}{
		{"active", StateOK}, {"activating", StateOK},
		{"failed", StateDown}, {"inactive", StateDown}, {"", StateUnknown},
	} {
		if state, _ := Evaluate(daemon, Status{Active: item.active}, now); state != item.want {
			t.Errorf("常驻服务 %q 应判为 %s，得到 %s", item.active, item.want, state)
		}
	}
}

func TestUnreachableNeverLooksHealthy(t *testing.T) {
	for _, m := range []Module{jobModule(time.Hour), {Kind: KindDaemon}} {
		if state, _ := Evaluate(m, Status{Unreachable: true, Active: "active"}, now); state != StateUnknown {
			t.Errorf("查不到状态时必须报未知而不是沿用字段，得到 %s", state)
		}
	}
}

func TestUnknownOutranksOKInRollup(t *testing.T) {
	if Worse(StateOK, StateUnknown) != StateUnknown {
		t.Error("一批模块里只要有查不到的，整体就不能报全部正常")
	}
	if Worse(StateWarn, StateUnknown) != StateWarn {
		t.Error("已知的告警比查不到更严重")
	}
	if Worse(StateWarn, StateDown) != StateDown {
		t.Error("中断比告警更严重")
	}
}

func TestEveryModuleIsReachableByExactlyOneRole(t *testing.T) {
	for _, m := range All() {
		if len(m.Roles) == 0 {
			t.Errorf("%s 没有归属角色，两个角色的面板都看不到它", m.Unit)
		}
		if m.Name == "" || m.Purpose == "" || m.Group == "" {
			t.Errorf("%s 缺少中文名/用途/分组，面板会显示空白", m.Unit)
		}
		if m.Kind == KindJob && m.Every <= 0 {
			t.Errorf("%s 是定时任务却没声明周期，超期判据永远不会生效", m.Unit)
		}
	}
	for _, role := range []string{RoleCNResolver, RoleGlobalBuilder} {
		seen := map[string]bool{}
		for _, unit := range UnitsForRole(role) {
			if seen[unit] {
				t.Errorf("角色 %s 的模块清单里 %s 重复", role, unit)
			}
			seen[unit] = true
		}
	}
}

func TestDisplayWidthCountsCJKAsTwoColumns(t *testing.T) {
	if DisplayWidth("归属交叉校验") != 12 {
		t.Fatalf("中文按两列计宽，得到 %d", DisplayWidth("归属交叉校验"))
	}
	if DisplayWidth("ECS 缓存分片") != 12 {
		t.Fatalf("中英混排要分别计宽，得到 %d", DisplayWidth("ECS 缓存分片"))
	}
	if got := Pad("大陆网段", 12); got != "大陆网段    " {
		t.Fatalf("补齐后总宽应为 12，得到 %q", got)
	}
}
