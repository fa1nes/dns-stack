package stack

import (
	"strconv"
	"strings"
	"time"
)

const (
	StateOK      = "ok"
	StateWarn    = "warn"
	StateDown    = "down"
	StateUnknown = "unknown"
)

var stateRank = map[string]int{StateOK: 0, StateUnknown: 1, StateWarn: 2, StateDown: 3}

func Worse(a, b string) string {
	if stateRank[b] > stateRank[a] {
		return b
	}
	return a
}

type Status struct {
	Active      string
	TimerActive string
	LastResult  string
	LastRun     int64
	NextRun     int64
	Memory      int64
	Restarts    int
	Unreachable bool
}

func Evaluate(m Module, st Status, now time.Time) (state, note string) {
	if st.Unreachable {
		return StateUnknown, "状态查询失败"
	}

	if m.Kind == KindDaemon {
		switch st.Active {
		case "active":
			return StateOK, "运行中"
		case "activating", "reloading":
			return StateOK, "启动中"
		case "failed":
			return StateDown, "服务已崩溃"
		case "inactive", "deactivating":
			return StateDown, "服务未运行"
		}
		return StateUnknown, "状态未知"
	}

	switch st.Active {
	case "failed":
		return StateWarn, "上次执行失败"
	case "active", "activating":
		return StateOK, "正在执行"
	}

	if st.TimerActive != "" && st.TimerActive != "active" {
		return StateWarn, "定时器未启动，这个模块不会自己运行"
	}
	if st.LastRun <= 0 {
		return StateWarn, "从未运行过"
	}
	elapsed := now.Sub(time.Unix(st.LastRun, 0))
	if budget := m.Overdue(); budget > 0 && elapsed > budget {
		return StateWarn, "已经 " + HumanSpan(elapsed) + "没有运行"
	}
	if st.LastResult != "" && st.LastResult != "success" {
		return StateWarn, "上次执行结果为 " + st.LastResult
	}
	return StateOK, HumanSpan(elapsed) + "前运行过"
}

func HumanSpan(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "不到 1 分钟"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " 分钟"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " 小时"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + " 天"
	}
}

func Headline(verdict string, troubled int) string {
	switch verdict {
	case StateOK:
		return "全部正常"
	case StateDown:
		return "关键模块中断"
	case StateUnknown:
		return "状态查不到"
	default:
		return strconv.Itoa(troubled) + " 个模块需要关注"
	}
}

func DisplayWidth(text string) int {
	width := 0
	for _, r := range text {
		if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
			(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
			(r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) ||
			(r >= 0xfe30 && r <= 0xfe6f) || (r >= 0xff00 && r <= 0xff60) ||
			(r >= 0xffe0 && r <= 0xffe6)) {
			width += 2
			continue
		}
		width++
	}
	return width
}

func Pad(text string, width int) string {
	if gap := width - DisplayWidth(text); gap > 0 {
		return text + strings.Repeat(" ", gap)
	}
	return text
}
