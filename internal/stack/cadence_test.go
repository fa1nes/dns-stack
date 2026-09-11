package stack

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func timerProps(t *testing.T, dir, unit string) (map[string]string, bool) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, unit+".timer"))
	if err != nil {
		return nil, false
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			props[key] = strings.TrimSpace(value)
		}
	}
	return props, true
}

func parseSpan(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	for _, unit := range []struct {
		suffix string
		scale  time.Duration
	}{{"min", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour}, {"s", time.Second}} {
		digits, ok := strings.CutSuffix(value, unit.suffix)
		if !ok {
			continue
		}
		number, err := strconv.Atoi(digits)
		if err != nil || number <= 0 {
			return 0, false
		}
		return time.Duration(number) * unit.scale, true
	}
	return 0, false
}

func parseCalendar(value string) (time.Duration, bool) {
	switch strings.TrimSpace(value) {
	case "daily":
		return 24 * time.Hour, true
	case "hourly":
		return time.Hour, true
	}
	if rest, ok := strings.CutPrefix(value, "*:0/"); ok {
		minutes, err := strconv.Atoi(strings.TrimSpace(rest))
		if err == nil && minutes > 0 {
			return time.Duration(minutes) * time.Minute, true
		}
	}
	if strings.HasPrefix(value, "*-*-* ") {
		return 24 * time.Hour, true
	}
	return 0, false
}

func timerInterval(props map[string]string) (time.Duration, bool) {
	if value := props["OnUnitActiveSec"]; value != "" {
		return parseSpan(value)
	}
	if value := props["OnCalendar"]; value != "" {
		return parseCalendar(value)
	}
	return 0, false
}

func TestDeclaredCadenceMatchesTheTimerFile(t *testing.T) {
	dir := systemdDir(t)
	checked := 0
	for _, m := range All() {
		if m.Kind != KindJob {
			continue
		}
		props, ok := timerProps(t, dir, m.Unit)
		if !ok {
			t.Errorf("%s 是定时任务却没有 timer 文件", m.Unit)
			continue
		}
		actual, ok := timerInterval(props)
		if !ok {
			t.Errorf("%s.timer 的周期解析不出来（%q / %q），这条判据对它失效了",
				m.Unit, props["OnCalendar"], props["OnUnitActiveSec"])
			continue
		}
		checked++
		if actual != m.Every {
			t.Errorf("%s 登记表声明每 %v 一次，实际 timer 是每 %v 一次——超期判据会用错刻度",
				m.Unit, m.Every, actual)
		}
	}
	if checked == 0 {
		t.Fatal("一个 timer 都没核对到，这条判据本身失效了")
	}
}

func TestOverdueBudgetCoversRandomizedDelay(t *testing.T) {
	dir := systemdDir(t)
	for _, m := range All() {
		if m.Kind != KindJob {
			continue
		}
		props, ok := timerProps(t, dir, m.Unit)
		if !ok {
			continue
		}
		delay := time.Duration(0)
		if value := props["RandomizedDelaySec"]; value != "" {
			parsed, ok := parseSpan(value)
			if !ok {
				t.Errorf("%s.timer 的 RandomizedDelaySec=%q 解析不出来", m.Unit, value)
				continue
			}
			delay = parsed
		}
		worst := m.Every + delay
		if budget := m.Overdue(); budget <= worst {
			t.Errorf("%s 最坏间隔 %v（周期 %v + 抖动 %v）已经够到超期阈值 %v，正常运行也会报警",
				m.Unit, worst, m.Every, delay, budget)
		}
	}
}
