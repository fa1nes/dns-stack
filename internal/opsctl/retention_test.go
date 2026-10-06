package opsctl

import "testing"

func TestVacuumLogsRejectsMinutesBeforeCallingJournalctl(t *testing.T) {
	for _, keep := range []string{"1m", "30m"} {
		if keepRe.MatchString(keep) {
			t.Errorf("%q 被接受了——命令行直接调用时同样会删掉几乎全部系统日志", keep)
		}
	}
	for _, keep := range []string{"7d", "2w"} {
		if !keepRe.MatchString(keep) {
			t.Errorf("%q 是合法的保留期，却被拒绝了", keep)
		}
	}
}
