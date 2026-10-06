package helper

import "testing"

func TestLogRetentionNeverAcceptsJournalctlMinutes(t *testing.T) {
	for _, keep := range []string{"1m", "30m", "12m"} {
		if retentionPattern.MatchString(keep) {
			t.Errorf("%q 被接受了——journalctl --vacuum-time 里 m 是分钟不是月，"+
				"「保留 1 个月」会变成删掉 1 分钟之前的全部系统日志", keep)
		}
	}
	for _, keep := range []string{"7d", "2w", "30d", "365d"} {
		if !retentionPattern.MatchString(keep) {
			t.Errorf("%q 是合法的保留期，却被拒绝了", keep)
		}
	}
}
