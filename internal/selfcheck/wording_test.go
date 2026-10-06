package selfcheck

import (
	"testing"
	"time"
)

func TestHumanSpanAndAgeSayDifferentThings(t *testing.T) {
	cases := []struct {
		d         time.Duration
		span, ago string
	}{
		{30 * time.Second, "不到 1 分钟", "不到 1 分钟前"},
		{90 * time.Minute, "1 小时", "1 小时前"},
		{72 * time.Hour, "3 天", "3 天前"},
	}
	for _, c := range cases {
		if got := humanSpan(c.d); got != c.span {
			t.Errorf("humanSpan(%s) = %q，期望 %q", c.d, got, c.span)
		}
		if got := humanAge(c.d); got != c.ago {
			t.Errorf("humanAge(%s) = %q，期望 %q", c.d, got, c.ago)
		}
	}
}
