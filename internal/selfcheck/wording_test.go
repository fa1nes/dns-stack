package selfcheck

import (
	"os"
	"path/filepath"
	"strings"
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

var doubledTimeWords = []string{"%s前", "已 %s", "近 %s", "%s 前"}

func TestHumanAgeIsNotUsedWhereTheSentenceAlreadySaysWhen(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "humanAge(") {
				continue
			}
			for _, bad := range doubledTimeWords {
				if strings.Contains(line, bad) {
					t.Errorf("%s:%d 用 humanAge 填 %q——humanAge 已经带了「前」，"+
						"这里要的是时长，请改用 humanSpan\n  %s",
						path, i+1, bad, strings.TrimSpace(line))
				}
			}
		}
	}
}
