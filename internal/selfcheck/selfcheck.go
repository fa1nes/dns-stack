package selfcheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type Level string

const (
	LevelOK   Level = "ok"
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
	LevelSkip Level = "skip"
)

type Result struct {
	Name   string `json:"name"`
	Group  string `json:"group"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Role    string   `json:"role"`
	Results []Result `json:"results"`
	OK      int      `json:"ok"`
	Warn    int      `json:"warn"`
	Fail    int      `json:"fail"`
	Skip    int      `json:"skip"`
}

func (r *Report) add(res Result) {
	r.Results = append(r.Results, res)
	switch res.Level {
	case LevelOK:
		r.OK++
	case LevelWarn:
		r.Warn++
	case LevelFail:
		r.Fail++
	case LevelSkip:
		r.Skip++
	}
}

func (r Report) Err() error {
	if r.Fail == 0 {
		return nil
	}
	var names []string
	for _, item := range r.Results {
		if item.Level == LevelFail {
			names = append(names, item.Name)
		}
	}
	return fmt.Errorf("%d 项判据未通过: %s", r.Fail, strings.Join(names, "; "))
}

type checker struct {
	report *Report
	group  string
}

func (c *checker) ok(name, format string, args ...any) {
	c.report.add(Result{Name: name, Group: c.group, Level: LevelOK, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) warn(name, format string, args ...any) {
	c.report.add(Result{Name: name, Group: c.group, Level: LevelWarn, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) fail(name, format string, args ...any) {
	c.report.add(Result{Name: name, Group: c.group, Level: LevelFail, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) skip(name, format string, args ...any) {
	c.report.add(Result{Name: name, Group: c.group, Level: LevelSkip, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) assert(cond bool, name, okDetail, failDetail string) {
	if cond {
		c.ok(name, "%s", okDetail)
		return
	}
	c.fail(name, "%s", failDetail)
}

type Options struct {
	StateDir   string
	ConfigFile string
	Role       string
	Out        io.Writer
	Quick      bool
	Now        func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func fileAge(path string, now time.Time) (time.Duration, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return now.Sub(info.ModTime()), true
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "不到 1 分钟前"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

func Render(report Report, out io.Writer) {
	groups := map[string][]Result{}
	var order []string
	for _, item := range report.Results {
		if _, seen := groups[item.Group]; !seen {
			order = append(order, item.Group)
		}
		groups[item.Group] = append(groups[item.Group], item)
	}
	marks := map[Level]string{LevelOK: "✓", LevelWarn: "!", LevelFail: "✗", LevelSkip: "–"}
	for _, group := range order {
		fmt.Fprintf(out, "\n── %s\n", group)
		for _, item := range groups[group] {
			line := fmt.Sprintf("  %s %s", marks[item.Level], item.Name)
			if item.Detail != "" {
				line += "  → " + item.Detail
			}
			fmt.Fprintln(out, line)
		}
	}
	fmt.Fprintf(out, "\n通过 %d / 关注 %d / 失败 %d / 跳过 %d\n",
		report.OK, report.Warn, report.Fail, report.Skip)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func Run(ctx context.Context, opt Options) (Report, error) {
	report := Report{Role: opt.Role}
	now := opt.now()

	checkModules(ctx, opt, &report)
	checkRoutingData(opt, &report, now)
	checkECSWhitelist(opt, &report, now)
	if !opt.Quick {
		checkResolution(ctx, opt, &report)
	}
	return report, nil
}
