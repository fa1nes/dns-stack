package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Status string

const (
	StatusRan     Status = "ran"
	StatusSkipped Status = "skipped"
	StatusFailed  Status = "failed"
	StatusBlocked Status = "blocked"
)

type Step struct {
	Name     string
	Label    string
	Every    time.Duration
	Needs    []string
	Run      func(ctx context.Context, rt *Runtime) error
	Critical bool
}

type StepResult struct {
	Name   string        `json:"name"`
	Label  string        `json:"label"`
	Status Status        `json:"status"`
	Took   time.Duration `json:"took_ns"`
	Err    string        `json:"error,omitempty"`
	Age    time.Duration `json:"age_ns"`
}

type Report struct {
	Steps   []StepResult `json:"steps"`
	Ran     int          `json:"ran"`
	Skipped int          `json:"skipped"`
	Failed  int          `json:"failed"`
	Blocked int          `json:"blocked"`
}

func (r Report) Err() error {
	var names []string
	for _, step := range r.Steps {
		if step.Status == StatusFailed {
			names = append(names, step.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf("流水线步骤失败: %s", strings.Join(names, ", "))
}

type Options struct {
	StateDir string
	Only     []string
	Force    bool
	DryRun   bool
	Out      io.Writer
	Now      func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) stampDir() string {
	return filepath.Join(o.StateDir, ".stamps")
}

func readStamp(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0)
}

func writeStamp(path string, at time.Time) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(strconv.FormatInt(at.Unix(), 10)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

func selected(only []string, name string) bool {
	if len(only) == 0 {
		return true
	}
	for _, want := range only {
		if strings.TrimSpace(want) == name {
			return true
		}
	}
	return false
}

func Run(ctx context.Context, opt Options, rt *Runtime, steps []Step) (Report, error) {
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if err := os.MkdirAll(opt.stampDir(), 0o755); err != nil {
		return Report{}, err
	}
	if err := validate(steps); err != nil {
		return Report{}, err
	}

	now := opt.now()
	report := Report{}
	done := map[string]bool{}

	for _, step := range steps {
		stamp := filepath.Join(opt.stampDir(), step.Name)
		last := readStamp(stamp)
		age := now.Sub(last)
		result := StepResult{Name: step.Name, Label: step.Label, Age: age}

		switch {
		case !selected(opt.Only, step.Name):
			result.Status = StatusSkipped
		case blockedBy(step, done) != "":
			result.Status = StatusBlocked
			result.Err = "上游步骤 " + blockedBy(step, done) + " 本轮失败，按依赖顺序跳过"
		case !opt.Force && !last.IsZero() && step.Every > 0 && age < step.Every:
			result.Status = StatusSkipped
		default:
			result.Status = StatusRan
		}

		if result.Status != StatusRan {
			report.Steps = append(report.Steps, result)
			tally(&report, result.Status)
			if result.Status == StatusSkipped {
				done[step.Name] = true
				fmt.Fprintf(opt.Out, "[跳过] %s（距上次 %s，周期 %s）\n",
					step.Label, humanAge(age, last), humanEvery(step.Every))
			} else {
				fmt.Fprintf(opt.Out, "[阻断] %s：%s\n", step.Label, result.Err)
			}
			continue
		}

		fmt.Fprintf(opt.Out, "[执行] %s\n", step.Label)
		if opt.DryRun {
			result.Status = StatusSkipped
			report.Steps = append(report.Steps, result)
			tally(&report, result.Status)
			done[step.Name] = true
			fmt.Fprintf(opt.Out, "  (dry-run，未执行)\n")
			continue
		}

		started := time.Now()
		err := step.Run(ctx, rt)
		result.Took = time.Since(started)
		if err != nil {
			result.Status = StatusFailed
			result.Err = err.Error()
			fmt.Fprintf(opt.Out, "[失败] %s：%v\n", step.Label, err)
		} else {
			done[step.Name] = true
			if err := writeStamp(stamp, opt.now()); err != nil {
				fmt.Fprintf(opt.Out, "[警告] %s 时间戳写入失败：%v\n", step.Label, err)
			}
			fmt.Fprintf(opt.Out, "[成功] %s（耗时 %s）\n", step.Label, result.Took.Round(time.Millisecond))
		}
		report.Steps = append(report.Steps, result)
		tally(&report, result.Status)

		if err != nil && step.Critical {
			return report, fmt.Errorf("关键步骤 %s 失败，中止本轮: %w", step.Name, err)
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
	}
	return report, report.Err()
}

func tally(r *Report, status Status) {
	switch status {
	case StatusRan:
		r.Ran++
	case StatusSkipped:
		r.Skipped++
	case StatusFailed:
		r.Failed++
	case StatusBlocked:
		r.Blocked++
	}
}

func blockedBy(step Step, done map[string]bool) string {
	for _, need := range step.Needs {
		if !done[need] {
			return need
		}
	}
	return ""
}

func validate(steps []Step) error {
	seen := map[string]bool{}
	for _, step := range steps {
		if step.Name == "" {
			return errors.New("流水线步骤缺少名字")
		}
		if seen[step.Name] {
			return fmt.Errorf("流水线步骤 %s 重复", step.Name)
		}
		for _, need := range step.Needs {
			if !seen[need] {
				return fmt.Errorf("步骤 %s 依赖 %s，但它没有排在前面——依赖必须是拓扑序", step.Name, need)
			}
		}
		seen[step.Name] = true
	}
	return nil
}

func humanAge(age time.Duration, last time.Time) string {
	if last.IsZero() {
		return "从未运行"
	}
	switch {
	case age < time.Minute:
		return "不到 1 分钟"
	case age < time.Hour:
		return fmt.Sprintf("%d 分钟", int(age.Minutes()))
	case age < 48*time.Hour:
		return fmt.Sprintf("%d 小时", int(age.Hours()))
	default:
		return fmt.Sprintf("%d 天", int(age.Hours()/24))
	}
}

func humanEvery(every time.Duration) string {
	switch {
	case every <= 0:
		return "每轮"
	case every < time.Hour:
		return fmt.Sprintf("%d 分钟", int(every.Minutes()))
	case every < 24*time.Hour:
		return fmt.Sprintf("%d 小时", int(every.Hours()))
	default:
		return fmt.Sprintf("%d 天", int(every.Hours()/24))
	}
}

func StepNames(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, step := range steps {
		out = append(out, step.Name)
	}
	sort.Strings(out)
	return out
}
