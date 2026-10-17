package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/statefile"
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
	Same   bool          `json:"same_as_last,omitempty"`
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
	Quiet    bool
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
	return statefile.WriteAtomic(path, []byte(strconv.FormatInt(at.Unix(), 10)+"\n"), 0o644)
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
				if !opt.Quiet {
					fmt.Fprintf(opt.Out, "[跳过] %s（距上次 %s，周期 %s）\n",
						step.Label, humanAge(age, last), humanEvery(step.Every))
				}
			} else {
				fmt.Fprintf(opt.Out, "[阻断] %s：%s\n", step.Label, result.Err)
			}
			continue
		}

		if opt.DryRun {
			fmt.Fprintf(opt.Out, "[执行] %s\n", step.Label)
			result.Status = StatusSkipped
			report.Steps = append(report.Steps, result)
			tally(&report, result.Status)
			done[step.Name] = true
			fmt.Fprintf(opt.Out, "  (dry-run，未执行)\n")
			continue
		}

		var captured bytes.Buffer
		quiet := opt.Quiet && rt != nil && step.Every <= time.Hour
		var stepOut io.Writer
		var lastLog *os.File
		if quiet {
			stepOut, rt.Out = rt.Out, &captured
			if f, ferr := os.Create(stamp + ".log"); ferr == nil {
				lastLog, rt.Out = f, io.MultiWriter(&captured, f)
			}
		} else {
			fmt.Fprintf(opt.Out, "[执行] %s\n", step.Label)
		}
		started := time.Now()
		err := step.Run(ctx, rt)
		result.Took = time.Since(started)
		if quiet {
			rt.Out = stepOut
			if lastLog != nil {
				_ = lastLog.Close()
			}
			digestPath := stamp + ".digest"
			digest := outputDigest(captured.Bytes())
			result.Same = err == nil && readDigest(digestPath) == digest
			if !result.Same {
				fmt.Fprintf(opt.Out, "[执行] %s\n", step.Label)
				if err != nil {
					_, _ = opt.Out.Write(captured.Bytes())
				} else {
					_, _ = opt.Out.Write(withoutDetail(captured.Bytes()))
				}
			}
			if err != nil {
				_ = os.Remove(digestPath)
			} else if werr := statefile.WriteAtomic(digestPath, []byte(digest+"\n"), 0o644); werr != nil {
				fmt.Fprintf(opt.Out, "[警告] %s 输出摘要写入失败：%v\n", step.Label, werr)
			}
		}
		if err != nil {
			result.Status = StatusFailed
			result.Err = err.Error()
			fmt.Fprintf(opt.Out, "[失败] %s：%v\n", step.Label, err)
		} else {
			done[step.Name] = true
			if err := writeStamp(stamp, now); err != nil {
				fmt.Fprintf(opt.Out, "[警告] %s 时间戳写入失败：%v\n", step.Label, err)
			}
			if !result.Same {
				fmt.Fprintf(opt.Out, "[成功] %s（耗时 %s）\n", step.Label, result.Took.Round(time.Millisecond))
			}
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

var digestNumber = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|\d+(?:\.\d+)?`)

func outputDigest(out []byte) string {
	normalized := digestNumber.ReplaceAllFunc(out, func(m []byte) []byte {
		if bytes.Count(m, []byte(".")) >= 3 {
			return m
		}
		return []byte("N")
	})
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:])
}

func withoutDetail(out []byte) []byte {
	var kept bytes.Buffer
	for _, line := range bytes.SplitAfter(out, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("[信息]")) {
			kept.Write(line)
		}
	}
	return kept.Bytes()
}

func readDigest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (r Report) SameSteps() []string {
	var labels []string
	for _, step := range r.Steps {
		if step.Same {
			labels = append(labels, step.Label)
		}
	}
	return labels
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
