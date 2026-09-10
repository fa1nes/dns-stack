package classify

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/dns-stack/dns-stack/internal/resolve"
)

var controlDomains = []string{"www.baidu.com", "www.qq.com", "www.taobao.com"}

type ViewHealth struct {
	OK                bool     `json:"ok"`
	Reason            string   `json:"reason"`
	Controls          int      `json:"controls"`
	Required          int      `json:"required"`
	CNResponsive      int      `json:"cn_responsive"`
	ForeignResponsive int      `json:"foreign_responsive"`
	FailedControls    []string `json:"failed_controls"`
}

type BatchHealth struct {
	Total             int    `json:"total"`
	CNViewFailed      int    `json:"cn_view_failed"`
	ForeignViewFailed int    `json:"foreign_view_failed"`
	StatusUnknown     int    `json:"status_unknown"`
	Decisive          int    `json:"decisive"`
	Warning           string `json:"warning,omitempty"`
}

func parallelMap[T, R any](items []T, workers int, fn func(T) R) []R {
	out := make([]R, len(items))
	if len(items) == 0 {
		return out
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}
	var cursor atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				index := int(cursor.Add(1)) - 1
				if index >= len(items) {
					return
				}
				out[index] = fn(items[index])
			}
		}()
	}
	wg.Wait()
	return out
}

type bothViews struct {
	domain  string
	cn      *resolve.Outcome
	foreign *resolve.Outcome
}

func (e *Engine) inspect(ctx context.Context, cn, foreign *resolve.Client, name string) bothViews {
	var cnOut, foreignOut resolve.Outcome
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); cnOut = resolve.Chain(ctx, cn, name) }()
	go func() { defer wg.Done(); foreignOut = resolve.Chain(ctx, foreign, name) }()
	wg.Wait()
	return bothViews{domain: name, cn: &cnOut, foreign: &foreignOut}
}

func (e *Engine) ValidateViews(ctx context.Context) (ViewHealth, error) {
	cn, foreign, err := e.Resolvers()
	if err != nil {
		return ViewHealth{}, err
	}
	observed := parallelMap(controlDomains, len(controlDomains), func(name string) bothViews {
		return e.inspect(ctx, cn, foreign, name)
	})
	health := ViewHealth{
		Controls: len(controlDomains),
		Required: min(2, len(controlDomains)),
		Reason:   "ok",
	}
	for _, item := range observed {
		if hasGlobalAnswer(item.cn) {
			health.CNResponsive++
		}
		if hasGlobalAnswer(item.foreign) {
			health.ForeignResponsive++
		}
		if !item.cn.OK || !item.foreign.OK {
			health.FailedControls = append(health.FailedControls, item.domain)
		}
	}
	health.OK = health.CNResponsive >= health.Required && health.ForeignResponsive >= health.Required
	if !health.OK {
		health.Reason = "resolver_view_guard_failed"
	}
	return health, nil
}

func hasGlobalAnswer(outcome *resolve.Outcome) bool {
	if outcome == nil || !outcome.OK {
		return false
	}
	return len(globalOnly(outcome.FinalAddresses())) > 0
}

func (e *Engine) ClassifyDomains(ctx context.Context, domains []string) ([]Verdict, BatchHealth, error) {
	cn, foreign, err := e.Resolvers()
	if err != nil {
		return nil, BatchHealth{}, err
	}
	mainland, err := e.Mainland()
	if err != nil {
		return nil, BatchHealth{}, err
	}
	polluted, err := e.Polluted()
	if err != nil {
		return nil, BatchHealth{}, err
	}
	overrides, err := e.Store.ManualOverrides()
	if err != nil {
		return nil, BatchHealth{}, err
	}

	verdicts := parallelMap(domains, e.Config.ClassifyConcurrency, func(name string) Verdict {
		views := e.inspect(ctx, cn, foreign, name)
		return Decide(Input{Domain: name, CN: views.cn, Foreign: views.foreign},
			overrides[name], mainland, polluted)
	})
	return verdicts, summarize(verdicts), nil
}

func summarize(verdicts []Verdict) BatchHealth {
	health := BatchHealth{Total: len(verdicts)}
	for _, v := range verdicts {
		if !v.CNUsable {
			health.CNViewFailed++
		}
		if !v.ForeignUsable {
			health.ForeignViewFailed++
		}
		if v.Status == StatusUnknown {
			health.StatusUnknown++
		}
		if v.Decisive {
			health.Decisive++
		}
	}
	if health.Total > 0 && health.CNViewFailed*5 >= health.Total {
		health.Warning = "国内视角失败率偏高，先降低 CLASSIFY_CONCURRENCY 或加大 QUERY_TIMEOUT_SEC 再看结论"
	}
	return health
}
