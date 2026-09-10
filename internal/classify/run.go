package classify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	ModeIncremental = "incremental"
	ModeVerify      = "verify"
	ModeManual      = "manual"

	recheckMinAge = 5 * time.Minute
)

type ResultRow struct {
	Domain  string `json:"domain"`
	Status  string `json:"status"`
	Route   string `json:"route"`
	Reason  string `json:"reason"`
	Landing string `json:"landing"`
}

type BatchReport struct {
	OK      bool        `json:"ok"`
	Mode    string      `json:"mode"`
	Count   int         `json:"count"`
	Changed int         `json:"changed"`
	Guard   ViewHealth  `json:"guard"`
	Health  BatchHealth `json:"view_health"`
	Results []ResultRow `json:"results,omitempty"`
	Message string      `json:"message,omitempty"`
}

func (e *Engine) RunBatch(ctx context.Context, domains []string, mode string) (BatchReport, error) {
	report := BatchReport{Mode: mode, Count: len(domains)}
	guard, err := e.ValidateViews(ctx)
	if err != nil {
		return report, err
	}
	report.Guard = guard
	guardJSON, _ := json.Marshal(guard)
	runID, err := e.Store.StartRun(mode, len(domains), string(guardJSON), guard.OK)
	if err != nil {
		return report, err
	}
	if !guard.OK {
		report.Message = "双视角健康门禁失败，未写入分类"
		return report, e.Store.FinishRun(runID, 0, 0, guard.Reason)
	}

	verdicts, health, err := e.ClassifyDomains(ctx, domains)
	if err != nil {
		e.Store.FinishRun(runID, 0, 0, err.Error())
		return report, err
	}
	changed, err := e.Store.ApplyVerdicts(verdicts)
	if err != nil {
		e.Store.FinishRun(runID, len(verdicts), 0, err.Error())
		return report, err
	}
	report.OK = true
	report.Changed = changed
	report.Health = health
	report.Results = make([]ResultRow, len(verdicts))
	for i, v := range verdicts {
		report.Results[i] = ResultRow{
			Domain: v.Domain, Status: v.Status, Route: v.Route,
			Reason: v.Reason, Landing: v.Landing,
		}
	}
	return report, e.Store.FinishRun(runID, len(verdicts), changed, "")
}

func (e *Engine) Classify(ctx context.Context, single string, limit int) (BatchReport, error) {
	if _, err := e.SyncManualRules(); err != nil {
		return BatchReport{}, err
	}
	if single != "" {
		return e.RunBatch(ctx, []string{single}, ModeManual)
	}
	candidates, err := e.Store.UnconsumedCandidates(limit)
	if err != nil {
		return BatchReport{}, err
	}
	recheck, err := e.Store.DomainsNeedingRecheck(limit, recheckMinAge)
	if err != nil {
		return BatchReport{}, err
	}
	domains := mergeUnique(candidates, recheck)
	if len(domains) == 0 {
		return BatchReport{OK: true, Mode: ModeIncremental, Message: "没有待分类的域名"}, nil
	}
	report, err := e.RunBatch(ctx, domains, ModeIncremental)
	if err != nil || !report.OK {
		return report, err
	}
	return report, e.Store.MarkCandidatesConsumed(candidates)
}

func (e *Engine) VerifyRules(ctx context.Context, limit int, maxAge time.Duration) (BatchReport, error) {
	if _, err := e.SyncManualRules(); err != nil {
		return BatchReport{}, err
	}
	if maxAge <= 0 {
		maxAge = e.Config.RecheckMaxAge
	}
	domains, err := e.Store.FormalDueForVerification(limit, maxAge)
	if err != nil {
		return BatchReport{}, err
	}
	if len(domains) == 0 {
		return BatchReport{OK: true, Mode: ModeVerify, Message: "没有到期的正式规则"}, nil
	}
	return e.RunBatch(ctx, domains, ModeVerify)
}

func mergeUnique(groups ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, group := range groups {
		for _, name := range group {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

type PipelineReport struct {
	OK        bool             `json:"ok"`
	Pull      *PullResult      `json:"pull,omitempty"`
	Classify  *BatchReport     `json:"classify,omitempty"`
	Authority *AuthorityReport `json:"authority,omitempty"`
	Build     *BundleSummary   `json:"build,omitempty"`
	Publish   *PublishResult   `json:"publish,omitempty"`
	Stage     string           `json:"failed_stage,omitempty"`
	Message   string           `json:"message,omitempty"`
	Elapsed   string           `json:"elapsed"`
}

type PipelineOptions struct {
	Limit             int
	SkipPull          bool
	SkipAuthority     bool
	AuthorityInterval time.Duration
	Force             bool
	Publish           bool
	StopOnBuildFail   bool
}

const lastAuthorityKey = "last_authority_scan_at"

func (e *Engine) authorityDue(interval time.Duration) bool {
	if interval <= 0 {
		return true
	}
	last := e.Store.metaInt(lastAuthorityKey)
	return e.unixNow()-last >= int64(interval.Seconds())
}

func (e *Engine) RunPipeline(ctx context.Context, opts PipelineOptions) (PipelineReport, error) {
	started := e.now()
	report := PipelineReport{}
	finish := func(stage string, err error) (PipelineReport, error) {
		report.Stage = stage
		report.Message = err.Error()
		report.Elapsed = e.now().Sub(started).Round(time.Millisecond).String()
		return report, fmt.Errorf("%s 阶段失败: %w", stage, err)
	}

	if !opts.SkipPull {
		pulled, err := e.Pull()
		if err != nil {
			return finish("pull", err)
		}
		report.Pull = &pulled
	}

	classified, err := e.Classify(ctx, "", opts.Limit)
	if err != nil {
		return finish("classify", err)
	}
	report.Classify = &classified

	if !opts.SkipAuthority && e.authorityDue(opts.AuthorityInterval) {
		authorityReport, err := e.ClassifyAuthority(ctx, 0)
		if err != nil {
			return finish("classify-authority", err)
		}
		report.Authority = &authorityReport
		if err := e.Store.setMeta(lastAuthorityKey, fmt.Sprint(e.unixNow())); err != nil {
			return finish("classify-authority", err)
		}
	}

	built, err := e.BuildRules(opts.Force)
	if err != nil {
		if _, isGuard := err.(*GuardError); isGuard && !opts.StopOnBuildFail {
			report.OK = true
			report.Stage = "build-rules"
			report.Message = err.Error()
			report.Elapsed = e.now().Sub(started).Round(time.Millisecond).String()
			return report, nil
		}
		return finish("build-rules", err)
	}
	report.Build = &built

	if opts.Publish {
		if err := e.EnsureRepo(); err != nil {
			return finish("publish", err)
		}
		published, err := e.Publish(PublishOptions{})
		if err != nil {
			return finish("publish", err)
		}
		report.Publish = &published
	}

	report.OK = true
	report.Elapsed = e.now().Sub(started).Round(time.Millisecond).String()
	return report, nil
}
