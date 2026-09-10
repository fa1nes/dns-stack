package classify

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/rulesync"
)

const (
	ModeStandard  = "standard"
	ModeColdStart = "cold-start"
	ModeFullReset = "full-reset"
	ModeIPReset   = "ip-reset"

	FileCN       = "cn.txt"
	FileGFW      = "gfw.txt"
	FileCNCIDR   = "cn-ip-cidr.txt"
	FilePolluted = "polluted-ip-cidr.txt"

	dropRatioAlert = 0.2
)

var publishFiles = []string{FileCN, FileGFW, FileCNCIDR, FilePolluted}

var validModes = map[string]bool{
	ModeStandard: true, ModeColdStart: true, ModeFullReset: true, ModeIPReset: true,
}

type GuardError struct{ msg string }

func (e *GuardError) Error() string { return e.msg }

func guardf(format string, args ...any) error {
	return &GuardError{msg: fmt.Sprintf(format, args...)}
}

type BundleSummary struct {
	CNCount              int    `json:"cn_count"`
	GFWCount             int    `json:"gfw_count"`
	CNCIDRCount          int    `json:"cn_cidr_count"`
	PollutedCIDRCount    int    `json:"polluted_cidr_count"`
	PollutedAuditOnly    int    `json:"polluted_audit_only_count"`
	PrivateManualCNCount int    `json:"private_manual_cn_count"`
	PrivateManualGFW     int    `json:"private_manual_gfw_count"`
	BundleMode           string `json:"bundle_mode"`
	GeneratedAt          int64  `json:"generated_at"`
	Changed              bool   `json:"changed"`
}

func (e *Engine) publishDir() string { return filepath.Join(e.Config.StateDir, "publish") }

func (e *Engine) BuildRules(force bool) (BundleSummary, error) {
	summary := BundleSummary{BundleMode: ModeStandard}
	cnRules, err := e.Store.PublicStaticRules(RuleCN)
	if err != nil {
		return summary, err
	}
	gfwRules, err := e.Store.PublicStaticRules(RuleForeign)
	if err != nil {
		return summary, err
	}
	manualCN, err := e.Store.ManualByStatus(OverrideCN)
	if err != nil {
		return summary, err
	}
	manualGFW, err := e.Store.ManualByStatus(OverrideGFW)
	if err != nil {
		return summary, err
	}

	cnClean := cleanDomains(cnRules)
	gfwClean := cleanDomains(gfwRules)
	if err := rulesync.CheckRuleSets(cnClean, gfwClean); err != nil {
		return summary, guardf("%v，禁止发布", err)
	}

	cnCIDRRaw, err := e.Store.ActiveCIDRs("cn")
	if err != nil {
		return summary, err
	}
	pollutedRaw, err := e.Store.ActiveCIDRs("polluted")
	if err != nil {
		return summary, err
	}
	cnCIDRs, err := collapsePrefixStrings(cnCIDRRaw)
	if err != nil {
		return summary, &GuardError{msg: err.Error()}
	}
	pollutedCollapsed, err := collapsePrefixStrings(pollutedRaw)
	if err != nil {
		return summary, &GuardError{msg: err.Error()}
	}
	if err := assertDisjoint(cnCIDRs, pollutedCollapsed); err != nil {
		return summary, &GuardError{msg: err.Error()}
	}
	publishable, auditOnly := partitionPollutedCIDRs(pollutedRaw)
	pollutedCIDRs, err := collapsePrefixStrings(publishable)
	if err != nil {
		return summary, &GuardError{msg: err.Error()}
	}
	if err := assertPollutedPublishable(pollutedCIDRs); err != nil {
		return summary, &GuardError{msg: err.Error()}
	}

	bodies := map[string][]string{
		FileCN: cnClean, FileGFW: gfwClean,
		FileCNCIDR: cnCIDRs, FilePolluted: pollutedCIDRs,
	}
	if err := e.guardMassDeletion(bodies, force); err != nil {
		return summary, err
	}
	if !force {
		if err := e.guardPublicationFreshness(); err != nil {
			return summary, err
		}
	}

	summary = BundleSummary{
		CNCount: len(cnClean), GFWCount: len(gfwClean),
		CNCIDRCount: len(cnCIDRs), PollutedCIDRCount: len(pollutedCIDRs),
		PollutedAuditOnly:    len(auditOnly),
		PrivateManualCNCount: len(manualCN), PrivateManualGFW: len(manualGFW),
		BundleMode: ModeStandard,
	}

	generations, modes := e.bundleState()
	if uniform(generations) > 0 && sameMode(modes, ModeStandard) && e.bodiesUnchanged(bodies) {
		summary.GeneratedAt = uniform(generations)
		return summary, nil
	}
	summary.GeneratedAt = nextGeneration(generations, e.unixNow())
	summary.Changed = true
	return summary, e.writeBundle(renderBundle(summary.GeneratedAt, ModeStandard, bodies))
}

func (e *Engine) unixNow() int64 { return e.now().Unix() }

func (e *Engine) BuildColdStart(resetCNCIDRs bool) (BundleSummary, error) {
	mode := ModeColdStart
	if resetCNCIDRs {
		mode = ModeFullReset
	}
	summary := BundleSummary{BundleMode: mode}
	formal, err := e.Store.CountFormalAutoRules()
	if err != nil {
		return summary, err
	}
	if formal > 0 {
		return summary, guardf("仍有 %d 条自动正式规则；先执行冷启动分类重置", formal)
	}
	empty := map[string][]string{FileCN: nil, FileGFW: nil, FileCNCIDR: nil, FilePolluted: nil}
	generations, modes := e.bundleState()
	if uniform(generations) > 0 && sameMode(modes, mode) && e.bodiesUnchanged(empty) {
		summary.GeneratedAt = uniform(generations)
		return summary, nil
	}
	summary.GeneratedAt = nextGeneration(generations, e.unixNow())
	summary.Changed = true
	return summary, e.writeBundle(renderBundle(summary.GeneratedAt, mode, empty))
}

func (e *Engine) BuildIPReset() (BundleSummary, error) {
	bodies := map[string][]string{
		FileCN:     e.publishedBody(FileCN),
		FileGFW:    e.publishedBody(FileGFW),
		FileCNCIDR: nil, FilePolluted: nil,
	}
	generations, _ := e.bundleState()
	generated := nextGeneration(generations, e.unixNow())
	summary := BundleSummary{
		CNCount: len(bodies[FileCN]), GFWCount: len(bodies[FileGFW]),
		BundleMode: ModeIPReset, GeneratedAt: generated, Changed: true,
	}
	return summary, e.writeBundle(renderBundle(generated, ModeIPReset, bodies))
}

func cleanDomains(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, raw := range values {
		name := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
		if name == "" || strings.HasPrefix(name, "#") || !rulesync.ValidDomain(name) {
			continue
		}
		unique[name] = struct{}{}
	}
	out := make([]string, 0, len(unique))
	for name := range unique {
		if !coveredByPublishedParent(name, unique) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func coveredByPublishedParent(name string, names map[string]struct{}) bool {
	rest := name
	for {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		rest = rest[dot+1:]
		if _, ok := names[rest]; ok && !IsSharedTenancyRoot(rest) {
			return true
		}
	}
}

func (e *Engine) guardMassDeletion(bodies map[string][]string, force bool) error {
	if force {
		return nil
	}
	for _, name := range publishFiles {
		old := len(e.publishedBody(name))
		fresh := len(bodies[name])
		if old == 0 {
			continue
		}
		if fresh == 0 {
			return guardf("%s 将从 %d 条清空为 0，禁止发布。确认这是预期的清理后用 build-rules --force", name, old)
		}
		if float64(fresh) < float64(old)*(1-dropRatioAlert) {
			return guardf("%s 条目数从 %d 骤降到 %d，超过 %d%% 阈值，禁止发布。先核对数量与正文，确认无误后用 build-rules --force",
				name, old, fresh, int(dropRatioAlert*100))
		}
	}
	return nil
}

func (e *Engine) guardPublicationFreshness() error {
	readiness, err := e.Store.PublicationReadiness(max(e.Config.PublishMaxStale, 3600))
	if err != nil {
		return err
	}
	if readiness.AutomaticTotal == 0 {
		return nil
	}
	if readiness.BeforeEpoch > 0 {
		return guardf("有 %d 条自动正式规则尚未完成当前基线复检，禁止发布（共 %d 条）。它们的判据产生于上一套分类标准，先重跑分类，或用 --force 人工放行",
			readiness.BeforeEpoch, readiness.AutomaticTotal)
	}
	if readiness.Stale > 0 {
		return guardf("有 %d 条自动正式规则的复检已过期（阈值 %d 秒，共 %d 条），禁止发布。先跑一轮复检，或用 --force 人工放行",
			readiness.Stale, readiness.MaxStaleSec, readiness.AutomaticTotal)
	}
	return nil
}

func (e *Engine) bundleState() (map[string]int64, map[string]string) {
	generations := make(map[string]int64, len(publishFiles))
	modes := make(map[string]string, len(publishFiles))
	for _, name := range publishFiles {
		generation, mode := e.publishedHeader(name)
		generations[name] = generation
		modes[name] = mode
	}
	return generations, modes
}

func uniform(generations map[string]int64) int64 {
	var value int64
	first := true
	for _, generation := range generations {
		if first {
			value, first = generation, false
			continue
		}
		if generation != value {
			return 0
		}
	}
	return value
}

func sameMode(modes map[string]string, want string) bool {
	for _, mode := range modes {
		if mode != want {
			return false
		}
	}
	return true
}

func nextGeneration(generations map[string]int64, now int64) int64 {
	var highest int64
	for _, generation := range generations {
		if generation > highest {
			highest = generation
		}
	}
	return max(now, highest+1)
}

func (e *Engine) bodiesUnchanged(bodies map[string][]string) bool {
	for _, name := range publishFiles {
		current := e.publishedBody(name)
		want := bodies[name]
		if len(current) != len(want) {
			return false
		}
		for i := range want {
			if current[i] != want[i] {
				return false
			}
		}
	}
	return true
}

func (e *Engine) publishedBody(name string) []string {
	return readBody(filepath.Join(e.publishDir(), name))
}

func readBody(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (e *Engine) publishedHeader(name string) (int64, string) {
	return readHeader(filepath.Join(e.publishDir(), name))
}

func readHeader(path string) (generation int64, mode string) {
	mode = ModeStandard
	file, err := os.Open(path)
	if err != nil {
		return 0, mode
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "#") {
			break
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if rest, ok := strings.CutPrefix(value, "generated-at:"); ok {
			generation, _ = strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		}
		if rest, ok := strings.CutPrefix(value, "bundle-mode:"); ok {
			if candidate := strings.TrimSpace(rest); validModes[candidate] {
				mode = candidate
			}
		}
	}
	return generation, mode
}

func renderBundle(generation int64, mode string, bodies map[string][]string) map[string]string {
	header := fmt.Sprintf("# generated-at: %d\n# bundle-mode: %s\n# 由 dns-stack 分类器自动生成，请勿手工编辑\n",
		generation, mode)
	out := make(map[string]string, len(publishFiles))
	for _, name := range publishFiles {
		body := bodies[name]
		if len(body) == 0 {
			out[name] = header
			continue
		}
		out[name] = header + strings.Join(body, "\n") + "\n"
	}
	return out
}

func (e *Engine) writeBundle(contents map[string]string) error {
	dir := e.publishDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	backups := make(map[string][]byte, len(publishFiles))
	var replaced []string
	restore := func() {
		for i := len(replaced) - 1; i >= 0; i-- {
			name := replaced[i]
			if previous, existed := backups[name]; existed {
				os.WriteFile(filepath.Join(dir, name), previous, 0o644)
				continue
			}
			os.Remove(filepath.Join(dir, name))
		}
	}
	for _, name := range publishFiles {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			backups[name] = data
		}
	}
	for _, name := range publishFiles {
		target := filepath.Join(dir, name)
		temp := target + ".tmp"
		if err := os.WriteFile(temp, []byte(contents[name]), 0o644); err != nil {
			restore()
			return err
		}
		if err := os.Rename(temp, target); err != nil {
			os.Remove(temp)
			restore()
			return err
		}
		replaced = append(replaced, name)
	}
	return nil
}

func (e *Engine) restampBundle(generation int64) error {
	_, modes := e.bundleState()
	mode := modes[FileCN]
	if !sameMode(modes, mode) {
		return guardf("本地四规则文件模式不一致，禁止重写版本")
	}
	bodies := make(map[string][]string, len(publishFiles))
	for _, name := range publishFiles {
		bodies[name] = e.publishedBody(name)
	}
	return e.writeBundle(renderBundle(generation, mode, bodies))
}
