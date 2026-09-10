package classify

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/dns-stack/dns-stack/internal/authority"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

var errAllVerdictsFailed = errors.New("全部判定失败，疑似解析链路故障，未改动规则")

type CollapseStat struct {
	Eligible int `json:"eligible"`
	Kept     int `json:"kept"`
}

type BlockedSet struct {
	Count   int      `json:"count"`
	Domains []string `json:"domains"`
}

func blocked(domains []string) BlockedSet {
	sort.Strings(domains)
	sample := domains
	if len(sample) > 20 {
		sample = sample[:20]
	}
	return BlockedSet{Count: len(domains), Domains: sample}
}

type AuthorityReport struct {
	Scanned               int                     `json:"scanned"`
	Written               map[string]int          `json:"written"`
	Unknown               int                     `json:"unknown"`
	UnknownReasons        map[string]int          `json:"unknown_reasons"`
	Collapsed             map[string]CollapseStat `json:"collapsed"`
	SkippedEmptyClasses   []string                `json:"skipped_empty_classes"`
	SharedProviderBlocked BlockedSet              `json:"shared_provider_root_blocked"`
	CNShadowedByForeign   BlockedSet              `json:"cn_shadowed_by_foreign"`
	CNLandingOffshore     BlockedSet              `json:"cn_landing_offshore"`
	CNLandingUnverified   int                     `json:"cn_landing_unverified"`
}

func ruleKey(name string, psl *domain.PSL) string {
	name = domain.Normalize(name)
	if domain.ZoneDefect(name, psl) != "" {
		return ""
	}
	key := psl.RegistrableDomain(name)
	if key == "" || domain.ZoneDefect(key, psl) != "" {
		return ""
	}
	return key
}

func (e *Engine) scanZones(limit int, psl *domain.PSL) ([]string, error) {
	raw, err := e.Store.AuthorityScanPool(limit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(raw))
	zones := make([]string, 0, len(raw))
	for _, name := range raw {
		key := ruleKey(name, psl)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		zones = append(zones, key)
	}
	sort.Strings(zones)
	return zones, nil
}

func (e *Engine) ClassifyAuthority(ctx context.Context, limit int) (AuthorityReport, error) {
	var report AuthorityReport
	psl, err := e.PSL()
	if err != nil {
		return report, err
	}
	mainland, err := e.Mainland()
	if err != nil {
		return report, err
	}
	cnClient, foreignClient, err := e.Resolvers()
	if err != nil {
		return report, err
	}

	zones, err := e.scanZones(limit, psl)
	if err != nil {
		return report, err
	}
	report.Scanned = len(zones)
	if len(zones) == 0 {
		return report, nil
	}

	verdicts := authority.ClassifyMany(ctx, foreignClient, mainland, zones, psl, e.Config.AuthorityConcurrency)

	var cnList, sharedBlocked []string
	report.UnknownReasons = map[string]int{}
	for _, v := range verdicts {
		switch v.Verdict {
		case authority.VerdictCN:
			if IsSharedTenancyRoot(v.Domain) {
				sharedBlocked = append(sharedBlocked, v.Domain)
				continue
			}
			cnList = append(cnList, v.Domain)
		default:
			report.Unknown++
			reason, _, _ := strings.Cut(v.Reason, "(")
			report.UnknownReasons[reason]++
		}
	}
	report.SharedProviderBlocked = blocked(sharedBlocked)

	gfwList, err := e.Store.VerifiedGFWDomains(zones)
	if err != nil {
		return report, err
	}
	existingForeign, err := e.Store.PublicStaticRules(RuleForeign)
	if err != nil {
		return report, err
	}
	cnList, shadowed := dropShadowedByForeign(cnList, append(append([]string{}, gfwList...), existingForeign...))
	report.CNShadowedByForeign = blocked(shadowed)

	cnList, offshore, unverified := e.confirmCNLanding(ctx, cnClient, mainland, cnList)
	report.CNLandingOffshore = blocked(offshore)
	report.CNLandingUnverified = unverified

	eligible := map[string]int{RuleCN: len(cnList), RuleForeign: len(gfwList)}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cnList = authority.CollapseByResolution(ctx, foreignClient, cnList, e.Config.AuthorityConcurrency)
	}()
	go func() {
		defer wg.Done()
		gfwList = authority.CollapseByResolution(ctx, foreignClient, gfwList, e.Config.AuthorityConcurrency)
	}()
	wg.Wait()

	report.Collapsed = map[string]CollapseStat{
		RuleCN:      {Eligible: eligible[RuleCN], Kept: len(cnList)},
		RuleForeign: {Eligible: eligible[RuleForeign], Kept: len(gfwList)},
	}
	rules := map[string][]string{RuleCN: cnList, RuleForeign: gfwList}
	for _, name := range []string{RuleCN, RuleForeign} {
		if len(rules[name]) == 0 {
			report.SkippedEmptyClasses = append(report.SkippedEmptyClasses, name)
		}
	}
	if len(cnList) == 0 && len(gfwList) == 0 {
		return report, errAllVerdictsFailed
	}

	written, err := e.Store.ReplaceTrafficRules(rules)
	if err != nil {
		return report, err
	}
	report.Written = written
	return report, nil
}

func dropShadowedByForeign(cnList, foreignMarked []string) (kept, dropped []string) {
	if len(foreignMarked) == 0 {
		return cnList, nil
	}
	marked := make(map[string]struct{}, len(foreignMarked))
	for _, name := range foreignMarked {
		marked[name] = struct{}{}
	}
	for _, name := range cnList {
		if coveredBySuffix(name, marked) {
			dropped = append(dropped, name)
			continue
		}
		kept = append(kept, name)
	}
	return kept, dropped
}

func coveredBySuffix(name string, marked map[string]struct{}) bool {
	for rest := name; rest != ""; {
		if _, ok := marked[rest]; ok {
			return true
		}
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		rest = rest[dot+1:]
	}
	return false
}

type landingOutcome struct {
	name     string
	mainland bool
	known    bool
}

func (e *Engine) confirmCNLanding(
	ctx context.Context, cnClient *resolve.Client, mainland Mainland, names []string,
) (kept, offshore []string, unverified int) {
	if len(names) == 0 {
		return names, nil, 0
	}
	results := parallelMap(names, e.Config.AuthorityConcurrency, func(name string) landingOutcome {
		isMainland, known := authority.LandingIsMainland(ctx, cnClient, mainland, name)
		return landingOutcome{name: name, mainland: isMainland, known: known}
	})
	for _, item := range results {
		if item.known && !item.mainland {
			offshore = append(offshore, item.name)
			continue
		}
		if !item.known {
			unverified++
		}
		kept = append(kept, item.name)
	}
	sort.Strings(kept)
	return kept, offshore, unverified
}
