package classify

import (
	"net/netip"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

const (
	StatusCN      = "cn"
	StatusGFW     = "gfw"
	StatusUnknown = "unknown"

	RouteCN      = "cn"
	RouteForeign = "foreign"
	RouteUnknown = "unknown"

	LandingMainland = "mainland"
	LandingMixed    = "mixed"
	LandingOffshore = "offshore"
	LandingNoAnswer = "no_answer"
	LandingUnjudged = "unjudged"

	OverrideCN      = "cn"
	OverrideGFW     = "gfw"
	OverrideExclude = "exclude"

	RuleCN      = "cn"
	RuleForeign = "foreign-dns"
	RuleNone    = "none"

	ReasonBothViewsFailed        = "both_views_failed"
	ReasonCNViewPolluted         = "cn_view_polluted"
	ReasonBothViewsPolluted      = "both_views_polluted"
	ReasonCNPollutionUnconfirmed = "cn_pollution_unconfirmed_hk"
	ReasonForeignViewPolluted    = "hk_view_polluted"
	ReasonAbnormalCNAnswer       = "abnormal_cn_answer"
	ReasonAbnormalForeignAnswer  = "abnormal_global_answer"
	ReasonIdenticalAnswer        = "identical_answer"
	ReasonSharedGeoDNSChain      = "shared_geodns_chain"
	ReasonViewsConflict          = "views_conflict_foreign_preferred"
	ReasonSplitHorizon           = "split_horizon_cn_landing"
	ReasonViewsAgreeNXDomain     = "views_agree_nxdomain"
	ReasonIndeterminate          = "indeterminate_dns_result"
	ReasonBothViewsTransient     = "both_views_transient"
	ReasonNoFinalIP              = "no_final_ip"
	ReasonManualRemoved          = "manual_removed"
	ReasonBaselineInvalidated    = "routing_baseline_invalidated"
	ReasonUnavailable            = "unavailable"
)

var recheckReasons = []string{
	ReasonIdenticalAnswer, ReasonSharedGeoDNSChain, ReasonViewsConflict,
	ReasonAbnormalForeignAnswer, ReasonAbnormalCNAnswer, ReasonIndeterminate,
	ReasonBothViewsTransient, ReasonNoFinalIP, ReasonBothViewsFailed,
	ReasonManualRemoved, ReasonBaselineInvalidated, ReasonCNPollutionUnconfirmed,
}

var (
	transientReasons     = map[string]bool{resolve.ReasonTimeout: true, resolve.ReasonServFail: true}
	indeterminateReasons = map[string]bool{
		resolve.ReasonCNAMELoop: true, resolve.ReasonMaxDepth: true, resolve.ReasonNoData: true,
	}
)

type Mainland interface {
	IsMainland(addr netip.Addr) bool
}

type Input struct {
	Domain  string
	CN      *resolve.Outcome
	Foreign *resolve.Outcome
}

type Verdict struct {
	Domain          string
	Status          string
	Route           string
	Reason          string
	Landing         string
	CNIPs           []netip.Addr
	ForeignIPs      []netip.Addr
	FinalIPs        []netip.Addr
	AnomalousIPs    []netip.Addr
	CNChain         []string
	ForeignChain    []string
	CNUsable        bool
	ForeignUsable   bool
	CNViewPolluted  bool
	ForeignPolluted bool
	Decisive        bool
}

type view struct {
	ips      []netip.Addr
	abnormal []netip.Addr
	polluted []netip.Addr
	chain    []string
	reason   string
	usable   bool
}

func inspect(o *resolve.Outcome, polluted *cidrutil.Set) view {
	if o == nil {
		return view{reason: ReasonUnavailable}
	}
	v := view{chain: o.CNAMEChain, reason: o.Reason}
	if !o.OK {
		return v
	}
	v.ips = o.FinalAddresses()
	for _, addr := range v.ips {
		if !ipset.IsGlobalAddr(addr) {
			v.abnormal = append(v.abnormal, addr)
			continue
		}
		if polluted.Contains(addr) {
			v.polluted = append(v.polluted, addr)
		}
	}
	v.usable = len(v.ips) > 0 && len(v.abnormal)*2 <= len(v.ips)
	return v
}

func Decide(in Input, override string, mainland Mainland, polluted *cidrutil.Set) Verdict {
	cn := inspect(in.CN, polluted)
	foreign := inspect(in.Foreign, polluted)

	pollutionConfirmed := len(cn.polluted) > 0 && cn.usable && foreign.usable && len(foreign.polluted) == 0

	route, reason := RouteUnknown, ReasonBothViewsFailed
	var anomalous []netip.Addr

	switch {
	case pollutionConfirmed:
		route, reason, anomalous = RouteForeign, ReasonCNViewPolluted, cn.polluted
	case len(cn.polluted) > 0 && len(foreign.polluted) > 0:
		reason, anomalous = ReasonBothViewsPolluted, mergeAddrs(cn.polluted, foreign.polluted)
	case len(cn.polluted) > 0:
		reason, anomalous = ReasonCNPollutionUnconfirmed, cn.polluted
	case len(foreign.polluted) > 0:
		reason, anomalous = ReasonForeignViewPolluted, foreign.polluted
	case !cn.usable && len(cn.abnormal) > 0:
		route, reason, anomalous = routeIf(foreign.usable, RouteForeign), ReasonAbnormalCNAnswer, cn.abnormal
	case !foreign.usable && len(foreign.abnormal) > 0:
		route, reason, anomalous = routeIf(cn.usable, RouteCN), ReasonAbnormalForeignAnswer, foreign.abnormal
	case cn.usable && foreign.usable:
		switch {
		case sameAddrs(cn.ips, foreign.ips):
			route, reason = RouteCN, ReasonIdenticalAnswer
		case sharesGeoSteeredChain(cn.chain, foreign.chain):
			route, reason = RouteCN, ReasonSharedGeoDNSChain
		case splitHorizonCN(cn.ips, foreign.ips, mainland):
			route, reason = RouteCN, ReasonSplitHorizon
		default:
			route, reason = RouteForeign, ReasonViewsConflict
		}
	case cn.usable:
		route, reason = RouteCN, "foreign_"+foreign.reason+"_fallback_cn"
	case foreign.usable:
		route, reason = RouteForeign, "cn_"+cn.reason+"_foreign_fallback"
	case in.CN != nil && in.Foreign != nil:
		switch {
		case cn.reason == resolve.ReasonNXDomain && foreign.reason == resolve.ReasonNXDomain:
			route, reason = RouteCN, ReasonViewsAgreeNXDomain
		case indeterminateReasons[cn.reason] || indeterminateReasons[foreign.reason]:
			reason = ReasonIndeterminate
		case transientReasons[cn.reason] || transientReasons[foreign.reason]:
			reason = ReasonBothViewsTransient
		default:
			reason = ReasonNoFinalIP
		}
	}

	landing := landingVerdict(cn.ips, foreign.ips, mainland)
	return Verdict{
		Domain:          in.Domain,
		Status:          staticStatus(override, landing, pollutionConfirmed, route, reason),
		Route:           route,
		Reason:          reason,
		Landing:         landing,
		CNIPs:           cn.ips,
		ForeignIPs:      foreign.ips,
		FinalIPs:        mergeAddrs(cn.ips, foreign.ips),
		AnomalousIPs:    anomalous,
		CNChain:         cn.chain,
		ForeignChain:    foreign.chain,
		CNUsable:        cn.usable,
		ForeignUsable:   foreign.usable,
		CNViewPolluted:  pollutionConfirmed,
		ForeignPolluted: len(foreign.polluted) > 0,
		Decisive:        (cn.usable && foreign.usable) || reason == ReasonViewsAgreeNXDomain,
	}
}

func routeIf(cond bool, route string) string {
	if cond {
		return route
	}
	return RouteUnknown
}

func staticStatus(override, landing string, polluted bool, route, reason string) string {
	switch override {
	case OverrideCN, OverrideGFW:
		return override
	}
	if polluted {
		return StatusGFW
	}
	if route == RouteCN &&
		(reason == ReasonIdenticalAnswer || reason == ReasonSharedGeoDNSChain ||
			reason == ReasonSplitHorizon) &&
		(landing == LandingMainland || landing == LandingMixed) {
		return StatusCN
	}
	return StatusUnknown
}

func landingVerdict(cnIPs, foreignIPs []netip.Addr, mainland Mainland) string {
	judged := judgeableOnly(cnIPs)
	global := globalOnly(cnIPs)
	if len(global) == 0 {
		judged, global = judgeableOnly(foreignIPs), globalOnly(foreignIPs)
	}
	if len(global) == 0 {
		return LandingNoAnswer
	}
	if len(judged) == 0 {
		return LandingUnjudged
	}
	hits := 0
	for _, addr := range judged {
		if mainland.IsMainland(addr) {
			hits++
		}
	}
	switch {
	case hits == len(judged):
		return LandingMainland
	case hits > 0:
		return LandingMixed
	default:
		return LandingOffshore
	}
}

func globalOnly(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0:0]
	for _, addr := range addrs {
		if ipset.IsGlobalAddr(addr) {
			out = append(out, addr)
		}
	}
	return out
}

func judgeable(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.Is4() && ipset.IsGlobalAddr(addr)
}

func judgeableOnly(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0:0]
	for _, addr := range addrs {
		if judgeable(addr) {
			out = append(out, addr)
		}
	}
	return out
}

func sharesGeoSteeredChain(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(right))
	for _, name := range right {
		seen[name] = struct{}{}
	}
	for _, name := range left {
		if _, ok := seen[name]; ok && isGeoSteered(name) {
			return true
		}
	}
	return false
}

func splitHorizonCN(cnIPs, foreignIPs []netip.Addr, mainland Mainland) bool {
	cnJudged := judgeableOnly(cnIPs)
	if len(cnJudged) == 0 {
		return false
	}
	for _, addr := range cnJudged {
		if !mainland.IsMainland(addr) {
			return false
		}
	}
	foreignJudged := judgeableOnly(foreignIPs)
	if len(foreignJudged) == 0 {
		return false
	}
	for _, addr := range foreignJudged {
		if mainland.IsMainland(addr) {
			return false
		}
	}
	return true
}

func sameAddrs(left, right []netip.Addr) bool {
	a, b := addrSet(left), addrSet(right)
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

func addrSet(addrs []netip.Addr) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		out[addr] = struct{}{}
	}
	return out
}

func mergeAddrs(left, right []netip.Addr) []netip.Addr {
	if len(right) == 0 {
		return left
	}
	if len(left) == 0 {
		return right
	}
	out := make([]netip.Addr, 0, len(left)+len(right))
	out = append(out, left...)
	out = append(out, right...)
	cidrutil.SortAddrs(out)
	return dedupeAddrs(out)
}

func dedupeAddrs(sorted []netip.Addr) []netip.Addr {
	out := sorted[:0]
	for i, addr := range sorted {
		if i == 0 || addr != sorted[i-1] {
			out = append(out, addr)
		}
	}
	return out
}
