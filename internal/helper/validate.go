package helper

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

var (
	errBadDomain  = errors.New("非法域名格式")
	errIPAsDomain = errors.New("IP 字面量不能作为 DNS 域名")
)

const (
	maxDomainLen = 253
	maxLabelLen  = 63
)

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelLen {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func SafeDomain(raw string) (string, error) {
	value := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
	if value == "" || len(value) > maxDomainLen || !strings.Contains(value, ".") {
		return "", errBadDomain
	}
	for _, label := range strings.Split(value, ".") {
		if !validLabel(label) {
			return "", errBadDomain
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", errIPAsDomain
	}
	return value, nil
}

func SafeClientSubnet(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	host, mask, found := strings.Cut(value, "/")
	if !found || mask != "24" {
		return "", false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return "", false
	}
	prefix := netip.PrefixFrom(addr, 24)
	if prefix.Masked().Addr() != addr {
		return "", false
	}
	last := addr.As4()
	last[3] = 255
	broadcast := netip.AddrFrom4(last)
	if !ipset.IsGlobalAddr(addr) || !ipset.IsGlobalAddr(broadcast) {
		return "", false
	}
	return prefix.String(), true
}

var (
	retentionPattern  = regexp.MustCompile(`^[0-9]{1,3}[dwm]$`)
	interfacePattern  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	sincePattern      = regexp.MustCompile(`^[0-9]{1,4}\s?(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days)\s?ago$`)
	ruleURLPattern    = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?(/[A-Za-z0-9._~%/+-]*)?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	branchPattern     = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,80}$`)
)

const ruleURLMaxLen = 200

func validateRuleURL(value, label string) string {
	if value == "" {
		return ""
	}
	if len(value) > ruleURLMaxLen || !ruleURLPattern.MatchString(value) {
		return label + " 必须是合法的 https URL(长度≤" + strconv.Itoa(ruleURLMaxLen) + "，不含空白/引号/反斜杠)"
	}
	return ""
}
