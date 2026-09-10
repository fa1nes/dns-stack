package domain

import (
	"net/netip"
	"strings"
)

const (
	DefectEmpty        = "empty"
	DefectMalformed    = "malformed"
	DefectReserved     = "reserved"
	DefectPublicSuffix = "public_suffix"
	DefectSingleLabel  = "single_label"
)

var DefectLabels = map[string]string{
	DefectEmpty:        "空值",
	DefectMalformed:    "不是合法 DNS 名",
	DefectReserved:     "RFC 保留域或本地域",
	DefectPublicSuffix: "公共后缀本身（不是可注册域）",
	DefectSingleLabel:  "无点单段名（顶级域或本地名）",
}

var reservedSuffixes = []string{
	"in-addr.arpa", "ip6.arpa", "arpa",
	"local", "localhost", "localdomain", "invalid", "test", "example",
	"home.arpa", "onion", "lan", "internal", "corp", "home", "intranet",
}

var fallbackPublicSuffixes = map[string]struct{}{
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {},
	"ac.cn": {}, "mil.cn": {},
	"com.hk": {}, "net.hk": {}, "org.hk": {}, "edu.hk": {}, "gov.hk": {},
	"com.tw": {}, "net.tw": {}, "org.tw": {}, "edu.tw": {}, "gov.tw": {},
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "gov.uk": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {}, "ac.jp": {}, "go.jp": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"com.br": {}, "com.sg": {}, "com.my": {}, "co.kr": {}, "or.kr": {},
}

func Normalize(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

func isLabelValid(label string) bool {
	if label == "" {
		return false
	}
	body := label
	if body[0] == '_' {
		body = body[1:]
	}
	if body == "" {
		return false
	}
	if !isAlnum(body[0]) || !isAlnum(body[len(body)-1]) {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !isAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func IsWellFormed(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if !isLabelValid(label) {
			return false
		}
	}
	return true
}

func IsReserved(name string) bool {
	for _, s := range reservedSuffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

func ZoneDefect(name string, psl *PSL) string {
	name = Normalize(name)
	if name == "" {
		return DefectEmpty
	}
	if !IsWellFormed(name) {
		return DefectMalformed
	}
	if IsReserved(name) {
		return DefectReserved
	}
	if !strings.Contains(name, ".") {
		return DefectSingleLabel
	}
	if psl != nil {
		if psl.IsPublicSuffix(name) {
			return DefectPublicSuffix
		}
	} else if _, ok := fallbackPublicSuffixes[name]; ok {
		return DefectPublicSuffix
	}
	return ""
}
