package collect

import "strings"

const maxDomainLength = 253

func NormalizeDomain(raw string) string {
	value := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
	if value == "" || len(value) > maxDomainLength {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if !validLabel(label) {
			return ""
		}
	}
	return value
}

func NonASCII(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return true
		}
	}
	return false
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}
