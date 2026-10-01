package collect

import "github.com/dns-stack/dns-stack/internal/domain"

func NormalizeDomain(raw string) string {
	value := domain.Normalize(raw)
	if !domain.IsWellFormed(value) {
		return ""
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
