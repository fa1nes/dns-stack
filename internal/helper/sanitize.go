package helper

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ipv4Pattern   = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	ipv6Pattern   = regexp.MustCompile(`\b([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{0,4}\b`)
	secretPattern = regexp.MustCompile(`(?i)\b(authorization|cookie|set-cookie|token|api[_-]?key|apikey|secret|` +
		`password|passwd|private[_-]?key|bearer|credential)\b` +
		`["']?\s*[:=]\s*("[^"]*"|'[^']*'|[^,;\r\n]+)`)
	pemPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
)

var infraPrefixes = []string{"127.", "10.100.0.", "0.0.0.0", "255.255.255."}

const (
	redactedValue   = "[已脱敏]"
	redactedKey     = "[已移除私钥内容]"
	redactedDoHPath = "[已脱敏DoH路径]"
	dohTokenMinLen  = 12
)

type dohTokenCache struct {
	mu     sync.Mutex
	mtime  time.Time
	tokens []string
}

var dohTokens dohTokenCache

func (c *dohTokenCache) get(configPath string) []string {
	info, err := os.Stat(configPath)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if info.ModTime().Equal(c.mtime) {
		return c.tokens
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return c.tokens
	}
	var tokens []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "DOH_PATH=") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		for _, segment := range strings.Split(strings.Trim(value, "/"), "/") {
			if len(segment) >= dohTokenMinLen {
				tokens = append(tokens, segment)
			}
		}
		break
	}
	c.mtime, c.tokens = info.ModTime(), tokens
	return tokens
}

func maskIPv4(match string) string {
	parts := ipv4Pattern.FindStringSubmatch(match)
	if len(parts) != 5 {
		return match
	}
	for _, prefix := range infraPrefixes {
		if strings.HasPrefix(match, prefix) {
			return match
		}
	}
	return parts[1] + "." + parts[2] + ".x.x"
}

func maskIPv6(match string) string {
	return strings.SplitN(match, ":", 2)[0] + ":xxxx::x"
}

func Sanitize(text, configPath string) string {
	if text == "" {
		return text
	}
	text = pemPattern.ReplaceAllString(text, redactedKey)
	text = secretPattern.ReplaceAllString(text, "${1}="+redactedValue)
	for _, token := range dohTokens.get(configPath) {
		text = strings.ReplaceAll(text, token, redactedDoHPath)
	}
	text = ipv4Pattern.ReplaceAllStringFunc(text, maskIPv4)
	text = ipv6Pattern.ReplaceAllStringFunc(text, maskIPv6)
	return text
}
