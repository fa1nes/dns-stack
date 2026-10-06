package stack

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var stampPattern = regexp.MustCompile(`^(?:[A-Za-z]{3,9}\s+)?(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:\s+\S+)?$`)

func parseStamp(value string) (int64, bool) {
	match := stampPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return 0, false
	}
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", match[1]+" "+match[2], time.Local)
	if err != nil {
		return 0, false
	}
	return parsed.Unix(), true
}

func blank(value string) bool {
	switch strings.TrimSpace(value) {
	case "", "n/a", "infinity", "0":
		return true
	}
	return false
}

func ServiceStamp(value string) int64 {
	value = strings.TrimSpace(value)
	if blank(value) {
		return 0
	}
	if seconds, err := strconv.ParseInt(strings.TrimPrefix(value, "@"), 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		return seconds
	}
	seconds, _ := parseStamp(value)
	return seconds
}

func TimerStamp(value string) int64 {
	value = strings.TrimSpace(value)
	if blank(value) {
		return 0
	}
	if seconds, ok := parseStamp(value); ok {
		return seconds
	}
	if micros, err := strconv.ParseInt(strings.TrimPrefix(value, "@"), 10, 64); err == nil && micros > 0 {
		return micros / 1e6
	}
	return 0
}
