package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRedactPathHidesSecretPath(t *testing.T) {
	secret := "/fab024b4c462c21ef07519465a0f71e4/dns-query"
	err := errors.New(`Post "https://127.0.0.1:1` + secret + `": dial tcp: connection refused`)
	got := redactPath(err, secret)
	if strings.Contains(got, secret) {
		t.Fatalf("随机 DOH_PATH 泄漏到了错误信息里: %s", got)
	}
	if !strings.Contains(got, "<DOH_PATH>") {
		t.Fatalf("没有被替换成占位符: %s", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("原因被抹掉了，失败信息就没用了: %s", got)
	}
}

func TestRedactPathLeavesDefaultPathAlone(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:443: connection refused")
	if got := redactPath(err, "/"); got != err.Error() {
		t.Fatalf("path=/ 不该触发替换: %s", got)
	}
	if got := redactPath(err, ""); got != err.Error() {
		t.Fatalf("path 为空不该触发替换: %s", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "/real"); got != "/real" {
		t.Fatalf("got %q", got)
	}
	if got := firstNonEmpty("/first", "/second"); got != "/first" {
		t.Fatalf("got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("got %q", got)
	}
}
