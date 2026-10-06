package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoHPathListsEveryProtocolAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("PUBLIC_IPV4=203.0.113.1\nDOH_PATH=/abc/dns-query\nDOT_PORT=8853\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := renderDoHPath(path)
	for _, want := range []string{
		"DOH_URL=https://203.0.113.1/abc/dns-query\n",
		"DOH_PATH_IS_DEFAULT=0\n",
		"DOT_URL=tls://203.0.113.1:8853\n",
		"DOQ_URL=quic://203.0.113.1:8853\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doh-path 输出缺少 %q——面板「设置 → 接入」按这几行列出地址：\n%s", want, out)
		}
	}
}
