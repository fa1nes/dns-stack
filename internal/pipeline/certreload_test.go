package pipeline

import "testing"

func TestMosproxyReleasesHotReloadCertificates(t *testing.T) {
	for id, want := range map[string]bool{
		"v0.2.0\n":   true,
		"v1.10.3":    true,
		"":           false,
		"80afb01":    false,
		"v0.2":       false,
		"v0.2.0-rc1": false,
	} {
		if got := mosproxyHotReloadsCerts(id); got != want {
			t.Errorf("build-id %q 判成 %v，期望 %v——fork 从 v0.2.0 起按 semver 发布且自带证书热重载；"+
				"判据曾经只认旧的 -p14 后缀，于是每次续签（约 3 天一次）都重启 mosproxy、丢掉整个缓存", id, got, want)
		}
	}
}
