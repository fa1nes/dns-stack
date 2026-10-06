package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeBackupConfig(t *testing.T, dir, role string) Config {
	t.Helper()
	configPath := filepath.Join(dir, "config.env")
	if err := os.WriteFile(configPath, []byte("ROLE="+role+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		ConfigFile: configPath,
		StateDir:   filepath.Join(dir, "state"),
		SystemdDir: filepath.Join(dir, "systemd"),
		GoBin:      filepath.Join(dir, "missing-dns-stack"),
	}
}

func TestCollectSystemdUsesCurrentRoleRegistry(t *testing.T) {
	tests := []struct {
		role    string
		include []string
		exclude []string
	}{
		{
			role: "cn-resolver",
			include: []string{
				"dns-stack-panel.service",
				"dns-stack-routing-data.timer",
			},
			exclude: []string{"dns-stack-classify.service", "dns-stack-trim-logs.service"},
		},
		{
			role:    "offshore",
			include: []string{"unbound.service"},
			exclude: []string{"dns-stack-panel.service", "dns-stack-classify.service"},
		},
	}

	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			dir := t.TempDir()
			cfg := writeBackupConfig(t, dir, test.role)
			if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{
				"dns-stack-panel.service",
				"dns-stack-routing-data.timer",
				"dns-stack-trim-logs.service",
				"dns-stack-classify.service",
				"unbound.service",
			} {
				if err := os.WriteFile(filepath.Join(cfg.SystemdDir, name), []byte(name), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			dest := filepath.Join(dir, "payload")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			cfg.collectSystemd(dest)

			for _, name := range test.include {
				if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
					t.Errorf("expected current unit %s in backup: %v", name, err)
				}
			}
			for _, name := range test.exclude {
				if _, err := os.Stat(filepath.Join(dest, name)); !os.IsNotExist(err) {
					t.Errorf("unexpected unit %s in backup (stat error: %v)", name, err)
				}
			}
		})
	}
}

func TestCollectStateDoesNotCopyRetiredClassifierData(t *testing.T) {
	for _, role := range []string{"cn-resolver", "offshore"} {
		t.Run(role, func(t *testing.T) {
			dir := t.TempDir()
			cfg := writeBackupConfig(t, dir, role)
			if err := os.MkdirAll(filepath.Join(cfg.StateDir, "publish"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"classifier.db", "manual-cn.txt", "manual-gfw.txt", "manual-exclude.txt"} {
				if err := os.WriteFile(filepath.Join(cfg.StateDir, name), []byte("retired"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(cfg.StateDir, "publish", "rules.txt"), []byte("retired"), 0o600); err != nil {
				t.Fatal(err)
			}

			dest := filepath.Join(dir, "payload")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := cfg.collectState(context.Background(), dest); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dest, "state", "classifier.db")); !os.IsNotExist(err) {
				t.Fatalf("retired classifier database was copied (stat error: %v)", err)
			}
			if _, err := os.Stat(filepath.Join(dest, "state", "publish")); !os.IsNotExist(err) {
				t.Fatalf("retired publish data was copied (stat error: %v)", err)
			}
		})
	}
}
