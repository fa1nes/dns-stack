package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAcmeRenewForcesOnlyWhenAsked(t *testing.T) {
	plain := acmeRenewArgs("192.0.2.1", false)
	if slices.Contains(plain, "--force") {
		t.Fatalf("a routine renewal must leave the schedule to acme.sh, got %v", plain)
	}
	if i := slices.Index(plain, "--log"); i < 0 || i+1 >= len(plain) || plain[i+1] != AcmeLog {
		t.Fatalf("acme.sh must log to %s so failed renewals leave a trace, got %v", AcmeLog, plain)
	}
	if !slices.Contains(acmeRenewArgs("192.0.2.1", true), "--force") {
		t.Fatal("a renewal close to expiry must force acme.sh")
	}
}

func TestEnsureAcmeLogTurnsOnLoggingOnce(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "account.conf")
	if err := os.WriteFile(conf, []byte("#LOG_FILE=\"/x\"\nAUTO_UPGRADE='1'"), 0o600); err != nil {
		t.Fatal(err)
	}
	added, err := EnsureAcmeLog(conf)
	if err != nil || !added {
		t.Fatalf("a commented-out LOG_FILE must be treated as off: added=%v err=%v", added, err)
	}
	if again, err := EnsureAcmeLog(conf); err != nil || again {
		t.Fatalf("second run must leave the file alone: added=%v err=%v", again, err)
	}
	data, _ := os.ReadFile(conf)
	want := "#LOG_FILE=\"/x\"\nAUTO_UPGRADE='1'\nLOG_FILE='" + AcmeLog + "'\n"
	if string(data) != want {
		t.Fatalf("got %q, want %q", data, want)
	}
	if added, err := EnsureAcmeLog(filepath.Join(t.TempDir(), "missing.conf")); err != nil || added {
		t.Fatalf("no acme.sh install means nothing to do: added=%v err=%v", added, err)
	}
}
