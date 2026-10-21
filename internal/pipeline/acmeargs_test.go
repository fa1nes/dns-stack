package pipeline

import (
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
