package opsctl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dns-stack/dns-stack/internal/stack"
)

func TestDefaultLogUnitMatchesCurrentRoles(t *testing.T) {
	for _, test := range []struct {
		role string
		want string
	}{
		{role: stack.RoleCNResolver, want: "mosproxy"},
		{role: stack.RoleOffshore, want: "unbound"},
		{role: "unknown", want: "unbound"},
	} {
		if got := defaultLogUnit(test.role); got != test.want {
			t.Errorf("defaultLogUnit(%q) = %q, want %q", test.role, got, test.want)
		}
	}
}

func TestMigrateShipsOnlyExistingRepositoryItems(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, item := range shippedItems {
		if _, err := os.Stat(filepath.Join(root, item)); err != nil {
			t.Errorf("migration payload item %q is not present in the repository: %v", item, err)
		}
	}
}
