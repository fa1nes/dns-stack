//go:build unix

package statefile

import (
	"os"
	"syscall"
	"testing"
)

func groupOf(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Sys().(*syscall.Stat_t).Gid)
}
