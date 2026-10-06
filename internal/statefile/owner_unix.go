//go:build unix

package statefile

import (
	"os"
	"syscall"
)

func keepOwner(file *os.File, target string) error {
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := file.Chown(int(st.Uid), int(st.Gid)); err != nil && os.Geteuid() == 0 {
		return err
	}
	return nil
}
