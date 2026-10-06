//go:build aix || android || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package geoip

import (
	"os"
	"syscall"
)

func mapReadOnly(file *os.File, size int64) ([]byte, error) {
	if size <= 0 || int64(int(size)) != size {
		return nil, syscall.EINVAL
	}
	return syscall.Mmap(int(file.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
}

func unmapReadOnly(data []byte) error {
	if data == nil {
		return nil
	}
	return syscall.Munmap(data)
}
