//go:build !unix

package statefile

import "errors"

var ErrLocked = errors.New("另一个进程正持有这把锁")

func TryLock(path string) (func(), error) { return func() {}, nil }
