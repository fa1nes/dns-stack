//go:build unix

package selfcheck

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func panelCanRead(path, group string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err.Error()
	}
	perm := info.Mode().Perm()
	if perm&0o004 != 0 {
		return true, ""
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return true, ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true, ""
	}
	if strconv.Itoa(int(st.Gid)) == g.Gid && perm&0o040 != 0 {
		return true, ""
	}
	owner := strconv.Itoa(int(st.Gid))
	if found, err := user.LookupGroupId(owner); err == nil {
		owner = found.Name
	}
	return false, fmt.Sprintf("属组是 %s、权限 %04o，%s 组读不到", owner, perm, group)
}
