//go:build linux || darwin

package opsctl

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func readPassword(file *os.File) (string, error) {
	fd := int(file.Fd())
	state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	quiet := *state
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, state)
	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
