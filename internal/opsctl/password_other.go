//go:build !linux && !darwin

package opsctl

import (
	"errors"
	"os"
)

func readPassword(*os.File) (string, error) {
	return "", errors.New("当前平台不支持关闭回显")
}
