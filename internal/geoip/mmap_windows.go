//go:build windows

package geoip

import (
	"errors"
	"io"
	"os"
)

func mapReadOnly(file *os.File, size int64) ([]byte, error) {
	if size <= 0 || int64(int(size)) != size {
		return nil, errors.New("geoip file size is invalid")
	}
	data := make([]byte, int(size))
	read, err := file.ReadAt(data, 0)
	if err != nil && !(errors.Is(err, io.EOF) && int64(read) == size) {
		return nil, err
	}
	if int64(read) != size {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func unmapReadOnly(_ []byte) error { return nil }
