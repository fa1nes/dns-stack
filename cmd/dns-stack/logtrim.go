package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type trimResult struct {
	Trimmed int
}

func trimDirectory(dir string, keepBytes int64) (trimResult, error) {
	if keepBytes <= 0 {
		return trimResult{}, fmt.Errorf("保留字节数必须大于 0")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return trimResult{}, err
	}
	var result trimResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return result, err
		}
		if info.Size() <= keepBytes {
			continue
		}
		if err := trimFile(path, info, keepBytes); err != nil {
			return result, err
		}
		result.Trimmed++
	}
	return result, nil
}

func trimFile(path string, info os.FileInfo, keepBytes int64) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(info.Size()-keepBytes, io.SeekStart); err != nil {
		return err
	}
	tail := make([]byte, keepBytes)
	if _, err := io.ReadFull(file, tail); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := file.Write(tail); err != nil {
		return err
	}
	return file.Sync()
}
