package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const staleTempAge = 24 * time.Hour

var (
	atomicLeftover = regexp.MustCompile(`^\.(.+)\.\d+$`)
	legacyStats    = regexp.MustCompile(`^\.stats\.[A-Za-z0-9]+$`)
)

func isStaleTemp(dir string, entry os.DirEntry, now time.Time) bool {
	if !entry.Type().IsRegular() {
		return false
	}
	name := entry.Name()
	switch {
	case legacyStats.MatchString(name):
	case atomicLeftover.MatchString(name):
		target := atomicLeftover.FindStringSubmatch(name)[1]
		if _, err := os.Lstat(filepath.Join(dir, target)); err != nil {
			return false
		}
	default:
		return false
	}
	info, err := entry.Info()
	return err == nil && now.Sub(info.ModTime()) > staleTempAge
}

func SweepStaleTemps(dirs []string, now time.Time) (removed []string, err error) {
	for _, dir := range dirs {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return removed, readErr
		}
		for _, entry := range entries {
			if !isStaleTemp(dir, entry, now) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				return removed, rmErr
			}
			removed = append(removed, path)
		}
	}
	return removed, nil
}

func stepStaleTemps(_ context.Context, rt *Runtime) error {
	dirs := []string{rt.Config.StateDir, rt.Config.Path("chnroute"), rt.Config.Path("sync-state")}
	removed, err := SweepStaleTemps(dirs, time.Now())
	if len(removed) > 0 {
		rt.Infof("清掉 %d 个超过 24 小时的写入残留临时文件", len(removed))
	} else if err == nil {
		rt.Infof("没有写入残留的临时文件")
	}
	return err
}
