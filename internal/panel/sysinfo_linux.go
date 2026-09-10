//go:build linux

package panel

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func systemInfo() map[string]any {
	info := map[string]any{}
	info["disk"] = diskUsage("/")
	info["memory"] = memoryUsage()
	load, ok := loadAverage()
	if ok {
		info["load"] = load
	} else {
		info["load"] = nil
	}
	info["cpu_count"] = runtime.NumCPU()
	info["uptime_seconds"] = uptimeSeconds()
	return info
}

func diskUsage(path string) any {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return nil
	}
	unit := uint64(st.Frsize)
	if unit == 0 {
		unit = uint64(st.Bsize)
	}
	total := st.Blocks * unit
	used := (st.Blocks - st.Bfree) * unit
	free := st.Bavail * unit
	percent := 0.0
	if total > 0 {
		percent = roundTo(float64(used)/float64(total)*100, 1)
	}
	return map[string]any{"total": total, "used": used, "free": free, "percent": percent}
}

func memoryUsage() any {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			values[strings.TrimSpace(key)] = v * 1024
		}
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	percent := 0.0
	if total > 0 {
		percent = roundTo(float64(total-available)/float64(total)*100, 1)
	}
	return map[string]any{
		"total": total, "available": available, "used": total - available,
		"percent": percent,
	}
}

func loadAverage() (map[string]any, bool) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return nil, false
	}
	out := map[string]any{}
	for i, key := range []string{"1m", "5m", "15m"} {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil, false
		}
		out[key] = v
	}
	return out, true
}

func uptimeSeconds() any {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return int64(v)
}
