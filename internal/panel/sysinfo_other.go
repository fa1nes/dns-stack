//go:build !linux

package panel

import "runtime"

func systemInfo() map[string]any {
	return map[string]any{
		"disk": nil, "memory": nil, "load": nil,
		"cpu_count": runtime.NumCPU(), "uptime_seconds": nil,
	}
}
