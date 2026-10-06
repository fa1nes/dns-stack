//go:build linux

package panel

import "testing"

func TestSystemInfoShipsNothingTheFrontendIgnores(t *testing.T) {
	frontend := frontendText(t)
	info := systemInfo()
	for name, value := range info {
		nested, ok := value.(map[string]any)
		if !ok {
			continue
		}
		keys := make([]string, 0, len(nested))
		for key := range nested {
			keys = append(keys, key)
		}
		assertFrontendReads(t, "/api/overview.system."+name, keys, frontend)
	}
}
