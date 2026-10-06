//go:build !unix

package statefile

import "testing"

func groupOf(*testing.T, string) int { return -1 }
