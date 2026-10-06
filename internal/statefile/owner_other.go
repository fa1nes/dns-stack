//go:build !unix

package statefile

import "os"

func keepOwner(*os.File, string) error { return nil }
