//go:build !unix

package selfcheck

func panelCanRead(string, string) (bool, string) { return true, "" }
