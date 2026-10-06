package web

import "embed"

//go:embed index.html login.html assets
var Files embed.FS
