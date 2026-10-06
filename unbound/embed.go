package unbound

import _ "embed"

//go:embed unbound.template.conf
var Template string

const (
	ServeExpiredTTL = "serve-expired-ttl"
	CacheMinTTL     = "cache-min-ttl"
)

var PanelTunable = map[string]bool{ServeExpiredTTL: true, CacheMinTTL: true}
