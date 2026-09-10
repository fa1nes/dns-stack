package geoip

import (
	"os"
	"strings"
	"sync"
	"time"
)

const DefaultIPInfoPath = "/var/lib/dns-stack/geoip/ipinfo-lite.mmdb"

type IPInfo struct {
	Path   string
	mu     sync.Mutex
	reader *MMDBReader
	mtime  time.Time
	err    string
}

func NewIPInfo(path string) *IPInfo {
	if path == "" {
		path = DefaultIPInfoPath
	}
	return &IPInfo{Path: path}
}

func (p *IPInfo) reload() {
	st, err := os.Stat(p.Path)
	if err != nil {
		if p.reader != nil {
			p.reader.Close()
			p.reader = nil
		}
		p.mtime = time.Time{}
		p.err = "数据库文件不存在"
		return
	}
	if p.mtime.Equal(st.ModTime()) {
		return
	}
	reader, err := OpenMMDB(p.Path)
	if err != nil {
		p.err = err.Error()
		return
	}
	if p.reader != nil {
		p.reader.Close()
	}
	p.reader, p.mtime, p.err = reader, st.ModTime(), ""
}

func (p *IPInfo) Lookup(ip string) SourceResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reload()
	out := SourceResult{Name: "ipinfo", Label: "IPinfo Lite"}
	if p.reader == nil {
		out.Error = p.err
		if out.Error == "" {
			out.Error = "数据库不可用"
		}
		return out
	}
	out.Available = true
	rec, err := p.reader.Get(ip)
	if err != nil || rec == nil {
		return out
	}
	built := map[string]any{"source": "ipinfo"}
	if value := mapString(rec, "country"); value != "" {
		built["country"] = value
	}
	if value := mapString(rec, "as_name"); value != "" {
		built["as_org"] = value
	}
	if value := mapString(rec, "asn"); value != "" {
		built["asn"] = strings.TrimPrefix(strings.TrimPrefix(value, "AS"), "as")
	} else if value := rec["asn"]; value != nil {
		built["asn"] = value
	}
	if carrier := MatchCarrier(mapString(rec, "as_name")); carrier != "" {
		built["carrier"] = carrier
	}
	built["label"] = composeLabel(built, mapString(rec, "as_name"))
	out.Record = withCountryCode(resultFromMap(ip, built, true).JSON(), mapString(rec, "country_code"))
	return out
}

func (p *IPInfo) Status() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reload()
	entry := map[string]any{"available": p.reader != nil, "path": p.Path, "error": nil}
	if p.err != "" {
		entry["error"] = p.err
	}
	if p.reader != nil {
		entry["build_epoch"] = p.reader.BuildEpoch
	}
	return entry
}
