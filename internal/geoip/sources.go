package geoip

import (
	"os"
	"sync"
	"time"
)

const (
	DefaultDBIPASNPath  = "/var/lib/dns-stack/geoip/dbip-asn.mmdb"
	DefaultDBIPCityPath = "/var/lib/dns-stack/geoip/dbip-city.mmdb"
)

type SourceResult struct {
	Name      string         `json:"name"`
	Label     string         `json:"label"`
	Available bool           `json:"available"`
	Record    map[string]any `json:"record"`
	Error     string         `json:"error"`
}

func isoCode(reader any, ip string) string {
	r, ok := reader.(*MMDBReader)
	if !ok || r == nil {
		return ""
	}
	rec, err := r.Get(ip)
	if err != nil || rec == nil {
		return ""
	}
	country, ok := rec["country"].(map[string]any)
	if !ok {
		if country, ok = rec["registered_country"].(map[string]any); !ok {
			return ""
		}
	}
	return mapString(country, "iso_code")
}

func withCountryCode(out map[string]any, code string) map[string]any {
	if out == nil {
		return nil
	}
	if code != "" {
		out["country_code"] = code
	}
	return out
}

type DBIP struct {
	ASNPath  string
	CityPath string
	mu       sync.Mutex
	asn      *MMDBReader
	city     *MMDBReader
	mtimes   map[string]time.Time
	errs     map[string]string
}

func NewDBIP(asnPath, cityPath string) *DBIP {
	if asnPath == "" {
		asnPath = DefaultDBIPASNPath
	}
	if cityPath == "" {
		cityPath = DefaultDBIPCityPath
	}
	return &DBIP{ASNPath: asnPath, CityPath: cityPath,
		mtimes: map[string]time.Time{}, errs: map[string]string{}}
}

func (d *DBIP) reload() {
	for kind, path := range map[string]string{"asn": d.ASNPath, "city": d.CityPath} {
		st, err := os.Stat(path)
		if err != nil {
			d.errs[kind] = "数据库文件不存在"
			if kind == "asn" && d.asn != nil {
				d.asn.Close()
				d.asn = nil
			}
			if kind == "city" && d.city != nil {
				d.city.Close()
				d.city = nil
			}
			d.mtimes[kind] = time.Time{}
			continue
		}
		if d.mtimes[kind].Equal(st.ModTime()) {
			continue
		}
		reader, err := OpenMMDB(path)
		if err != nil {
			d.errs[kind] = err.Error()
			continue
		}
		if kind == "asn" {
			if d.asn != nil {
				d.asn.Close()
			}
			d.asn = reader
		} else {
			if d.city != nil {
				d.city.Close()
			}
			d.city = reader
		}
		d.mtimes[kind] = st.ModTime()
		delete(d.errs, kind)
	}
}

func (d *DBIP) Lookup(ip string) SourceResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reload()
	out := SourceResult{Name: "dbip", Label: "DB-IP Lite"}
	if d.asn == nil && d.city == nil {
		out.Error = firstError(d.errs, "asn", "city")
		return out
	}
	out.Available = true
	rec := probeMaxMind(ip, d.asn, d.city)
	if rec == nil {
		return out
	}
	rec["source"] = "dbip"
	out.Record = withCountryCode(resultFromMap(ip, rec, true).JSON(), isoCode(d.city, ip))
	return out
}

func (d *DBIP) Status() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reload()
	out := map[string]any{}
	for kind, reader := range map[string]*MMDBReader{"asn": d.asn, "city": d.city} {
		entry := map[string]any{"available": reader != nil, "error": nil}
		if message := d.errs[kind]; message != "" {
			entry["error"] = message
		}
		if reader != nil {
			entry["build_epoch"] = reader.BuildEpoch
		}
		out[kind] = entry
	}
	out["available"] = d.asn != nil || d.city != nil
	return out
}

func firstError(errs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := errs[key]; value != "" {
			return value
		}
	}
	return "数据库不可用"
}

func (g *GeoDB) Sources(ip string) []SourceResult {
	out := make([]SourceResult, 0, 2)

	cn := SourceResult{Name: "qqwry", Label: "纯真 qqwry"}
	if reader := g.load("cnip"); reader != nil {
		cn.Available = true
		if rec := probeCNIP(ip, reader); rec != nil {
			code := mapString(rec, "country_code")
			rec["source"] = "qqwry"
			cn.Record = withCountryCode(resultFromMap(ip, rec, true).JSON(), code)
		}
	} else {
		cn.Error = g.errors["cnip"]
	}
	out = append(out, cn)

	mm := SourceResult{Name: "maxmind", Label: "MaxMind GeoLite2"}
	asn, city := g.load("asn"), g.load("city")
	if asn != nil || city != nil {
		mm.Available = true
		if rec := probeMaxMind(ip, asn, city); rec != nil {
			rec["source"] = "maxmind"
			mm.Record = withCountryCode(resultFromMap(ip, rec, true).JSON(), isoCode(city, ip))
		}
	} else {
		mm.Error = firstError(g.errors, "asn", "city")
	}
	out = append(out, mm)
	return out
}
