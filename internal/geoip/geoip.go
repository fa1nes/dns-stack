package geoip

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultGeoIPDir = "/var/lib/dns-stack/geoip"
	DefaultASNPath  = DefaultGeoIPDir + "/GeoLite2-ASN.mmdb"
	DefaultCityPath = DefaultGeoIPDir + "/GeoLite2-City.mmdb"
	DefaultCNIPPath = DefaultGeoIPDir + "/qqwry.ipdb"
)

type MMDBError struct{ Err error }

func (e *MMDBError) Error() string { return e.Err.Error() }
func (e *MMDBError) Unwrap() error { return e.Err }

type decoder struct {
	b    []byte
	base int
}

func (d decoder) decode(off int) (any, int, error) {
	if off < 0 || off >= len(d.b) {
		return nil, off, errors.New("mmdb offset out of range")
	}
	ctrl := d.b[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 0 {
		if off >= len(d.b) {
			return nil, off, errors.New("mmdb extended type truncated")
		}
		typ = int(d.b[off]) + 7
		off++
	}
	if typ == 1 {
		return d.pointer(ctrl, off)
	}
	sz, noff, err := d.size(ctrl, off)
	if err != nil {
		return nil, noff, err
	}
	off = noff
	if sz < 0 || off+sz > len(d.b) {
		return nil, off, errors.New("mmdb value truncated")
	}
	switch typ {
	case 2:
		return string(d.b[off : off+sz]), off + sz, nil
	case 3:
		if sz != 8 {
			return nil, off, errors.New("mmdb double size")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d.b[off:])), off + sz, nil
	case 4:
		v := make([]byte, sz)
		copy(v, d.b[off:off+sz])
		return v, off + sz, nil
	case 5, 6, 9, 10:
		var v uint64
		for _, x := range d.b[off : off+sz] {
			v = (v << 8) | uint64(x)
		}
		return v, off + sz, nil
	case 7:
		m := make(map[string]any, sz)
		for i := 0; i < sz; i++ {
			k, next, err := d.decode(off)
			if err != nil {
				return nil, next, err
			}
			off = next
			v, next, err := d.decode(off)
			if err != nil {
				return nil, next, err
			}
			off = next
			ks, ok := k.(string)
			if ok {
				m[ks] = v
			}
		}
		return m, off, nil
	case 8:
		var v int64
		for _, x := range d.b[off : off+sz] {
			v = (v << 8) | int64(x)
		}
		if sz > 0 && d.b[off]&0x80 != 0 {
			v -= int64(1) << uint(sz*8)
		}
		return v, off + sz, nil
	case 11:
		a := make([]any, 0, sz)
		for i := 0; i < sz; i++ {
			v, next, err := d.decode(off)
			if err != nil {
				return nil, next, err
			}
			off = next
			a = append(a, v)
		}
		return a, off, nil
	case 14:
		return sz != 0, off, nil
	case 15:
		if sz != 4 {
			return nil, off, errors.New("mmdb float size")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(d.b[off:]))), off + sz, nil
	default:
		return nil, off, fmt.Errorf("unsupported mmdb type %d", typ)
	}
}

func (d decoder) size(ctrl byte, off int) (int, int, error) {
	v := int(ctrl & 0x1f)
	switch v {
	case 29:
		if off >= len(d.b) {
			return 0, off, errors.New("mmdb size truncated")
		}
		return 29 + int(d.b[off]), off + 1, nil
	case 30:
		if off+2 > len(d.b) {
			return 0, off, errors.New("mmdb size truncated")
		}
		return 285 + int(binary.BigEndian.Uint16(d.b[off:])), off + 2, nil
	case 31:
		if off+3 > len(d.b) {
			return 0, off, errors.New("mmdb size truncated")
		}
		return 65821 + (int(d.b[off])<<16 | int(d.b[off+1])<<8 | int(d.b[off+2])), off + 3, nil
	default:
		return v, off, nil
	}
}

func (d decoder) pointer(ctrl byte, off int) (any, int, error) {
	ps := (ctrl >> 3) & 3
	var p int
	switch ps {
	case 0:
		if off >= len(d.b) {
			return nil, off, errors.New("mmdb pointer truncated")
		}
		p = int(ctrl&7)<<8 | int(d.b[off])
		off++
	case 1:
		if off+2 > len(d.b) {
			return nil, off, errors.New("mmdb pointer truncated")
		}
		p = (int(ctrl&7)<<16 | int(binary.BigEndian.Uint16(d.b[off:]))) + 2048
		off += 2
	case 2:
		if off+3 > len(d.b) {
			return nil, off, errors.New("mmdb pointer truncated")
		}
		p = (int(ctrl&7)<<24 | int(d.b[off])<<16 | int(d.b[off+1])<<8 | int(d.b[off+2])) + 526336
		off += 3
	default:
		if off+4 > len(d.b) {
			return nil, off, errors.New("mmdb pointer truncated")
		}
		p = int(binary.BigEndian.Uint32(d.b[off:]))
		off += 4
	}
	v, _, err := d.decode(d.base + p)
	return v, off, err
}

type MMDBReader struct {
	Path       string
	data       []byte
	file       *os.File
	recordSize int
	nodeCount  int
	ipVersion  int
	dataBase   int
	Metadata   map[string]any
	BuildEpoch int64
}

func OpenMMDB(path string) (*MMDBReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Size() == 0 {
		f.Close()
		return nil, errors.New("empty mmdb")
	}
	b, err := mapReadOnly(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	marker := []byte{0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}
	start := len(b) - 128*1024
	if start < 0 {
		start = 0
	}
	idx := -1
	for i := len(b) - len(marker); i >= start; i-- {
		if string(b[i:i+len(marker)]) == string(marker) {
			idx = i
			break
		}
	}
	if idx < 0 {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("missing metadata marker")
	}
	metaStart := idx + len(marker)
	meta, _, err := (decoder{b: b, base: metaStart}).decode(metaStart)
	if err != nil {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, err
	}
	m, ok := meta.(map[string]any)
	if !ok {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("invalid mmdb metadata")
	}
	nodeCount, ok := intValue(m["node_count"])
	if !ok {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("missing mmdb node_count")
	}
	recordSize, ok := intValue(m["record_size"])
	if !ok || (recordSize != 24 && recordSize != 28 && recordSize != 32) {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("unsupported mmdb record_size")
	}
	ipVersion, _ := intValue(m["ip_version"])
	if ipVersion == 0 {
		ipVersion = 4
	}
	base := nodeCount*(recordSize*2/8) + 16
	r := &MMDBReader{Path: path, data: b, file: f, recordSize: recordSize, nodeCount: nodeCount, ipVersion: ipVersion, dataBase: base, Metadata: m}
	if epoch, ok := intValue(m["build_epoch"]); ok {
		r.BuildEpoch = int64(epoch)
	}
	return r, nil
}

func (r *MMDBReader) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.data != nil {
		err = unmapReadOnly(r.data)
		r.data = nil
	}
	if r.file != nil {
		if e := r.file.Close(); err == nil {
			err = e
		}
		r.file = nil
	}
	return err
}

func (r *MMDBReader) readNode(node, bit int) (int, error) {
	width := r.recordSize * 2 / 8
	base := node * width
	if base < 0 || base+width > len(r.data) {
		return 0, errors.New("mmdb node out of range")
	}
	switch r.recordSize {
	case 24:
		off := base + bit*3
		return int(r.data[off])<<16 | int(r.data[off+1])<<8 | int(r.data[off+2]), nil
	case 32:
		off := base + bit*4
		return int(binary.BigEndian.Uint32(r.data[off:])), nil
	default:
		middle := r.data[base+3]
		if bit == 0 {
			return int(middle&0xf0)<<20 | int(r.data[base])<<16 | int(r.data[base+1])<<8 | int(r.data[base+2]), nil
		}
		return int(middle&0x0f)<<24 | int(r.data[base+4])<<16 | int(r.data[base+5])<<8 | int(r.data[base+6]), nil
	}
}

func (r *MMDBReader) Get(ip string) (map[string]any, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil, nil
	}
	if a.Is6() && r.ipVersion == 4 {
		return nil, nil
	}
	var packed [16]byte
	bits := 128
	if a.Is4() {
		v := a.As4()
		if r.ipVersion == 6 {
			packed[10], packed[11] = 0xff, 0xff
			copy(packed[12:], v[:])
		} else {
			copy(packed[:4], v[:])
			bits = 32
		}
	} else {
		packed = a.As16()
	}
	node := 0
	for i := 0; i < bits; i++ {
		if node >= r.nodeCount {
			break
		}
		bit := int((packed[i/8] >> uint(7-(i&7))) & 1)
		n, err := r.readNode(node, bit)
		if err != nil {
			return nil, err
		}
		node = n
	}
	if node <= r.nodeCount {
		return nil, nil
	}
	off := node - r.nodeCount - 16 + r.dataBase
	v, _, err := (decoder{b: r.data, base: r.dataBase}).decode(off)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (r *MMDBReader) v4Root() (int, error) {
	if r.ipVersion == 4 {
		return 0, nil
	}
	node := 0
	for i := 0; i < 96; i++ {
		if node >= r.nodeCount {
			return node, nil
		}
		bit := 0
		if i >= 80 && i < 96 {
			bit = 1
		}
		n, err := r.readNode(node, bit)
		if err != nil {
			return 0, err
		}
		node = n
	}
	return node, nil
}

func (r *MMDBReader) decodeAt(node int) map[string]any {
	off := node - r.nodeCount - 16 + r.dataBase
	v, _, err := (decoder{b: r.data, base: r.dataBase}).decode(off)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func (r *MMDBReader) WalkV4(visit func(prefix netip.Prefix, countryCode string) error) error {
	root, err := r.v4Root()
	if err != nil {
		return err
	}
	type item struct {
		node   int
		prefix uint32
		depth  int
	}
	stack := make([]item, 0, 64)
	stack = append(stack, item{root, 0, 0})
	codes := make(map[int]string)
	for len(stack) > 0 {
		last := len(stack) - 1
		it := stack[last]
		stack = stack[:last]
		if it.depth > 32 {
			continue
		}
		for _, bit := range []int{1, 0} {
			child, err := r.readNode(it.node, bit)
			if err != nil {
				return err
			}
			value := it.prefix | uint32(bit)<<uint(31-it.depth)
			if child < r.nodeCount {
				stack = append(stack, item{child, value, it.depth + 1})
				continue
			}
			if child == r.nodeCount {
				continue
			}
			code, cached := codes[child]
			if !cached {
				code = mmdbCountryCode(r.decodeAt(child))
				codes[child] = code
			}
			if code == "" {
				continue
			}
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{
				byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
			}), it.depth+1)
			if err := visit(prefix, code); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *MMDBReader) NodeCount() int {
	if r == nil {
		return 0
	}
	return r.nodeCount
}

func (r *MMDBReader) DatabaseType() string {
	if r == nil || r.Metadata == nil {
		return ""
	}
	value, _ := r.Metadata["database_type"].(string)
	return value
}

func CountryCodeOf(record map[string]any) string {
	return mmdbCountryCode(record)
}

func mmdbCountryCode(record map[string]any) string {
	for _, key := range []string{"country", "registered_country"} {
		block, ok := record[key].(map[string]any)
		if !ok {
			continue
		}
		if code, ok := block["iso_code"].(string); ok && code != "" {
			return code
		}
	}
	if code, ok := record["country_code"].(string); ok {
		return code
	}
	return ""
}

type IPDBReader struct {
	Path       string
	data       []byte
	file       *os.File
	metaLen    int
	nodeCount  int
	dataBase   int
	ipVersion  int
	v4Start    int
	Metadata   map[string]any
	Fields     []string
	BuildEpoch int64
}

func OpenIPDB(path string) (*IPDBReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	b, err := mapReadOnly(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	if len(b) < 4 {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("ipdb header truncated")
	}
	ml := int(binary.BigEndian.Uint32(b[:4]))
	if ml < 2 || 4+ml > len(b) {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("ipdb metadata truncated")
	}
	var meta map[string]any
	if err := json.Unmarshal(b[4:4+ml], &meta); err != nil {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, err
	}
	nodeCount, ok := intValue(meta["node_count"])
	if !ok {
		_ = unmapReadOnly(b)
		f.Close()
		return nil, errors.New("ipdb missing node_count")
	}
	fields := []string{}
	if a, ok := meta["fields"].([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				fields = append(fields, s)
			}
		}
	}
	ipVersion, _ := intValue(meta["ip_version"])
	if ipVersion == 0 {
		ipVersion = 1
	}
	v4, _ := intValue(meta["v4node"])
	r := &IPDBReader{Path: path, data: b, file: f, metaLen: ml, nodeCount: nodeCount, dataBase: 4 + ml + nodeCount*8, ipVersion: ipVersion, v4Start: v4, Metadata: meta, Fields: fields}
	if epoch, ok := intValue(meta["build"]); ok {
		r.BuildEpoch = int64(epoch)
	}
	if r.v4Start == 0 && r.ipVersion&2 != 0 {
		r.v4Start, err = r.walk(0, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 96)
		if err != nil {
			r.Close()
			return nil, err
		}
	}
	return r, nil
}

func (r *IPDBReader) NodeCount() int {
	if r == nil {
		return 0
	}
	return r.nodeCount
}

func (r *IPDBReader) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.data != nil {
		err = unmapReadOnly(r.data)
		r.data = nil
	}
	if r.file != nil {
		if e := r.file.Close(); err == nil {
			err = e
		}
		r.file = nil
	}
	return err
}

func (r *IPDBReader) record(node, bit int) (int, error) {
	off := 4 + r.metaLen + node*8 + bit*4
	if off < 0 || off+4 > len(r.data) {
		return 0, errors.New("ipdb node out of range")
	}
	return int(binary.BigEndian.Uint32(r.data[off:])), nil
}

func (r *IPDBReader) walk(node int, packed [16]byte, bits int) (int, error) {
	for i := 0; i < bits; i++ {
		if node >= r.nodeCount {
			break
		}
		bit := int((packed[i/8] >> uint(7-(i&7))) & 1)
		var err error
		node, err = r.record(node, bit)
		if err != nil {
			return 0, err
		}
	}
	return node, nil
}

func (r *IPDBReader) decodeNode(node int) map[string]string {
	off := node - r.nodeCount + r.nodeCount*8
	base := 4 + r.metaLen + off
	if base < 0 || base+2 > len(r.data) {
		return nil
	}
	sz := int(binary.BigEndian.Uint16(r.data[base:]))
	if base+2+sz > len(r.data) {
		return nil
	}
	parts := strings.Split(string(r.data[base+2:base+2+sz]), "\t")
	out := make(map[string]string)
	for i, field := range r.Fields {
		if i < len(parts) {
			if v := strings.TrimSpace(parts[i]); v != "" {
				out[field] = v
			}
		}
	}
	return out
}

func (r *IPDBReader) Get(ip string) (map[string]string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil, nil
	}
	var node int
	if a.Is4() {
		if r.v4Start == 0 && r.ipVersion != 1 {
			return nil, nil
		}
		var p [16]byte
		v := a.As4()
		copy(p[:4], v[:])
		node, err = r.walk(r.v4Start, p, 32)
	} else {
		node, err = r.walk(0, a.As16(), 128)
	}
	if err != nil {
		return nil, err
	}
	if node <= r.nodeCount {
		return nil, nil
	}
	return r.decodeNode(node), nil
}

func (r *IPDBReader) WalkV4(visit func(prefix netip.Prefix, record map[string]string) error) error {
	if r.v4Start == 0 && r.ipVersion != 1 {
		return nil
	}
	type item struct {
		node   int
		prefix uint32
		depth  int
	}
	stack := make([]item, 0, 64)
	stack = append(stack, item{r.v4Start, 0, 0})
	records := make(map[int]map[string]string)
	for len(stack) > 0 {
		last := len(stack) - 1
		it := stack[last]
		stack = stack[:last]
		if it.depth > 32 {
			continue
		}
		for _, bit := range []int{1, 0} {
			child, err := r.record(it.node, bit)
			if err != nil {
				return err
			}
			value := it.prefix | uint32(bit)<<uint(31-it.depth)
			if child < r.nodeCount {
				stack = append(stack, item{child, value, it.depth + 1})
				continue
			}
			if child <= r.nodeCount {
				continue
			}
			rec, cached := records[child]
			if !cached {
				rec = r.decodeNode(child)
				records[child] = rec
			}
			if len(rec) == 0 {
				continue
			}
			addr := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
			if err := visit(netip.PrefixFrom(addr, it.depth+1), rec); err != nil {
				return err
			}
		}
	}
	return nil
}

type Result struct {
	IP        string `json:"ip"`
	Available bool   `json:"available"`
	ASN       any    `json:"asn"`
	ASOrg     string `json:"as_org"`
	Carrier   string `json:"carrier"`
	Region    string `json:"region"`
	Country   string `json:"country"`
	City      string `json:"city"`
	Owner     string `json:"owner"`
	Source    string `json:"source"`
	Label     string `json:"label"`
	IsCloud   bool   `json:"is_cloud"`
}

func (r Result) JSON() map[string]any {
	optional := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	return map[string]any{
		"ip": r.IP, "available": r.Available, "asn": r.ASN,
		"as_org": optional(r.ASOrg), "carrier": optional(r.Carrier),
		"region": optional(r.Region), "country": optional(r.Country),
		"city": optional(r.City), "owner": optional(r.Owner),
		"source": optional(r.Source), "label": optional(r.Label),
		"is_cloud": r.IsCloud,
	}
}

type GeoDB struct {
	ASNPath  string
	CityPath string
	CNIPPath string
	asn      *MMDBReader
	city     *MMDBReader
	cnip     *IPDBReader
	mtimes   map[string]time.Time
	errors   map[string]string
}

func NewGeoDB(asnPath, cityPath, cnipPath string) *GeoDB {
	if asnPath == "" {
		asnPath = DefaultASNPath
	}
	if cityPath == "" {
		cityPath = DefaultCityPath
	}
	if cnipPath == "" {
		cnipPath = DefaultCNIPPath
	}
	return NewGeoDBExact(asnPath, cityPath, cnipPath)
}

func NewGeoDBExact(asnPath, cityPath, cnipPath string) *GeoDB {
	return &GeoDB{ASNPath: asnPath, CityPath: cityPath, CNIPPath: cnipPath, mtimes: map[string]time.Time{}, errors: map[string]string{}}
}

func (g *GeoDB) load(kind string) any {
	path := g.ASNPath
	if kind == "city" {
		path = g.CityPath
	} else if kind == "cnip" {
		path = g.CNIPPath
	}
	st, err := os.Stat(path)
	if err != nil {
		if kind == "asn" && g.asn != nil {
			g.asn.Close()
			g.asn = nil
		} else if kind == "city" && g.city != nil {
			g.city.Close()
			g.city = nil
		} else if kind == "cnip" && g.cnip != nil {
			g.cnip.Close()
			g.cnip = nil
		}
		g.mtimes[kind] = time.Time{}
		g.errors[kind] = "数据库文件不存在"
		return nil
	}
	if g.mtimes[kind].Equal(st.ModTime()) {
		if kind == "asn" {
			return g.asn
		}
		if kind == "city" {
			return g.city
		}
		return g.cnip
	}
	var v any
	if kind == "cnip" {
		v, err = OpenIPDB(path)
	} else {
		v, err = OpenMMDB(path)
	}
	if err != nil {
		g.errors[kind] = fmt.Sprintf("%T: %v", err, err)
		return g.reader(kind)
	}
	old := g.reader(kind)
	switch kind {
	case "asn":
		g.asn = v.(*MMDBReader)
	case "city":
		g.city = v.(*MMDBReader)
	case "cnip":
		g.cnip = v.(*IPDBReader)
	}
	g.mtimes[kind] = st.ModTime()
	g.errors[kind] = ""
	if old != nil {
		closeReader(old)
	}
	return v
}

func (g *GeoDB) reader(kind string) any {
	if kind == "asn" {
		return g.asn
	}
	if kind == "city" {
		return g.city
	}
	return g.cnip
}

func closeReader(v any) {
	switch x := v.(type) {
	case *MMDBReader:
		x.Close()
	case *IPDBReader:
		x.Close()
	}
}

func (g *GeoDB) Lookup(ip string) Result {
	out := Result{IP: ip}
	asn := g.load("asn")
	city := g.load("city")
	cnip := g.load("cnip")
	if asn == nil && city == nil && cnip == nil {
		return out
	}
	out.Available = true
	cn := probeCNIP(ip, cnip)
	mm := probeMaxMind(ip, asn, city)
	merged := mergeRecords(cn, mm)
	if merged == nil {
		return out
	}
	return resultFromMap(ip, merged, true)
}

func (g *GeoDB) Available() bool {
	return g.load("asn") != nil || g.load("cnip") != nil
}

func (g *GeoDB) HasASN() bool { return g.load("asn") != nil }

func (g *GeoDB) Status() map[string]any {
	out := map[string]any{}
	for _, kind := range []string{"asn", "city", "cnip"} {
		r := g.load(kind)
		path := g.ASNPath
		if kind == "city" {
			path = g.CityPath
		} else if kind == "cnip" {
			path = g.CNIPPath
		}
		entry := map[string]any{"path": path, "available": r != nil, "error": g.errors[kind]}
		if r != nil {
			var epoch int64
			switch x := r.(type) {
			case *MMDBReader:
				epoch = x.BuildEpoch
			case *IPDBReader:
				epoch = x.BuildEpoch
			}
			entry["build_epoch"] = epoch
			if st, err := os.Stat(path); err == nil {
				entry["size_bytes"] = st.Size()
			}
		}
		out[kind] = entry
	}
	out["available"] = out["asn"].(map[string]any)["available"].(bool) || out["cnip"].(map[string]any)["available"].(bool)
	asnOK := out["asn"].(map[string]any)["available"].(bool)
	cnOK := out["cnip"].(map[string]any)["available"].(bool)
	out["degraded"] = (asnOK || cnOK) && !(asnOK && cnOK)
	return out
}

func ASNumber(v any) (int, bool) { return intValue(v) }

func intValue(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case uint64:
		return int(x), true
	case float64:
		return int(x), true
	case json.Number:
		i, err := strconv.Atoi(string(x))
		return i, err == nil
	default:
		return 0, false
	}
}

var carrierPatterns = []struct {
	keys []string
	name string
}{
	{[]string{"cernet", "china education and research", "教育网", "教育和科研"}, "教育网"},
	{[]string{"china unicom", "chinaunicom", "china169", "cnc group", "china netcom", "unicom", "联通", "网通"}, "联通"},
	{[]string{"china mobile", "chinamobile", "cmnet", "china tietong", "tietong", "railway communication", "移动", "铁通"}, "移动"},
	{[]string{"chinanet", "china telecom", "chinatelecom", "china telecommunications", "电信"}, "电信"},
	{[]string{"china broadcasting", "chinabtn", "broadcasting network", "广电"}, "广电"},
	{[]string{"alibaba", "aliyun", "taobao", "alicloud", "阿里"}, "阿里云"},
	{[]string{"tencent", "腾讯"}, "腾讯云"},
	{[]string{"huawei", "华为"}, "华为云"},
	{[]string{"baidu", "百度"}, "百度"},
	{[]string{"bytedance", "douyin", "toutiao", "字节"}, "字节跳动"},
	{[]string{"kingsoft"}, "金山云"},
	{[]string{"ucloud"}, "UCloud"},
	{[]string{"qihoo", "360"}, "360"},
	{[]string{"jd.com", "jingdong", "jd cloud"}, "京东云"},
	{[]string{"cloudflare"}, "Cloudflare"},
	{[]string{"akamai"}, "Akamai"},
	{[]string{"amazon", "aws"}, "AWS"},
	{[]string{"google"}, "Google"},
	{[]string{"microsoft", "azure"}, "Microsoft"},
	{[]string{"fastly"}, "Fastly"},
}

var asnCarriers = map[int]string{4134: "电信", 4809: "电信", 4811: "电信", 4812: "电信", 4816: "电信", 23650: "电信", 23724: "电信", 58466: "电信", 4808: "联通", 4837: "联通", 9929: "联通", 10099: "联通", 17621: "联通", 17622: "联通", 17623: "联通", 17816: "联通", 9394: "移动", 9808: "移动", 24400: "移动", 24444: "移动", 24445: "移动", 56040: "移动", 56041: "移动", 56042: "移动", 56044: "移动", 56046: "移动", 56047: "移动", 56048: "移动", 58453: "移动", 4538: "教育网", 23910: "教育网"}

var cloudCarriers = map[string]bool{"阿里云": true, "腾讯云": true, "华为云": true, "百度": true, "字节跳动": true, "金山云": true, "UCloud": true, "360": true, "京东云": true, "Cloudflare": true, "Akamai": true, "AWS": true, "Google": true, "Microsoft": true, "Fastly": true}

var placeNames = map[string]string{"beijing": "北京", "shanghai": "上海", "tianjin": "天津", "chongqing": "重庆", "hebei": "河北", "shanxi": "山西", "liaoning": "辽宁", "jilin": "吉林", "heilongjiang": "黑龙江", "jiangsu": "江苏", "zhejiang": "浙江", "anhui": "安徽", "fujian": "福建", "jiangxi": "江西", "shandong": "山东", "henan": "河南", "hubei": "湖北", "hunan": "湖南", "guangdong": "广东", "hainan": "海南", "sichuan": "四川", "guizhou": "贵州", "yunnan": "云南", "shaanxi": "陕西", "gansu": "甘肃", "qinghai": "青海", "taiwan": "台湾", "guangxi": "广西", "neimenggu": "内蒙古", "inner mongolia": "内蒙古", "ningxia": "宁夏", "xinjiang": "新疆", "xizang": "西藏", "tibet": "西藏", "hong kong": "香港", "hongkong": "香港", "macau": "澳门", "macao": "澳门", "guangzhou": "广东", "shenzhen": "广东", "dongguan": "广东", "foshan": "广东", "hangzhou": "浙江", "ningbo": "浙江", "wenzhou": "浙江", "nanjing": "江苏", "suzhou": "江苏", "wuxi": "江苏", "jinan": "山东", "qingdao": "山东", "yantai": "山东", "zhengzhou": "河南", "wuhan": "湖北", "changsha": "湖南", "chengdu": "四川", "xian": "陕西", "xi'an": "陕西", "shenyang": "辽宁", "dalian": "辽宁", "changchun": "吉林", "harbin": "黑龙江", "hefei": "安徽", "fuzhou": "福建", "xiamen": "福建", "nanchang": "江西", "taiyuan": "山西", "shijiazhuang": "河北", "kunming": "云南", "guiyang": "贵州", "nanning": "广西", "lanzhou": "甘肃", "urumqi": "新疆", "hohhot": "内蒙古", "haikou": "海南"}

var postcodePrefix = map[string]string{"10": "北京", "30": "天津", "20": "上海", "40": "重庆", "05": "河北", "06": "河北", "07": "河北", "03": "山西", "04": "山西", "01": "内蒙古", "02": "内蒙古", "11": "辽宁", "12": "辽宁", "13": "吉林", "15": "黑龙江", "16": "黑龙江", "21": "江苏", "22": "江苏", "31": "浙江", "32": "浙江", "23": "安徽", "24": "安徽", "35": "福建", "36": "福建", "33": "江西", "34": "江西", "25": "山东", "26": "山东", "27": "山东", "45": "河南", "46": "河南", "43": "湖北", "44": "湖北", "41": "湖南", "42": "湖南", "51": "广东", "52": "广东", "53": "广西", "54": "广西", "57": "海南", "61": "四川", "62": "四川", "63": "四川", "64": "四川", "55": "贵州", "56": "贵州", "65": "云南", "66": "云南", "67": "云南", "85": "西藏", "86": "西藏", "71": "陕西", "72": "陕西", "73": "甘肃", "74": "甘肃", "81": "青海", "75": "宁夏", "83": "新疆", "84": "新疆"}

var orgNoise = regexp.MustCompile(`(?i)\s*\((?:US|HK|SG|JP|UK|CN)\)|\s*,?\s*(?:Co\.?\s*,?\s*Ltd\.?|Inc\.?|LLC|Limited|Corporation|Corp\.?|Company)\.?$`)
var addressHints = []string{"building", "avenue", "street", " road", "floor", "district", "tower", "no.", "block", "zone", "park"}

func MatchCarrier(text string) string {
	l := strings.ToLower(text)
	for _, p := range carrierPatterns {
		for _, k := range p.keys {
			if strings.Contains(l, k) {
				return p.name
			}
		}
	}
	return ""
}

func MatchPlace(text string) string {
	l := strings.ToLower(text)
	tokens := map[string]bool{}
	for _, t := range regexp.MustCompile(`[a-z']+`).FindAllString(l, -1) {
		tokens[t] = true
	}
	keys := make([]string, 0, len(placeNames))
	for k := range placeNames {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if strings.Contains(k, " ") {
			if strings.Contains(l, k) {
				return placeNames[k]
			}
		} else if tokens[k] {
			return placeNames[k]
		}
	}
	for _, m := range regexp.MustCompile(`\d{6}`).FindAllStringIndex(l, -1) {
		if (m[0] == 0 || l[m[0]-1] < '0' || l[m[0]-1] > '9') && (m[1] == len(l) || l[m[1]] < '0' || l[m[1]] > '9') {
			if p := postcodePrefix[l[m[0]:m[1]][:2]]; p != "" {
				return p
			}
		}
	}
	return ""
}

func cleanOrg(text string) string {
	if text == "" {
		return ""
	}
	l := strings.ToLower(text)
	for _, h := range addressHints {
		if strings.Contains(l, h) {
			return ""
		}
	}
	return strings.Trim(strings.TrimSpace(orgNoise.ReplaceAllString(text, "")), " ,.")
}

func shortenOwner(owner string) string {
	owner = strings.TrimSpace(owner)
	runes := []rune(owner)
	if len(runes) <= 16 {
		return owner
	}
	tails := []string{"有限公司", "股份公司", "公司", "大学", "学院", "研究院", "研究所", "集团", "中心", "网络", "科技"}
	for i := 2; i < len(runes) && i <= 20; i++ {
		for _, tail := range tails {
			if strings.HasPrefix(string(runes[i:]), tail) {
				return string(runes[:i+len([]rune(tail))])
			}
		}
	}
	return ""
}

func shortenOrg(text string) string {
	text = cleanOrg(text)
	if text == "" {
		return ""
	}
	parts := strings.Fields(text)
	for len(parts) > 0 {
		if _, ok := placeNames[strings.Trim(strings.ToLower(parts[0]), ",.")]; !ok {
			break
		}
		parts = parts[1:]
	}
	short := strings.Trim(strings.Join(parts, " "), " ,.")
	if short == "" {
		short = text
	}
	if len([]rune(short)) <= 28 {
		return short
	}
	return ""
}

func joinRegion(region, name string) string {
	if region == "" {
		return name
	}
	if isASCIIEnd(region) || (name != "" && isASCIIStart(name)) {
		return region + " " + name
	}
	return region + name
}

func isASCIIStart(s string) bool {
	if s == "" {
		return false
	}
	return s[0] < 128
}

func isASCIIEnd(s string) bool {
	if s == "" {
		return false
	}
	return s[len(s)-1] < 128
}

func composeLabel(m map[string]any, asOrg string) string {
	region, _ := m["region"].(string)
	carrier, _ := m["carrier"].(string)
	if region != "" && carrier != "" {
		return region + carrier
	}
	if carrier != "" {
		return carrier
	}
	if owner, _ := m["owner"].(string); owner != "" {
		if short := shortenOwner(owner); short != "" {
			return joinRegion(region, short)
		}
	}
	if short := shortenOrg(asOrg); short != "" {
		return joinRegion(region, short)
	}
	if region != "" {
		return region
	}
	if country, _ := m["country"].(string); country != "" {
		return country
	}
	return ""
}

func probeCNIP(ip string, reader any) map[string]any {
	r, ok := reader.(*IPDBReader)
	if !ok || r == nil {
		return nil
	}
	rec, err := r.Get(ip)
	if err != nil || len(rec) == 0 {
		return nil
	}
	isp, owner := rec["isp_domain"], rec["owner_domain"]
	carrier := MatchCarrier(isp)
	if carrier == "" {
		carrier = MatchCarrier(owner)
	}
	if carrier == "" && len([]rune(isp)) > 0 && len([]rune(isp)) <= 6 {
		carrier = isp
	}
	if owner == "" && carrier == "" {
		owner = isp
	}
	code := rec["country_code"]
	region := strings.NewReplacer("市", "", "省", "").Replace(rec["region_name"])
	if region == "" {
		region = map[string]string{"HK": "香港", "TW": "台湾", "MO": "澳门"}[code]
	}
	out := map[string]any{"country": rec["country_name"], "region": region, "city": rec["city_name"], "owner": owner, "carrier": carrier, "source": "qqwry", "country_code": code}
	out["label"] = composeLabel(out, owner)
	return out
}

func mapString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func probeMaxMind(ip string, asnReader, cityReader any) map[string]any {
	var asOrg string
	var asn any
	if r, ok := asnReader.(*MMDBReader); ok && r != nil {
		if rec, _ := r.Get(ip); rec != nil {
			asOrg = mapString(rec, "autonomous_system_organization")
			asn = rec["autonomous_system_number"]
		}
	}
	var region, country, city string
	if r, ok := cityReader.(*MMDBReader); ok && r != nil {
		if rec, _ := r.Get(ip); rec != nil {
			if x, ok := rec["country"].(map[string]any); ok {
				if n, ok := x["names"].(map[string]any); ok {
					country = mapString(n, "zh-CN")
					if country == "" {
						country = mapString(n, "en")
					}
				}
			}
			if subs, ok := rec["subdivisions"].([]any); ok && len(subs) > 0 {
				if s, ok := subs[0].(map[string]any); ok {
					if n, ok := s["names"].(map[string]any); ok {
						region = mapString(n, "zh-CN")
						if region == "" {
							region = mapString(n, "en")
						}
					}
				}
			}
			if c, ok := rec["city"].(map[string]any); ok {
				if n, ok := c["names"].(map[string]any); ok {
					city = mapString(n, "zh-CN")
					if city == "" {
						city = mapString(n, "en")
					}
				}
			}
		}
	}
	if asOrg == "" && country == "" {
		return nil
	}
	carrier := MatchCarrier(asOrg)
	if carrier == "" {
		if n, ok := intValue(asn); ok {
			carrier = asnCarriers[n]
		}
	}
	if region == "" {
		region = MatchPlace(asOrg)
	}
	region = strings.NewReplacer("市", "", "省", "").Replace(region)
	out := map[string]any{"asn": asn, "as_org": asOrg, "country": country, "city": city, "carrier": carrier, "region": region, "source": "maxmind"}
	out["label"] = composeLabel(out, asOrg)
	return out
}

func mergeRecords(cn, mm map[string]any) map[string]any {
	if cn == nil && mm == nil {
		return nil
	}
	if cn == nil {
		cn = map[string]any{}
	}
	if mm == nil {
		mm = map[string]any{}
	}
	pick := func(vs ...any) any {
		for _, v := range vs {
			switch x := v.(type) {
			case string:
				if x != "" {
					return x
				}
			case nil:
			default:
				return v
			}
		}
		return nil
	}
	mmCarrier := mapString(mm, "carrier")
	cloud := ""
	if cloudCarriers[mmCarrier] {
		cloud = mmCarrier
	}
	code := mapString(cn, "country_code")
	trusted := code == "CN" || code == "HK" || code == "TW" || code == "MO"
	cnRegion, cnCity := "", ""
	cnCarrier := ""
	if trusted {
		cnRegion, cnCity = mapString(cn, "region"), mapString(cn, "city")
		cnCarrier = mapString(cn, "carrier")
	}
	out := map[string]any{"region": pick(cnRegion, mm["region"], cnCity, mm["city"]), "city": pick(cnCity, mm["city"]), "carrier": pick(cloud, cnCarrier, mm["carrier"]), "country": pick(mm["country"], cn["country"]), "owner": cn["owner"], "asn": mm["asn"], "as_org": cleanOrg(mapString(mm, "as_org"))}
	sources := []string{}
	if len(cn) > 0 {
		sources = append(sources, "qqwry")
	}
	if len(mm) > 0 {
		sources = append(sources, "maxmind")
	}
	out["source"] = strings.Join(sources, "+")
	out["is_cloud"] = cloudCarriers[mapString(out, "carrier")]
	out["label"] = composeLabel(out, mapString(out, "as_org"))
	country := mapString(out, "country")
	label := mapString(out, "label")
	domestic := trusted || map[string]bool{"中国": true, "China": true, "香港": true, "Hong Kong": true, "台湾": true, "Taiwan": true, "澳门": true, "Macao": true, "Macau": true}[country]
	if country != "" && label != "" && !domestic && !strings.Contains(label, country) && label != country {
		out["label"] = country + "·" + label
	}
	return out
}

func resultFromMap(ip string, m map[string]any, available bool) Result {
	r := Result{IP: ip, Available: available, ASN: m["asn"], ASOrg: mapString(m, "as_org"), Carrier: mapString(m, "carrier"), Region: mapString(m, "region"), Country: mapString(m, "country"), City: mapString(m, "city"), Owner: mapString(m, "owner"), Source: mapString(m, "source"), Label: mapString(m, "label")}
	r.IsCloud, _ = m["is_cloud"].(bool)
	return r
}

func MergeRecords(cn, mm map[string]any) Result {
	m := mergeRecords(cn, mm)
	if m == nil {
		return Result{}
	}
	return resultFromMap("", m, true)
}
