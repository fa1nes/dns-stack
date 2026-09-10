package geoip

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const ipSBEndpoint = "https://api.ip.sb/geoip/"

type ipSBRecord struct {
	Country      string `json:"country"`
	CountryCode  string `json:"country_code"`
	Region       string `json:"region"`
	City         string `json:"city"`
	ASN          int    `json:"asn"`
	ASNOrg       string `json:"asn_organization"`
	Organization string `json:"organization"`
	ISP          string `json:"isp"`
}

type onlineCacheEntry struct {
	rec map[string]any
	exp time.Time
}

type OnlineLookup struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]onlineCacheEntry
	ttl    time.Duration
	sem    chan struct{}
}

func NewOnlineLookup() *OnlineLookup {
	return &OnlineLookup{
		client: &http.Client{Timeout: 4 * time.Second},
		cache:  map[string]onlineCacheEntry{},
		ttl:    10 * time.Minute,
		sem:    make(chan struct{}, 4),
	}
}

func (o *OnlineLookup) cached(ip string) (map[string]any, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entry, ok := o.cache[ip]
	if !ok || time.Now().After(entry.exp) {
		return nil, false
	}
	return entry.rec, true
}

func (o *OnlineLookup) store(ip string, rec map[string]any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.cache) > 4096 {
		o.cache = map[string]onlineCacheEntry{}
	}
	o.cache[ip] = onlineCacheEntry{rec: rec, exp: time.Now().Add(o.ttl)}
}

func (o *OnlineLookup) Lookup(ctx context.Context, ip string) map[string]any {
	if rec, ok := o.cached(ip); ok {
		return rec
	}
	select {
	case o.sem <- struct{}{}:
		defer func() { <-o.sem }()
	case <-ctx.Done():
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipSBEndpoint+ip, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "dns-stack panel geoip lookup")
	resp, err := o.client.Do(req)
	if err != nil {
		o.store(ip, nil)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		o.store(ip, nil)
		return nil
	}
	var raw ipSBRecord
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		o.store(ip, nil)
		return nil
	}
	rec := map[string]any{}
	if raw.Country != "" {
		rec["country"] = raw.Country
	}
	if raw.Region != "" {
		rec["region"] = raw.Region
	}
	if raw.City != "" {
		rec["city"] = raw.City
	}
	if raw.ASN > 0 {
		rec["asn"] = json.Number(strconv.Itoa(raw.ASN))
	}
	org := raw.ASNOrg
	if org == "" {
		org = raw.Organization
	}
	if org == "" {
		org = raw.ISP
	}
	if org != "" {
		rec["as_org"] = org
	}
	rec["source"] = "ipsb"
	rec["country_code"] = raw.CountryCode
	rec["label"] = composeLabel(rec, org)
	o.store(ip, rec)
	return rec
}
