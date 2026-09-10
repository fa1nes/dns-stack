package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cnauth"
	"github.com/dns-stack/dns-stack/internal/geoip"
)

type geoCountry struct{ db *geoip.GeoDB }

func (g geoCountry) CountryOf(addr netip.Addr) (code, label string, available bool) {
	for _, src := range g.db.Sources(addr.String()) {
		if !src.Available {
			continue
		}
		available = true
		if src.Record == nil {
			continue
		}
		text := func(key string) string {
			value, _ := src.Record[key].(string)
			return strings.TrimSpace(value)
		}
		label = strings.TrimSpace(strings.Join(nonEmpty(text("label"), text("as_org"), text("owner")), " "))
		if value := text("country_code"); value != "" {
			return strings.ToUpper(value), label, true
		}
		switch country := text("country"); country {
		case "":
		case "中国", "China":
			return "CN", label, true
		default:
			return country, label, true
		}
	}
	return "", label, available
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func cmdECSOrphans(args []string) error {
	fs := flag.NewFlagSet("ecs-orphans", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", "/var/lib/dns-stack"), "状态目录")
	ecsConf := fs.String("ecs-conf", envOr("ECS_CONF",
		"/etc/unbound/unbound.conf.d/dns-stack-ecs.conf"), "Unbound ECS 白名单配置")
	maxForeign := fs.Int("max-foreign", cnauth.DefaultMaxForeignOrphans, "境外孤儿数量阈值")
	listAll := fs.Bool("list", false, "列出全部孤儿而不只是境外的")
	asJSON := fs.Bool("json", false, "输出 JSON")
	ttl := fs.Duration("accum-ttl", cnauth.DefaultAccumTTL, "累积保留的有效期")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if seconds := os.Getenv("ECS_ACCUM_TTL_SEC"); seconds != "" && !flagPassed(fs, "accum-ttl") {
		var value int
		if _, err := fmt.Sscan(seconds, &value); err == nil && value > 0 {
			*ttl = time.Duration(value) * time.Second
		}
	}

	chnroute := filepath.Join(*state, "chnroute")
	geo := geoip.NewGeoDB(
		filepath.Join(*state, "geoip", "GeoLite2-ASN.mmdb"),
		filepath.Join(*state, "geoip", "GeoLite2-City.mmdb"),
		filepath.Join(*state, "geoip", "qqwry.ipdb"))

	report, err := cnauth.AuditOrphans(cnauth.OrphanOptions{
		ECSConfPath:        *ecsConf,
		Direct4Path:        filepath.Join(chnroute, "direct4.txt"),
		CNAuthorityPath:    filepath.Join(chnroute, "cn-authority.txt"),
		SharedExcludedPath: filepath.Join(chnroute, "shared-excluded.txt"),
		AccumStatePath:     filepath.Join(chnroute, "ecs-accum-state.tsv"),
		AccumTTL:           *ttl,
		MaxForeign:         *maxForeign,
		Geo:                geoCountry{geo},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeCompactJSON(report); err != nil {
			return err
		}
	} else {
		report.Write(os.Stdout, *listAll)
	}
	if !report.OK {
		os.Exit(1)
	}
	return nil
}

func flagPassed(fs *flag.FlagSet, name string) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}
