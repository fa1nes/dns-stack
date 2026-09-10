package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/dns-stack/dns-stack/internal/geoip"
)

var geoipExpectedType = map[string]string{
	"asn":  "GeoLite2-ASN",
	"city": "GeoLite2-City",
}

func geoipProbes(kind string) []string {
	if kind == "cnip" {
		return []string{"114.114.114.114", "223.5.5.5"}
	}
	return []string{"1.1.1.1", "8.8.8.8"}
}

func verifyIPDB(path, kind string) error {
	reader, err := geoip.OpenIPDB(path)
	if err != nil {
		return fmt.Errorf("无法解析：%w", err)
	}
	defer reader.Close()
	var missing []string
	for _, ip := range geoipProbes(kind) {
		record, err := reader.Get(ip)
		if err != nil || len(record) == 0 {
			missing = append(missing, ip)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("抽查地址查不到记录：%v，树可能被截断", missing)
	}
	fmt.Printf("[信息] 校验通过：%s build=%d nodes=%d\n", kind, reader.BuildEpoch, reader.NodeCount())
	return nil
}

func verifyMMDB(path, kind string) error {
	reader, err := geoip.OpenMMDB(path)
	if err != nil {
		return fmt.Errorf("无法解析：%w", err)
	}
	defer reader.Close()

	if expected := geoipExpectedType[kind]; expected != "" {
		if actual := reader.DatabaseType(); actual != expected {
			return fmt.Errorf("库类型是 %s，期望 %s", actual, expected)
		}
	}

	records := map[string]map[string]any{}
	var missing []string
	for _, ip := range geoipProbes(kind) {
		record, err := reader.Get(ip)
		if err != nil || record == nil {
			missing = append(missing, ip)
			continue
		}
		records[ip] = record
	}
	if len(missing) > 0 {
		return fmt.Errorf("抽查地址查不到记录：%v，树可能被截断", missing)
	}

	switch kind {
	case "city", "dbip_city", "ipinfo":
		cn, err := reader.Get("114.114.114.114")
		if err != nil {
			return fmt.Errorf("抽查 114.114.114.114 失败：%w", err)
		}
		us, err := reader.Get("8.8.8.8")
		if err != nil {
			return fmt.Errorf("抽查 8.8.8.8 失败：%w", err)
		}
		cnCode := strings.ToUpper(geoip.CountryCodeOf(cn))
		usCode := strings.ToUpper(geoip.CountryCodeOf(us))
		if cnCode != "CN" {
			return fmt.Errorf("114.114.114.114 的国家码是 %q，期望 CN", cnCode)
		}
		if usCode == "" || usCode == "CN" {
			return fmt.Errorf("8.8.8.8 的国家码是 %q，境外地址被判成大陆", usCode)
		}
		fmt.Printf("[信息] 国家码抽查通过：114.114.114.114=%s 8.8.8.8=%s\n", cnCode, usCode)
	case "dbip_asn", "asn":
		record := records["8.8.8.8"]
		if _, ok := geoip.ASNumber(record["autonomous_system_number"]); !ok {
			if _, ok := geoip.ASNumber(record["asn"]); !ok {
				return fmt.Errorf("8.8.8.8 查不到 ASN，这不是一个 ASN 库")
			}
		}
	}

	fmt.Printf("[信息] 校验通过：%s build=%d nodes=%d\n", kind, reader.BuildEpoch, reader.NodeCount())
	return nil
}

func cmdGeoIPVerify(args []string) error {
	fs := flag.NewFlagSet("geoip-verify", flag.ContinueOnError)
	kind := fs.String("kind", "", "库类型: asn|city|cnip|dbip_asn|dbip_city|ipinfo")
	file := fs.String("file", "", "库文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" || *file == "" {
		return fmt.Errorf("必须指定 --kind 与 --file")
	}
	if *kind == "cnip" {
		return verifyIPDB(*file, *kind)
	}
	return verifyMMDB(*file, *kind)
}
