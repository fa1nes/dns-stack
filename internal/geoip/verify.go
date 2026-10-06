package geoip

import (
	"fmt"
	"strings"
)

var expectedType = map[string]string{
	"asn":  "GeoLite2-ASN",
	"city": "GeoLite2-City",
}

func probesFor(kind string) []string {
	switch kind {
	case "cnip":
		return []string{"114.114.114.114", "223.5.5.5"}
	case "city", "dbip_city":
		return []string{"1.1.1.1", "8.8.8.8", "114.114.114.114"}
	}
	return []string{"1.1.1.1", "8.8.8.8"}
}

func Verify(kind, path string) (string, error) {
	if kind == "cnip" {
		return verifyIPDB(kind, path)
	}
	return verifyMMDB(kind, path)
}

func VerifyFile(kind, path string) error {
	_, err := Verify(kind, path)
	return err
}

func verifyIPDB(kind, path string) (string, error) {
	reader, err := OpenIPDB(path)
	if err != nil {
		return "", fmt.Errorf("无法解析：%w", err)
	}
	defer reader.Close()
	var missing []string
	for _, ip := range probesFor(kind) {
		record, err := reader.Get(ip)
		if err != nil || len(record) == 0 {
			missing = append(missing, ip)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("抽查地址查不到记录：%v，树可能被截断", missing)
	}
	return fmt.Sprintf("%s build=%d nodes=%d", kind, reader.BuildEpoch, reader.NodeCount()), nil
}

func verifyMMDB(kind, path string) (string, error) {
	reader, err := OpenMMDB(path)
	if err != nil {
		return "", fmt.Errorf("无法解析：%w", err)
	}
	defer reader.Close()

	if want := expectedType[kind]; want != "" {
		if actual := reader.DatabaseType(); actual != want {
			return "", fmt.Errorf("库类型是 %s，期望 %s", actual, want)
		}
	}

	records := map[string]map[string]any{}
	var missing []string
	for _, ip := range probesFor(kind) {
		record, err := reader.Get(ip)
		if err != nil || record == nil {
			missing = append(missing, ip)
			continue
		}
		records[ip] = record
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("抽查地址查不到记录：%v，树可能被截断", missing)
	}

	detail := fmt.Sprintf("%s build=%d nodes=%d", kind, reader.BuildEpoch, reader.NodeCount())
	switch kind {
	case "city", "dbip_city":
		cnCode := strings.ToUpper(CountryCodeOf(records["114.114.114.114"]))
		usCode := strings.ToUpper(CountryCodeOf(records["8.8.8.8"]))
		if cnCode != "CN" {
			return "", fmt.Errorf("114.114.114.114 的国家码是 %q，期望 CN", cnCode)
		}
		if usCode == "" || usCode == "CN" {
			return "", fmt.Errorf("8.8.8.8 的国家码是 %q，境外地址被判成大陆", usCode)
		}
		detail += fmt.Sprintf(" 114.114.114.114=%s 8.8.8.8=%s", cnCode, usCode)
	case "dbip_asn", "asn":
		record := records["8.8.8.8"]
		if _, ok := ASNumber(record["autonomous_system_number"]); !ok {
			if _, ok := ASNumber(record["asn"]); !ok {
				return "", fmt.Errorf("8.8.8.8 查不到 ASN，这不是一个 ASN 库")
			}
		}
	}
	return detail, nil
}
