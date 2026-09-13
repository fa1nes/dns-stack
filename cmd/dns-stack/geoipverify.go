package main

import (
	"flag"
	"fmt"

	"github.com/dns-stack/dns-stack/internal/geoip"
)

func cmdGeoIPVerify(args []string) error {
	fs := flag.NewFlagSet("geoip-verify", flag.ContinueOnError)
	kind := fs.String("kind", "", "库类型: asn|city|cnip|dbip_asn|dbip_city")
	file := fs.String("file", "", "库文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" || *file == "" {
		return fmt.Errorf("必须指定 --kind 与 --file")
	}
	detail, err := geoip.Verify(*kind, *file)
	if err != nil {
		return err
	}
	fmt.Printf("[信息] 校验通过：%s\n", detail)
	return nil
}
