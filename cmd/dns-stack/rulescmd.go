package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dns-stack/dns-stack/internal/rulesync"
)

func cmdRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: dns-stack rules <check-domains|clean-cidr|check-disjoint|merge-polluted|check-overlap|json-field> [参数]")
	}
	sub, rest := args[0], args[1:]
	need := func(n int, usage string) error {
		if len(rest) < n {
			return fmt.Errorf("用法: dns-stack rules %s %s", sub, usage)
		}
		return nil
	}
	switch sub {
	case "check-domains":
		if err := need(1, "<域名文件>"); err != nil {
			return err
		}
		return rulesync.CheckDomains(rest[0])
	case "clean-cidr":
		if err := need(2, "<输入> <输出>"); err != nil {
			return err
		}
		return rulesync.CleanCIDRFile(rest[0], rest[1])
	case "check-disjoint":
		if err := need(2, "<cn-cidr> <polluted-cidr>"); err != nil {
			return err
		}
		return rulesync.CheckDisjoint(rest[0], rest[1])
	case "merge-polluted":
		if err := need(4, "<远端CIDR> <本地IP> <本地CIDR> <输出>"); err != nil {
			return err
		}
		return rulesync.MergePolluted(rest[0], rest[1], rest[2], rest[3])
	case "check-overlap":
		if err := need(2, "<cn.txt> <gfw.txt>"); err != nil {
			return err
		}
		return rulesync.CheckRuleOverlap(rest[0], rest[1])
	case "json-field":
		if err := need(1, "<字段名>  # JSON 从 stdin 读"); err != nil {
			return err
		}
		var payload map[string]any
		if err := json.NewDecoder(os.Stdin).Decode(&payload); err != nil {
			fmt.Println("")
			return nil
		}
		if value, ok := payload[rest[0]].(string); ok {
			fmt.Println(value)
			return nil
		}
		fmt.Println("")
		return nil
	default:
		return fmt.Errorf("未知子命令: rules %s", sub)
	}
}
