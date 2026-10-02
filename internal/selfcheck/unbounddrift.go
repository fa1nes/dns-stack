package selfcheck

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/stack"
	"github.com/dns-stack/dns-stack/unbound"
)

var unboundOption = func(ctx context.Context, key string) (string, error) {
	out, err := shellOut(ctx, "unbound-control", "-c", "/etc/unbound/unbound.conf", "get_option", key)
	return strings.TrimSpace(out), err
}

type unboundSetting struct{ key, value string }

func templateSettings(body string) []unboundSetting {
	multiValued := map[string]bool{"interface": true, "access-control": true}
	index := map[string]int{}
	var out []unboundSetting
	section := ""
	for _, raw := range strings.Split(body, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "{{") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok || section != "server" || multiValued[key] {
			continue
		}
		setting := unboundSetting{key: key, value: strings.Trim(strings.TrimSpace(value), `"`)}
		if at, seen := index[key]; seen {
			out[at] = setting
			continue
		}
		index[key] = len(out)
		out = append(out, setting)
	}
	return out
}

func unboundMemSize(value string) string {
	units := map[string]int64{"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
	if len(value) < 2 {
		return value
	}
	unit, ok := units[strings.ToLower(value[len(value)-1:])]
	if !ok {
		return value
	}
	number, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
	if err != nil {
		return value
	}
	return strconv.FormatInt(number*unit, 10)
}

func checkUnboundDrift(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "解析链路"}
	const name = "Unbound 运行配置与模板一致"
	var drift []string
	matched, unreadable := 0, 0
	for _, setting := range templateSettings(unbound.Template) {
		if unbound.PanelTunable[setting.key] {
			continue
		}
		running, err := unboundOption(ctx, setting.key)
		if err != nil || running == "" || strings.HasPrefix(running, "error") {
			unreadable++
			continue
		}
		if running == unboundMemSize(setting.value) {
			matched++
			continue
		}
		drift = append(drift, fmt.Sprintf("%s 运行中是 %s、模板是 %s", setting.key, running, setting.value))
	}
	switch {
	case len(drift) > 0:
		c.fail(name, "%s——照 unbound/unbound.template.conf 改 /etc/unbound/unbound.conf.d/dns-stack.conf，"+
			"再 unbound-control reload_keep_cache", strings.Join(drift, "；"))
	case matched == 0:
		c.skip(name, "unbound-control 一项都读不到")
	case unreadable > 0:
		c.ok(name, "%d 项一致，%d 项这一版 unbound-control 读不到", matched, unreadable)
	default:
		c.ok(name, "%d 项一致", matched)
	}
}
