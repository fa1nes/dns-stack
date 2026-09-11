package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/stack"
)

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	role := fs.String("role", "", "角色，留空则读 config.env 的 ROLE")
	configPath := fs.String("config", "/etc/dns-stack/config.env", "配置文件路径")
	asJSON := fs.Bool("json", false, "输出 JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role == "" {
		*role = config.ReadKeys(*configPath, "ROLE")["ROLE"]
	}

	now := time.Now()
	modules := stack.ForRole(*role)
	type row struct {
		Module stack.Module
		Status stack.Status
		State  string
		Note   string
	}
	rows := make([]row, 0, len(modules))
	counts := map[string]int{}
	overall := stack.StateOK
	troubled := 0
	nameWidth, noteWidth := 0, 0
	for _, m := range modules {
		status := unitStatus(m.Unit)
		state, note := stack.Evaluate(m, status, now)
		counts[state]++
		switch state {
		case stack.StateUnknown:
			overall = stack.Worse(overall, stack.StateUnknown)
		case stack.StateWarn, stack.StateDown:
			troubled++
			overall = stack.Worse(overall, stack.StateWarn)
		}
		if state == stack.StateDown && m.Critical {
			overall = stack.StateDown
		}
		nameWidth = max(nameWidth, stack.DisplayWidth(m.Name))
		noteWidth = max(noteWidth, stack.DisplayWidth(note))
		rows = append(rows, row{m, status, state, note})
	}

	if *asJSON {
		items := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			items = append(items, map[string]any{
				"unit": r.Module.Unit, "name": r.Module.Name, "group": r.Module.Group,
				"impl": string(r.Module.Impl), "kind": string(r.Module.Kind),
				"state": r.State, "note": r.Note, "last_run": r.Status.LastRun,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"role": *role, "verdict": overall, "headline": stack.Headline(overall, troubled),
			"counts": counts, "modules": items,
		})
	}

	fmt.Printf("%s  角色 %s，共 %d 个模块（正常 %d / 关注 %d / 中断 %d / 未知 %d）\n",
		stack.Headline(overall, troubled), *role, len(rows),
		counts[stack.StateOK], counts[stack.StateWarn],
		counts[stack.StateDown], counts[stack.StateUnknown])

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	group := ""
	for _, r := range rows {
		if r.Module.Group != group {
			group = r.Module.Group
			fmt.Fprintf(out, "\n[%s]\n", group)
		}
		fmt.Fprintf(out, "  %s  %s  %s  %s\n", stateMark(r.State),
			stack.Pad(r.Module.Name, nameWidth),
			stack.Pad(r.Note, noteWidth), r.Module.Unit)
	}
	if overall == stack.StateDown {
		out.Flush()
		os.Exit(1)
	}
	return nil
}

func stateMark(state string) string {
	switch state {
	case stack.StateOK:
		return "OK  "
	case stack.StateWarn:
		return "WARN"
	case stack.StateDown:
		return "DOWN"
	}
	return "??  "
}

func unitStatus(unit string) stack.Status {
	cmd := exec.Command("systemctl", "show", unit+".service", unit+".timer",
		"--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,"+
			"ExecMainStartTimestampMonotonic,MemoryCurrent,NRestarts,"+
			"NextElapseUSecRealtime,LastTriggerUSec", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return stack.Status{Unreachable: true}
	}

	service, timer := map[string]string{}, map[string]string{}
	current := map[string]string{}
	blocks := []map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(output)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if len(current) > 0 {
				blocks = append(blocks, current)
				current = map[string]string{}
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found {
			current[key] = value
		}
	}
	if len(current) > 0 {
		blocks = append(blocks, current)
	}
	for _, block := range blocks {
		if block["Id"] == unit+".service" && len(service) == 0 {
			service = block
		}
		if block["Id"] == unit+".timer" && len(timer) == 0 {
			timer = block
		}
	}

	status := stack.Status{
		Active:     service["ActiveState"],
		LastResult: service["Result"],
		Memory:     parseNumber(service["MemoryCurrent"]),
		Restarts:   int(parseNumber(service["NRestarts"])),
	}
	if timer["LoadState"] == "loaded" {
		status.TimerActive = timer["ActiveState"]
		status.LastRun = parseNumber(timer["LastTriggerUSec"]) / 1e6
		status.NextRun = parseNumber(timer["NextElapseUSecRealtime"]) / 1e6
		if status.Active == "inactive" && status.TimerActive == "active" {
			status.Active = "waiting"
			if code := service["ExecMainStatus"]; code != "" && code != "0" {
				status.Active = "failed"
			}
		}
	}
	return status
}

func parseNumber(value string) int64 {
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || number < 0 {
		return 0
	}
	return number
}
