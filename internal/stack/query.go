package stack

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

func parseNumber(value string) int64 {
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || number < 0 {
		return 0
	}
	return number
}

func UnitStatus(unit string) Status {
	cmd := exec.Command("systemctl", "show", unit+".service", unit+".timer",
		"--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,"+
			"ExecMainStartTimestamp,ExecMainStartTimestampMonotonic,MemoryCurrent,NRestarts,"+
			"NextElapseUSecRealtime,LastTriggerUSec", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return Status{Unreachable: true}
	}

	service, timer := map[string]string{}, map[string]string{}
	current := map[string]string{}
	var blocks []map[string]string
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
		if key, value, found := strings.Cut(line, "="); found {
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

	status := Status{
		Active:     service["ActiveState"],
		LastResult: service["Result"],
		Memory:     parseNumber(service["MemoryCurrent"]),
		Restarts:   int(parseNumber(service["NRestarts"])),
	}
	if timer["LoadState"] == "loaded" {
		status.TimerActive = timer["ActiveState"]
		status.LastRun = TimerStamp(timer["LastTriggerUSec"])
		status.NextRun = TimerStamp(timer["NextElapseUSecRealtime"])
		if status.Active == "inactive" && status.TimerActive == "active" {
			status.Active = "waiting"
			if code := service["ExecMainStatus"]; code != "" && code != "0" {
				status.Active = "failed"
			}
		}
	}
	if status.LastRun == 0 {
		status.LastRun = ServiceStamp(service["ExecMainStartTimestamp"])
	}
	return status
}
