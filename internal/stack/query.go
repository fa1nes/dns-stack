package stack

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
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
	if _, err := exec.LookPath("systemctl"); err != nil {
		return openRCStatus(unit)
	}
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

func openRCStatus(unit string) Status {
	module, ok := Lookup(unit)
	if !ok {
		return Status{Unreachable: true}
	}
	if module.Kind == KindJob {
		logPath := filepath.Join("/var/log/dns-stack", module.LogFile)
		var lastRun int64
		if module.LogFile != "" {
			if info, err := os.Stat(logPath); err == nil {
				lastRun = info.ModTime().Unix()
			}
		}
		body, err := os.ReadFile("/etc/crontabs/root")
		scheduled := err == nil && activeCronContains(string(body), module.Cron)
		return cronJobStatus(lastRun, scheduled)
	}
	service := module.OpenRC
	if service == "" {
		service = unit
	}
	output, err := exec.Command("rc-service", service, "status").CombinedOutput()
	if err != nil && len(output) == 0 {
		return Status{Unreachable: true}
	}
	return parseOpenRCServiceStatus(string(output))
}

func activeCronContains(body, needle string) bool {
	if needle == "" {
		return false
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func parseOpenRCServiceStatus(output string) Status {
	text := strings.ToLower(output)
	switch {
	case strings.Contains(text, "started") || strings.Contains(text, "status: started"):
		return Status{Active: "active"}
	case strings.Contains(text, "crashed") || strings.Contains(text, "stopped"):
		return Status{Active: "failed"}
	default:
		return Status{Unreachable: true}
	}
}

func cronJobStatus(lastRun int64, scheduled bool) Status {
	status := Status{Active: "waiting", LastRun: lastRun, LastResult: "success"}
	if scheduled {
		status.TimerActive = "active"
	} else {
		status.TimerActive = "inactive"
	}
	return status
}
