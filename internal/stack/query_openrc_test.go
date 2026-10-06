package stack

import (
	"testing"
	"time"
)

func TestOpenRCServiceStatusParsesStartedAndCrashed(t *testing.T) {
	started := parseOpenRCServiceStatus(" * status: started\n")
	if started.Unreachable || started.Active != "active" {
		t.Fatalf("started service = %+v, want active and reachable", started)
	}

	crashed := parseOpenRCServiceStatus(" * status: crashed\n")
	if crashed.Unreachable || crashed.Active != "failed" {
		t.Fatalf("crashed service = %+v, want failed and reachable", crashed)
	}
}

func TestCronJobStatusUsesFreshLogAsLastRun(t *testing.T) {
	now := time.Date(2026, 9, 14, 13, 54, 0, 0, time.UTC)
	status := cronJobStatus(now.Add(-10*time.Minute).Unix(), true)
	if status.Unreachable {
		t.Fatalf("cron-backed job should be reachable: %+v", status)
	}
	if status.Active != "waiting" || status.TimerActive != "active" {
		t.Fatalf("cron-backed job = %+v, want waiting with active scheduler", status)
	}
	if status.LastRun != now.Add(-10*time.Minute).Unix() {
		t.Fatalf("last run = %d, want log timestamp", status.LastRun)
	}
}

func TestCronJobStatusReportsMissingSchedule(t *testing.T) {
	status := cronJobStatus(0, false)
	if status.Unreachable {
		t.Fatalf("missing cron entry is a known unhealthy state, not unreachable: %+v", status)
	}
	if status.TimerActive != "inactive" {
		t.Fatalf("timer state = %q, want inactive", status.TimerActive)
	}
}

func TestActiveCronContainsIgnoresCommentedJobs(t *testing.T) {
	body := "0 3 * * * dns-stack trim-logs\n# 7 */6 * * * dns-stack removed-command\n"
	if !activeCronContains(body, "dns-stack trim-logs") {
		t.Fatal("active pipeline cron entry was not found")
	}
	if activeCronContains(body, "dns-stack removed-command") {
		t.Fatal("commented publish entry must not count as scheduled")
	}
}

func TestOffshoreDoesNotClaimCNOnlyPanelServices(t *testing.T) {
	for _, module := range ForRole(RoleOffshore) {
		switch module.Unit {
		case "dns-stack-panel", "dns-stack-helper", "dns-stack-maintenance":
			t.Fatalf("offshore role must not claim CN-only module %s", module.Unit)
		}
	}
}
