package pipeline

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeUnits struct {
	failed  map[string]bool
	dies    map[string]bool
	started []string
}

func (f *fakeUnits) systemctl(_ context.Context, args ...string) error {
	unit := args[len(args)-1]
	switch args[0] {
	case "is-failed":
		if f.failed[unit] {
			return nil
		}
		return errors.New("not failed")
	case "start":
		f.started = append(f.started, unit)
		f.failed[unit] = f.dies[unit]
	case "is-active":
		if f.failed[unit] {
			return errors.New("inactive")
		}
	}
	return nil
}

func TestReviverRestartsOnlyUnitsSystemdGaveUpOn(t *testing.T) {
	units := &fakeUnits{
		failed: map[string]bool{"mosproxy.service": true, "wg-quick@wg0.service": true},
		dies:   map[string]bool{"wg-quick@wg0.service": true},
	}
	var out bytes.Buffer
	rt := NewRuntime(Config{}, &out)
	problems := Reviver{Systemctl: units.systemctl}.Revive(context.Background(), rt, ReviveUnits)
	if strings.Join(units.started, ",") != "mosproxy.service,wg-quick@wg0.service" {
		t.Fatalf("只该拉起 failed 的单元，实际拉起 %q——正常运行或被人手工 stop 的单元不能碰", units.started)
	}
	if len(problems) != 2 {
		t.Fatalf("拉起成功和拉起后又退出都要告警，实际 %q", problems)
	}
	if !strings.Contains(problems[0], "已重新拉起") || !strings.Contains(problems[1], "又退出") {
		t.Fatalf("告警文案没分清成功与失败: %q", problems)
	}
}
