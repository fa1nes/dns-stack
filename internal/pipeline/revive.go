package pipeline

import (
	"context"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

var ReviveUnits = []string{"mosproxy", "unbound", "wg-quick@" + stack.TunnelIf}

type Reviver struct {
	Systemctl func(ctx context.Context, args ...string) error
	Settle    time.Duration
}

func NewReviver() Reviver {
	return Reviver{Systemctl: systemctl, Settle: 3 * time.Second}
}

func unitLabel(unit string) string {
	if module, ok := stack.Lookup(unit); ok {
		return module.Name + "（" + unit + "）"
	}
	return unit
}

func (r Reviver) Revive(ctx context.Context, rt *Runtime, units []string) []string {
	var problems []string
	for _, unit := range units {
		service := unit + ".service"
		if r.Systemctl(ctx, "is-failed", "--quiet", service) != nil {
			continue
		}
		label := unitLabel(unit)
		rt.Warnf("%s 处于 failed 状态（systemd 已放弃自动重启），尝试重新拉起", label)
		_ = r.Systemctl(ctx, "reset-failed", service)
		if err := r.Systemctl(ctx, "start", service); err != nil {
			problems = append(problems, label+" 已停止，看门狗重新拉起失败——journalctl -u "+service+" -n 50")
			continue
		}
		if r.Settle > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(r.Settle):
			}
		}
		if r.Systemctl(ctx, "is-active", "--quiet", service) != nil {
			problems = append(problems, label+" 已停止，看门狗拉起后又退出——journalctl -u "+service+" -n 50")
			continue
		}
		rt.Infof("%s 已重新拉起", label)
		problems = append(problems, label+" 曾停止（systemd 放弃了自动重启），看门狗已重新拉起，请查明原因")
	}
	return problems
}
