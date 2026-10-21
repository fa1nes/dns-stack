package pipeline

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"github.com/dns-stack/dns-stack/internal/ecszone"
	"github.com/dns-stack/dns-stack/internal/metrics"

	_ "modernc.org/sqlite"
)

func stepECSFanout(ctx context.Context, rt *Runtime) error {
	cfg := rt.Config
	days := int(cfg.Duration("ECS_FANOUT_WINDOW_SEC", 7*24*time.Hour) / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	minQueries := int(cfg.Float("ECS_FANOUT_MIN_QUERIES", 200))
	maxZones := int(cfg.Float("ECS_FANOUT_MAX_ZONES", 4))

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(cfg.Path("collector.db"))+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	rows, err := db.QueryContext(ctx, `SELECT ecs_zone, client_subnet, COUNT(*) FROM query_events
		WHERE ts >= ? AND prefetch = 0 AND COALESCE(ecs_zone,'') != '' AND COALESCE(client_subnet,'') != ''
		GROUP BY 1, 2`, since)
	if err != nil {
		return err
	}
	byZone := map[string]*ecszone.ZoneTraffic{}
	for rows.Next() {
		var zone, subnet string
		var n int
		if err := rows.Scan(&zone, &subnet, &n); err != nil {
			rows.Close()
			return err
		}
		ecszone.AddTraffic(byZone, zone, subnet, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	picked := ecszone.PickFanout(byZone, minQueries, maxZones)
	for _, t := range picked {
		rt.Infof("并发分片 %s（%d 次查询，代表子网 %s）", t.Zone, t.Queries, t.Subnet)
	}
	if picked == nil {
		rt.Infof("最近 %d 天只有不到两个分片达到 %d 次查询，没有可并发的运营商", days, minQueries)
	}
	out := cfg.Path("ecs-fanout.txt")
	content := []byte(ecszone.RenderFanout(picked, days))
	if previous, err := os.ReadFile(out); err == nil && bytes.Equal(previous, content) {
		return nil
	}
	if rt.Preview {
		rt.Infof("预览：并发清单有变化，未落盘 %s", out)
		return nil
	}
	message, err := metrics.ReplaceAndReload(out, content, "并发清单", func() int { return metrics.Reload(ctx) })
	if err != nil {
		return err
	}
	rt.Infof("%s", message)
	return nil
}
