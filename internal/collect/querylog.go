package collect

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/geoip"
)

const (
	DefaultLogLimit = 200
	MaxLogExport    = 100000
)

type LogFilter struct {
	Since        time.Time
	Until        time.Time
	Kind         string
	Domain       string
	ClientSubnet string
	ExitPath     string
	Limit        int
}

type LogRow struct {
	TS           int64   `json:"ts"`
	Domain       string  `json:"domain"`
	QType        string  `json:"qtype"`
	RCode        int64   `json:"rcode"`
	Kind         string  `json:"kind"`
	KindLabel    string  `json:"kind_label"`
	ClientSubnet string  `json:"client_subnet,omitempty"`
	ECSZone      string  `json:"ecs_zone,omitempty"`
	RespBy       string  `json:"resp_by,omitempty"`
	ExitPath     string  `json:"exit_path,omitempty"`
	ServerTag    string  `json:"server_tag,omitempty"`
	Prefetch     bool    `json:"prefetch,omitempty"`
	ElapsedMS    float64 `json:"elapsed_ms,omitempty"`
	SubnetRegion string  `json:"subnet_region,omitempty"`
	CDNProvider  string  `json:"cdn_provider,omitempty"`
}

func (f LogFilter) build() (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, f.Until.Unix())
	}
	if f.Kind != "" {
		where = append(where, "COALESCE(kind,'') = ?")
		args = append(args, f.Kind)
	}
	if f.Domain != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(f.Domain)+"%")
	}
	if f.ClientSubnet != "" {
		where = append(where, "COALESCE(client_subnet,'') LIKE ?")
		args = append(args, "%"+f.ClientSubnet+"%")
	}
	if f.ExitPath != "" {
		where = append(where, "COALESCE(exit_path,'') = ?")
		args = append(args, f.ExitPath)
	}
	return strings.Join(where, " AND "), args
}

func QueryLog(ctx context.Context, db *sql.DB, f LogFilter) ([]LogRow, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLogLimit
	}
	if limit > MaxLogExport {
		limit = MaxLogExport
	}
	clause, args := f.build()
	args = append(args, limit)
	rows, err := db.QueryContext(ctx,
		"SELECT ts, domain, qtype, rcode, COALESCE(kind,''), COALESCE(client_subnet,''), "+
			"COALESCE(ecs_zone,''), COALESCE(resp_by,''), COALESCE(exit_path,''), "+
			"COALESCE(server_tag,''), prefetch, COALESCE(elapsed_ms,0) "+
			"FROM query_events WHERE "+clause+" ORDER BY ts DESC, id DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRow
	for rows.Next() {
		var (
			row      LogRow
			qtype    int64
			prefetch int64
		)
		if err := rows.Scan(&row.TS, &row.Domain, &qtype, &row.RCode, &row.Kind,
			&row.ClientSubnet, &row.ECSZone, &row.RespBy, &row.ExitPath,
			&row.ServerTag, &prefetch, &row.ElapsedMS); err != nil {
			return nil, err
		}
		row.QType = dnswire.TypeName(uint16(qtype))
		row.Prefetch = prefetch != 0
		if row.Kind == "" {
			row.Kind = ClassifyKind(row.RespBy, row.RCode)
		}
		row.KindLabel = KindLabel(row.Kind)
		out = append(out, row)
	}
	return out, rows.Err()
}

func Annotate(rows []LogRow, geo *geoip.GeoDB, cdn *cdnrules.Set) {
	for i := range rows {
		if geo != nil && rows[i].ClientSubnet != "" {
			if prefix, err := netip.ParsePrefix(rows[i].ClientSubnet); err == nil {
				if result := geo.Lookup(prefix.Addr().String()); result.Label != "" {
					rows[i].SubnetRegion = result.Label
				}
			}
		}
		if cdn != nil {
			if provider, ok := cdn.ProviderFor(rows[i].Domain); ok {
				rows[i].CDNProvider = provider.Name
			}
		}
	}
}

var logHeader = []string{
	"时间", "域名", "记录类型", "rcode", "递归类型",
	"来源子网(ECS)", "来源区域", "ECS 分片", "应答来源", "出口路径", "入口", "预取", "耗时ms", "CDN",
}

func WriteLogCSV(w io.Writer, rows []LogRow) error {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(logHeader); err != nil {
		return err
	}
	for _, row := range rows {
		record := []string{
			time.Unix(row.TS, 0).Format("2006-01-02 15:04:05"),
			row.Domain, row.QType, strconv.FormatInt(row.RCode, 10),
			row.KindLabel, row.ClientSubnet, row.SubnetRegion, row.ECSZone,
			row.RespBy, row.ExitPath, row.ServerTag,
			boolText(row.Prefetch), fmt.Sprintf("%.1f", row.ElapsedMS), row.CDNProvider,
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func boolText(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

type KindCount struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Count int64  `json:"count"`
}

func KindBreakdown(ctx context.Context, db *sql.DB, since time.Time) ([]KindCount, error) {
	rows, err := db.QueryContext(ctx,
		"SELECT COALESCE(kind,''), COUNT(*) FROM query_events WHERE ts >= ? GROUP BY 1 ORDER BY 2 DESC",
		since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KindCount
	for rows.Next() {
		var item KindCount
		if err := rows.Scan(&item.Kind, &item.Count); err != nil {
			return nil, err
		}
		if item.Kind == "" {
			item.Kind = KindUnknown
		}
		item.Label = KindLabel(item.Kind)
		out = append(out, item)
	}
	return out, rows.Err()
}
