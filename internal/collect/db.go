package collect

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	SchemaVersion   = 3
	DefaultDBPath   = "/var/lib/dns-stack/collector.db"
	DefaultStateDir = "/var/lib/dns-stack"

	eventRetentionDays = 7
	eventMaxRows       = 2_000_000

	candidateRequeueIntervalSec = 3600
)

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY,
		first_seen_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		occurrence_count INTEGER NOT NULL DEFAULT 1,
		pulled_by_foreign INTEGER NOT NULL DEFAULT 0,
		pulled_at INTEGER
	)`,
	`CREATE INDEX IF NOT EXISTS idx_domains_pulled ON domains(pulled_by_foreign)`,
	`CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen_at)`,
	`CREATE TABLE IF NOT EXISTS query_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		domain TEXT NOT NULL,
		qtype INTEGER NOT NULL,
		rcode INTEGER NOT NULL,
		resp_by TEXT NOT NULL DEFAULT '',
		route TEXT NOT NULL DEFAULT 'unknown',
		server_tag TEXT NOT NULL DEFAULT '',
		prefetch INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON query_events(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_domain ON query_events(domain)`,
	`CREATE INDEX IF NOT EXISTS idx_events_route ON query_events(route, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_rcode ON query_events(rcode, ts)`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		actor TEXT NOT NULL DEFAULT 'panel',
		operation TEXT NOT NULL,
		args TEXT NOT NULL DEFAULT '',
		ok INTEGER NOT NULL DEFAULT 0,
		message TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)`,
}

var domainExtraColumns = [][2]string{
	{"last_rcode", "INTEGER"},
	{"last_route", "TEXT"},
	{"fail_count", "INTEGER NOT NULL DEFAULT 0"},
}

var eventExtraColumns = [][2]string{
	{"elapsed_ms", "REAL"},
	{"exit_path", "TEXT"},
}

var eventExtraIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_events_exit ON query_events(exit_path, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_elapsed ON query_events(ts, elapsed_ms) WHERE elapsed_ms IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_events_domain_elapsed ON query_events(domain, elapsed_ms) WHERE elapsed_ms IS NOT NULL`,
}

type Event struct {
	TS        int64
	Domain    string
	QType     int64
	RCode     int64
	RespBy    string
	Route     string
	ExitPath  string
	ServerTag string
	Prefetch  int64

	ElapsedMS *float64
}

func OpenDB(path string) (*sql.DB, error) {
	if path == "" {
		path = DefaultDBPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	for _, statement := range schemaStatements {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func EffectivePragmas(db *sql.DB) (journalMode string, busyTimeout int64) {
	_ = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	_ = db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout)
	return journalMode, busyTimeout
}

func migrate(db *sql.DB) error {
	if err := addMissingColumns(db, "domains", domainExtraColumns); err != nil {
		return err
	}
	if err := addMissingColumns(db, "query_events", eventExtraColumns); err != nil {
		return err
	}

	for _, ddl := range eventExtraIndexes {
		if _, err := db.Exec(ddl); err != nil {
			return err
		}
	}
	_, err := db.Exec(
		"INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?) "+
			"ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		SchemaVersion)
	return err
}

func addMissingColumns(db *sql.DB, table string, columns [][2]string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var index int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&index, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, column := range columns {
		if existing[column[0]] {
			continue
		}
		if _, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column[0] + " " + column[1]); err != nil {
			return err
		}
	}
	return nil
}

type domainAggregate struct {
	domain  string
	firstTS int64
	lastTS  int64
	count   int64
	rcode   int64
	route   string
	fails   int64
}

func aggregateDomains(events []Event) []domainAggregate {
	index := map[string]*domainAggregate{}
	order := make([]string, 0, len(events))
	for _, event := range events {
		item := index[event.Domain]
		if item == nil {
			fails := int64(0)
			if event.RCode != 0 {
				fails = 1
			}
			index[event.Domain] = &domainAggregate{
				domain: event.Domain, firstTS: event.TS, lastTS: event.TS,
				count: 1, rcode: event.RCode, route: event.Route, fails: fails,
			}
			order = append(order, event.Domain)
			continue
		}
		item.count++
		if event.RCode != 0 {
			item.fails++
		}
		if event.TS < item.firstTS {
			item.firstTS = event.TS
		}

		if event.TS >= item.lastTS {
			item.lastTS = event.TS
			item.rcode = event.RCode
			item.route = event.Route
		}
	}
	out := make([]domainAggregate, 0, len(order))
	for _, domain := range order {
		out = append(out, *index[domain])
	}
	return out
}

func RecordEvents(db *sql.DB, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	insertEvent, err := tx.Prepare(
		"INSERT INTO query_events(ts, domain, qtype, rcode, resp_by, route, server_tag, prefetch, elapsed_ms, exit_path) " +
			"VALUES (?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	for _, event := range events {
		var elapsed any
		if event.ElapsedMS != nil {
			elapsed = *event.ElapsedMS
		}
		var exit any
		if event.ExitPath != "" {
			exit = event.ExitPath
		}
		if _, err := insertEvent.Exec(event.TS, event.Domain, event.QType, event.RCode,
			event.RespBy, event.Route, event.ServerTag, event.Prefetch, elapsed, exit); err != nil {
			insertEvent.Close()
			return err
		}
	}
	insertEvent.Close()

	upsertDomain, err := tx.Prepare(`
		INSERT INTO domains(domain, first_seen_at, last_seen_at, occurrence_count,
		                    pulled_by_foreign, last_rcode, last_route, fail_count)
		VALUES (?, ?, ?, ?, 0, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			last_seen_at = max(domains.last_seen_at, excluded.last_seen_at),
			occurrence_count = occurrence_count + excluded.occurrence_count,
			last_rcode = excluded.last_rcode,
			last_route = excluded.last_route,
			fail_count = fail_count + excluded.fail_count,
			pulled_by_foreign = CASE
				WHEN domains.pulled_at IS NULL
				  OR excluded.last_seen_at - domains.pulled_at >= ? THEN 0
				ELSE domains.pulled_by_foreign END`)
	if err != nil {
		return err
	}
	defer upsertDomain.Close()
	for _, item := range aggregateDomains(events) {
		if _, err := upsertDomain.Exec(item.domain, item.firstTS, item.lastTS,
			item.count, item.rcode, item.route, item.fails,
			candidateRequeueIntervalSec); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func PruneEvents(db *sql.DB, now int64) (int64, error) {
	cutoff := now - eventRetentionDays*86400
	result, err := db.Exec("DELETE FROM query_events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	deleted, _ := result.RowsAffected()

	var total int64
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events").Scan(&total); err != nil {
		return deleted, err
	}
	if total > eventMaxRows {
		result, err := db.Exec(
			"DELETE FROM query_events WHERE id IN "+
				"(SELECT id FROM query_events ORDER BY id ASC LIMIT ?)", total-eventMaxRows)
		if err != nil {
			return deleted, err
		}
		extra, _ := result.RowsAffected()
		deleted += extra
	}
	return deleted, nil
}

func Checkpoint(db *sql.DB) error {
	_, err := db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	return err
}

type Candidate struct {
	Domain          string `json:"domain"`
	FirstSeenAt     int64  `json:"first_seen_at"`
	LastSeenAt      int64  `json:"last_seen_at"`
	OccurrenceCount int64  `json:"occurrence_count"`
}

func PullBatch(db *sql.DB, limit int, now int64) ([]Candidate, error) {
	if limit <= 0 {
		limit = 2000
	}
	rows, err := db.Query(
		"SELECT domain, first_seen_at, last_seen_at, occurrence_count FROM domains "+
			"WHERE pulled_by_foreign = 0 ORDER BY last_seen_at ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	var all []Candidate
	for rows.Next() {
		var item Candidate
		if err := rows.Scan(&item.Domain, &item.FirstSeenAt, &item.LastSeenAt, &item.OccurrenceCount); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return []Candidate{}, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	statement, err := tx.Prepare("UPDATE domains SET pulled_by_foreign = 1, pulled_at = ? WHERE domain = ?")
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	for _, item := range all {
		if _, err := statement.Exec(now, item.Domain); err != nil {
			statement.Close()
			_ = tx.Rollback()
			return nil, err
		}
	}
	statement.Close()
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	out := make([]Candidate, 0, len(all))
	for _, item := range all {
		if classifiableCandidate(item.Domain) {
			out = append(out, item)
		}
	}
	return out, nil
}

func classifiableCandidate(domain string) bool {
	value := strings.ToLower(strings.TrimRight(domain, "."))
	if !strings.Contains(value, ".") {
		return false
	}
	for _, suffix := range []string{
		".in-addr.arpa", ".ip6.arpa", ".local", ".localhost", ".invalid", ".test",
	} {
		if strings.HasSuffix(value, suffix) {
			return false
		}
	}
	return true
}

type Stats struct {
	TotalDomains int64 `json:"total_domains"`
	PendingPull  int64 `json:"pending_pull"`
	QueryEvents  int64 `json:"query_events"`
}

func ReadStats(db *sql.DB) (Stats, error) {
	var out Stats
	if err := db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&out.TotalDomains); err != nil {
		return out, err
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE pulled_by_foreign = 0").Scan(&out.PendingPull); err != nil {
		return out, err
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events").Scan(&out.QueryEvents); err != nil {
		return out, err
	}
	return out, nil
}

func WriteAudit(db *sql.DB, operation, args string, ok bool, message, actor string) error {
	if actor == "" {
		actor = "panel"
	}
	flag := 0
	if ok {
		flag = 1
	}
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := db.Exec(
		"INSERT INTO audit_log(ts, actor, operation, args, ok, message) VALUES (?,?,?,?,?,?)",
		time.Now().Unix(), actor, operation, args, flag, message)
	return err
}
