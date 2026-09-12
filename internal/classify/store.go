package classify

import (
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	SchemaVersion         = 6
	DefaultDBPath         = "/var/lib/dns-stack/classifier.db"
	TrafficRuleSource     = "cn-dynamic-traffic"
	observationsPerDomain = 24
	runHistoryLimit       = 500
)

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS candidates (
		domain TEXT PRIMARY KEY,
		first_seen_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		occurrence_count INTEGER NOT NULL DEFAULT 1,
		consumed INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_candidates_pending ON candidates(consumed, last_seen_at)`,
	`CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY,
		status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('cn','gfw','unknown')),
		manual_override TEXT CHECK(manual_override IS NULL OR manual_override IN ('cn','gfw','exclude')),
		last_check_at INTEGER,
		last_decisive_at INTEGER,
		status_changed_at INTEGER,
		last_result TEXT,
		runtime_route TEXT NOT NULL DEFAULT 'unknown',
		runtime_reason TEXT,
		landing TEXT NOT NULL DEFAULT 'no_answer',
		cn_ips TEXT NOT NULL DEFAULT '',
		foreign_ips TEXT NOT NULL DEFAULT '',
		cname_chain TEXT NOT NULL DEFAULT '',
		static_rule TEXT NOT NULL DEFAULT 'none',
		static_rule_source TEXT,
		publication_scope TEXT NOT NULL DEFAULT 'private',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status)`,
	`CREATE INDEX IF NOT EXISTS idx_domains_rule ON domains(static_rule, publication_scope)`,
	`CREATE INDEX IF NOT EXISTS idx_domains_recheck ON domains(status, last_check_at)`,
	`CREATE TABLE IF NOT EXISTS observations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		observed_at INTEGER NOT NULL,
		status TEXT NOT NULL,
		route TEXT NOT NULL,
		reason TEXT NOT NULL,
		landing TEXT NOT NULL DEFAULT 'no_answer',
		final_ips TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_observations_domain ON observations(domain, id DESC)`,
	`CREATE TABLE IF NOT EXISTS ip_cidrs (
		cidr TEXT NOT NULL,
		kind TEXT NOT NULL CHECK(kind IN ('cn','polluted')),
		source TEXT NOT NULL,
		first_seen_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		PRIMARY KEY(cidr, kind, source)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_cidrs_kind_active ON ip_cidrs(kind, active)`,
	`CREATE TABLE IF NOT EXISTS runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT NOT NULL,
		started_at INTEGER NOT NULL,
		completed_at INTEGER,
		requested_count INTEGER NOT NULL DEFAULT 0,
		checked_count INTEGER NOT NULL DEFAULT 0,
		changed_count INTEGER NOT NULL DEFAULT 0,
		guard_ok INTEGER NOT NULL DEFAULT 0,
		guard TEXT NOT NULL DEFAULT '',
		error TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC)`,
}

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func OpenStore(path string, now func() time.Time) (*Store, error) {
	if path == "" {
		path = DefaultDBPath
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if now == nil {
		now = time.Now
	}
	s := &Store{db: db, now: now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) unix() int64 { return s.now().Unix() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	previous := s.metaInt("schema_version")
	for _, stmt := range schemaStatements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("建表失败: %w", err)
		}
	}
	if previous > 0 && previous < 6 {
		if err := s.migrateToV6(); err != nil {
			return fmt.Errorf("迁移到 schema v6 失败: %w", err)
		}
	}
	return s.setMeta("schema_version", fmt.Sprint(SchemaVersion))
}

var v6DomainColumns = [][2]string{
	{"last_result", "TEXT"},
	{"last_decisive_at", "INTEGER"},
	{"status_changed_at", "INTEGER"},
	{"runtime_route", "TEXT NOT NULL DEFAULT 'unknown'"},
	{"runtime_reason", "TEXT"},
	{"landing", "TEXT NOT NULL DEFAULT 'no_answer'"},
	{"cn_ips", "TEXT NOT NULL DEFAULT ''"},
	{"foreign_ips", "TEXT NOT NULL DEFAULT ''"},
	{"cname_chain", "TEXT NOT NULL DEFAULT ''"},
	{"static_rule", "TEXT NOT NULL DEFAULT 'none'"},
	{"static_rule_source", "TEXT"},
	{"publication_scope", "TEXT NOT NULL DEFAULT 'private'"},
}

func (s *Store) columnsOf(table string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (s *Store) migrateToV6() error {
	legacyObservations, err := s.tableExists("classification_observations")
	if err != nil {
		return err
	}
	legacyRuns, err := s.tableExists("classification_runs")
	if err != nil {
		return err
	}
	existing, err := s.columnsOf("domains")
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, column := range v6DomainColumns {
		if existing[column[0]] {
			continue
		}
		if _, err := tx.Exec(`ALTER TABLE domains ADD COLUMN ` + column[0] + ` ` + column[1]); err != nil {
			return fmt.Errorf("补列 domains.%s 失败: %w", column[0], err)
		}
	}
	if existing["cname_chain_json"] {
		if _, err := tx.Exec(`UPDATE domains SET cname_chain=''
			WHERE cname_chain IS NULL OR cname_chain=''`); err != nil {
			return err
		}
	}

	if legacyObservations {
		if _, err := tx.Exec(`INSERT INTO observations(domain, observed_at, status, route, reason, landing, final_ips)
			SELECT domain, observed_at, status,
			       COALESCE(runtime_route, 'unknown'), COALESCE(reason, ''), 'no_answer', ''
			FROM classification_observations`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DROP TABLE classification_observations`); err != nil {
			return err
		}
	}
	if legacyRuns {
		if _, err := tx.Exec(`INSERT INTO runs(mode, started_at, completed_at, requested_count,
				checked_count, changed_count, guard_ok, guard, error)
			SELECT mode, started_at, completed_at, requested_count,
			       checked_count, changed_count, guard_ok, COALESCE(guard_json, ''), error
			FROM classification_runs`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DROP TABLE classification_runs`); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM schema_meta WHERE key='classification_epoch_observation_id'`); err != nil {
		return err
	}
	for _, column := range []string{"landing", "cn_ips", "foreign_ips", "cname_chain"} {
		if _, err := tx.Exec(`UPDATE domains SET ` + column + `=COALESCE(` + column + `, '')`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) tableExists(name string) (bool, error) {
	var found string
	err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) metaInt(key string) int64 {
	var raw string
	if err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key=?`, key).Scan(&raw); err != nil {
		return 0
	}
	var value int64
	fmt.Sscan(raw, &value)
	return value
}

func (s *Store) setMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func scanStrings(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	if n == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func (s *Store) UpsertCandidates(domains []string) (int, error) {
	if len(domains) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO candidates(domain, first_seen_at, last_seen_at, occurrence_count, consumed)
		VALUES(?, ?, ?, 1, 0)
		ON CONFLICT(domain) DO UPDATE SET
			last_seen_at=excluded.last_seen_at,
			occurrence_count=candidates.occurrence_count+1,
			consumed=0`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	now := s.unix()
	inserted := 0
	for _, domain := range domains {
		result, err := stmt.Exec(domain, now, now)
		if err != nil {
			return 0, err
		}
		if affected, _ := result.RowsAffected(); affected == 1 {
			inserted++
		}
	}
	return inserted, tx.Commit()
}

func (s *Store) UnconsumedCandidates(limit int) ([]string, error) {
	return scanStrings(s.db.Query(
		`SELECT domain FROM candidates WHERE consumed=0 ORDER BY last_seen_at ASC LIMIT ?`, limit))
}

func (s *Store) MarkCandidatesConsumed(domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE candidates SET consumed=1 WHERE domain IN (`+placeholders(len(domains))+`)`,
		toAny(domains)...)
	return err
}

func (s *Store) AuthorityScanPool(limit int) ([]string, error) {
	query := `SELECT domain FROM candidates
		UNION SELECT domain FROM domains WHERE manual_override IS NULL`
	if limit > 0 {
		return scanStrings(s.db.Query(query+` LIMIT ?`, limit))
	}
	return scanStrings(s.db.Query(query))
}

func (s *Store) DomainsNeedingRecheck(limit int, minAge time.Duration) ([]string, error) {
	args := append([]any{s.unix() - int64(minAge.Seconds())}, toAny(recheckReasons)...)
	args = append(args, limit)
	return scanStrings(s.db.Query(`SELECT domain FROM domains
		WHERE status='unknown' AND manual_override IS NULL
		  AND (last_check_at IS NULL OR last_check_at <= ?)
		  AND last_result IN (`+placeholders(len(recheckReasons))+`)
		ORDER BY last_check_at ASC LIMIT ?`, args...))
}

func (s *Store) FormalDueForVerification(limit int, maxAge time.Duration) ([]string, error) {
	return scanStrings(s.db.Query(`SELECT domain FROM domains
		WHERE manual_override IS NULL AND status IN ('cn','gfw')
		  AND (last_decisive_at IS NULL OR last_decisive_at <= ?)
		ORDER BY COALESCE(last_check_at, 0) ASC, COALESCE(last_decisive_at, 0) ASC, domain
		LIMIT ?`, s.unix()-int64(maxAge.Seconds()), limit))
}

type domainState struct {
	status          string
	override        string
	statusChangedAt int64
	known           bool
}

func (s *Store) statesFor(domains []string) (map[string]domainState, error) {
	out := make(map[string]domainState, len(domains))
	const chunk = 400
	for start := 0; start < len(domains); start += chunk {
		end := min(start+chunk, len(domains))
		batch := domains[start:end]
		rows, err := s.db.Query(
			`SELECT domain, status, COALESCE(manual_override, ''), COALESCE(status_changed_at, created_at)
			 FROM domains WHERE domain IN (`+placeholders(len(batch))+`)`, toAny(batch)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var name string
			var state domainState
			if err := rows.Scan(&name, &state.status, &state.override, &state.statusChangedAt); err != nil {
				rows.Close()
				return nil, err
			}
			state.known = true
			out[name] = state
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) ApplyVerdicts(verdicts []Verdict) (int, error) {
	if len(verdicts) == 0 {
		return 0, nil
	}
	names := make([]string, len(verdicts))
	for i, v := range verdicts {
		names[i] = v.Domain
	}
	states, err := s.statesFor(names)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	upsert, err := tx.Prepare(`INSERT INTO domains(
			domain, status, last_check_at, last_decisive_at, status_changed_at, last_result,
			runtime_route, runtime_reason, landing, cn_ips, foreign_ips, cname_chain,
			static_rule, publication_scope, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'none','private',?,?)
		ON CONFLICT(domain) DO UPDATE SET
			status=excluded.status,
			last_check_at=excluded.last_check_at,
			last_decisive_at=COALESCE(excluded.last_decisive_at, domains.last_decisive_at),
			status_changed_at=excluded.status_changed_at,
			last_result=excluded.last_result,
			runtime_route=excluded.runtime_route,
			runtime_reason=excluded.runtime_reason,
			landing=excluded.landing,
			cn_ips=excluded.cn_ips,
			foreign_ips=excluded.foreign_ips,
			cname_chain=excluded.cname_chain,
			static_rule=CASE
				WHEN domains.manual_override='cn' THEN 'cn'
				WHEN domains.manual_override='gfw' THEN 'foreign-dns'
				WHEN domains.static_rule_source=? THEN domains.static_rule
				ELSE 'none' END,
			publication_scope=CASE
				WHEN domains.static_rule_source=? THEN domains.publication_scope
				ELSE 'private' END,
			updated_at=excluded.updated_at`)
	if err != nil {
		return 0, err
	}
	defer upsert.Close()

	observe, err := tx.Prepare(`INSERT INTO observations(domain, observed_at, status, route, reason, landing, final_ips)
		VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer observe.Close()

	now := s.unix()
	changed := 0
	for _, v := range verdicts {
		state := states[v.Domain]
		status := v.Status
		switch state.override {
		case OverrideCN:
			status = StatusCN
		case OverrideGFW:
			status = StatusGFW
		case OverrideExclude:
			status = StatusUnknown
		}
		if state.known && state.status != status || !state.known && status != StatusUnknown {
			changed++
		}
		changedAt := now
		if state.known && state.status == status && state.statusChangedAt > 0 {
			changedAt = state.statusChangedAt
		}
		var decisiveAt any
		if v.Decisive {
			decisiveAt = now
		}
		if _, err := upsert.Exec(
			v.Domain, status, now, decisiveAt, changedAt, v.Reason,
			v.Route, v.Reason, v.Landing,
			joinAddrs(v.CNIPs), joinAddrs(v.ForeignIPs), strings.Join(v.CNChain, " "),
			now, now, TrafficRuleSource, TrafficRuleSource,
		); err != nil {
			return 0, err
		}
		if _, err := observe.Exec(
			v.Domain, now, status, v.Route, v.Reason, v.Landing, joinAddrs(v.FinalIPs),
		); err != nil {
			return 0, err
		}
	}
	if err := trimObservations(tx, names); err != nil {
		return 0, err
	}
	return changed, tx.Commit()
}

func trimObservations(tx *sql.Tx, domains []string) error {
	const chunk = 400
	for start := 0; start < len(domains); start += chunk {
		end := min(start+chunk, len(domains))
		batch := domains[start:end]
		marks := placeholders(len(batch))
		args := make([]any, 0, len(batch)*2+1)
		args = append(args, toAny(batch)...)
		args = append(args, toAny(batch)...)
		args = append(args, observationsPerDomain)
		if _, err := tx.Exec(`DELETE FROM observations WHERE domain IN (`+marks+`)
			AND id NOT IN (
				SELECT id FROM (
					SELECT id, ROW_NUMBER() OVER (PARTITION BY domain ORDER BY id DESC) AS rn
					FROM observations WHERE domain IN (`+marks+`)
				) WHERE rn <= ?)`, args...); err != nil {
			return err
		}
	}
	return nil
}

func joinAddrs(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return ""
	}
	parts := make([]string, len(addrs))
	for i, addr := range addrs {
		parts[i] = addr.String()
	}
	return strings.Join(parts, " ")
}

func (s *Store) ManualOverrides() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT domain, manual_override FROM domains WHERE manual_override IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var domain, kind string
		if err := rows.Scan(&domain, &kind); err != nil {
			return nil, err
		}
		out[domain] = kind
	}
	return out, rows.Err()
}

func (s *Store) ReplaceManualOverrides(overrides map[string]string) error {
	for domain, kind := range overrides {
		switch kind {
		case OverrideCN, OverrideGFW, OverrideExclude:
		default:
			return fmt.Errorf("非法人工规则类型 %q（域名 %s）", kind, domain)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.unix()
	if _, err := tx.Exec(`UPDATE domains SET manual_override=NULL, status='unknown',
		static_rule='none', publication_scope='private', last_result=?, updated_at=?
		WHERE manual_override IS NOT NULL`, ReasonManualRemoved, now); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO domains(domain, status, manual_override, static_rule,
			publication_scope, created_at, updated_at)
		VALUES(?, ?, ?, ?, 'private', ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			manual_override=excluded.manual_override,
			status=excluded.status,
			static_rule=excluded.static_rule,
			publication_scope='private',
			updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, domain := range sortedKeys(overrides) {
		kind := overrides[domain]
		status, rule := StatusUnknown, RuleNone
		switch kind {
		case OverrideCN:
			status, rule = StatusCN, RuleCN
		case OverrideGFW:
			status, rule = StatusGFW, RuleForeign
		}
		if _, err := stmt.Exec(domain, status, kind, rule, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (s *Store) ReplaceTrafficRules(rules map[string][]string) (map[string]int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.unix()
	counts := make(map[string]int, len(rules))
	for _, rule := range []string{RuleCN, RuleForeign} {
		clean := normalizeRuleDomains(rules[rule])
		counts[rule] = len(clean)
		if len(clean) == 0 {
			continue
		}
		if _, err := tx.Exec(`UPDATE domains SET static_rule='none', publication_scope='private', updated_at=?
			WHERE static_rule_source=? AND static_rule=?`, now, TrafficRuleSource, rule); err != nil {
			return nil, err
		}
		stmt, err := tx.Prepare(`INSERT INTO domains(domain, status, static_rule, static_rule_source,
				publication_scope, created_at, updated_at)
			VALUES(?, 'unknown', ?, ?, 'public', ?, ?)
			ON CONFLICT(domain) DO UPDATE SET
				static_rule=excluded.static_rule,
				static_rule_source=excluded.static_rule_source,
				publication_scope='public',
				updated_at=excluded.updated_at
			WHERE domains.manual_override IS NULL`)
		if err != nil {
			return nil, err
		}
		for _, domain := range clean {
			if _, err := stmt.Exec(domain, rule, TrafficRuleSource, now, now); err != nil {
				stmt.Close()
				return nil, err
			}
		}
		stmt.Close()
	}
	return counts, tx.Commit()
}

func normalizeRuleDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, raw := range domains {
		name := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (s *Store) ClearTrafficRuleClass(rule string) (int, error) {
	if rule != RuleCN && rule != RuleForeign {
		return 0, fmt.Errorf("非法流量规则类别: %s", rule)
	}
	result, err := s.db.Exec(`UPDATE domains SET static_rule='none', publication_scope='private', updated_at=?
		WHERE static_rule_source=? AND static_rule=?`, s.unix(), TrafficRuleSource, rule)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func (s *Store) ReplaceCIDRs(kind string, sources map[string][]string) error {
	if kind != "cn" && kind != "polluted" {
		return fmt.Errorf("非法 CIDR 类别: %s", kind)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.unix()
	if _, err := tx.Exec(`UPDATE ip_cidrs SET active=0 WHERE kind=?`, kind); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO ip_cidrs(cidr, kind, source, first_seen_at, last_seen_at, active)
		VALUES(?,?,?,?,?,1)
		ON CONFLICT(cidr, kind, source) DO UPDATE SET last_seen_at=excluded.last_seen_at, active=1`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, source := range sortedKeys(sources) {
		if source == "" {
			continue
		}
		for _, cidr := range normalizePrefixStrings(sources[source]) {
			if _, err := stmt.Exec(cidr, kind, source, now, now); err != nil {
				return err
			}
		}
	}
	if err := assertCIDRClassesDisjoint(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ActiveCIDRs(kind string) ([]string, error) {
	return scanStrings(s.db.Query(
		`SELECT DISTINCT cidr FROM ip_cidrs WHERE kind=? AND active=1 ORDER BY cidr`, kind))
}

func (s *Store) PurgeCIDRs() (int, error) {
	result, err := s.db.Exec(`DELETE FROM ip_cidrs WHERE kind IN ('cn','polluted')`)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func (s *Store) PublicStaticRules(rule string) ([]string, error) {
	if rule != RuleCN && rule != RuleForeign {
		return nil, fmt.Errorf("非法静态规则类型: %s", rule)
	}
	return scanStrings(s.db.Query(
		`SELECT domain FROM domains WHERE static_rule=? AND publication_scope='public' ORDER BY domain`, rule))
}

func (s *Store) ManualByStatus(status string) ([]string, error) {
	return scanStrings(s.db.Query(
		`SELECT domain FROM domains WHERE manual_override=? ORDER BY domain`, status))
}

func (s *Store) VerifiedGFWDomains(allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		return nil, nil
	}
	var out []string
	const chunk = 400
	for start := 0; start < len(allowed); start += chunk {
		end := min(start+chunk, len(allowed))
		batch := allowed[start:end]
		args := append(toAny(batch), ReasonCNViewPolluted)
		values, err := scanStrings(s.db.Query(`SELECT domain FROM domains
			WHERE domain IN (`+placeholders(len(batch))+`)
			  AND manual_override IS NULL AND status='gfw' AND last_result=?`, args...))
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
	}
	sort.Strings(out)
	return out, nil
}

type Readiness struct {
	AutomaticTotal int   `json:"automatic_total"`
	Stale          int   `json:"stale"`
	BeforeEpoch    int   `json:"before_epoch"`
	Epoch          int64 `json:"epoch"`
	MaxStaleSec    int64 `json:"max_stale_sec"`
}

func (s *Store) PublicationReadiness(maxStale time.Duration) (Readiness, error) {
	epoch := s.metaInt("classification_epoch")
	cutoff := s.unix() - int64(maxStale.Seconds())
	out := Readiness{Epoch: epoch, MaxStaleSec: int64(maxStale.Seconds())}
	err := s.db.QueryRow(`SELECT COUNT(*),
			SUM(CASE WHEN last_decisive_at IS NULL OR last_decisive_at < ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN last_decisive_at IS NULL OR last_decisive_at < ? THEN 1 ELSE 0 END)
		FROM domains WHERE manual_override IS NULL AND status IN ('cn','gfw')`,
		cutoff, epoch).Scan(&out.AutomaticTotal, &nullableInt{&out.Stale}, &nullableInt{&out.BeforeEpoch})
	return out, err
}

type nullableInt struct{ target *int }

func (n *nullableInt) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*n.target = 0
	case int64:
		*n.target = int(v)
	case float64:
		*n.target = int(v)
	default:
		return fmt.Errorf("无法把 %T 读成整数", value)
	}
	return nil
}

func (s *Store) CountFormalAutoRules() (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM domains WHERE manual_override IS NULL AND status IN ('cn','gfw')`).Scan(&count)
	return count, err
}

func (s *Store) InvalidateAutomatic(reason string, purgeObservations, resetPolluted bool) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	names, err := scanStrings(tx.Query(`SELECT domain FROM domains WHERE manual_override IS NULL ORDER BY domain`))
	if err != nil {
		return 0, err
	}
	now := s.unix()
	if _, err := tx.Exec(`UPDATE domains SET status='unknown', last_check_at=NULL, last_result=?,
		last_decisive_at=NULL, status_changed_at=?, static_rule='none', publication_scope='private',
		landing='no_answer', cn_ips='', foreign_ips='', cname_chain='', updated_at=?
		WHERE manual_override IS NULL`, reason, now, now); err != nil {
		return 0, err
	}
	if purgeObservations {
		if _, err := tx.Exec(`DELETE FROM observations WHERE domain IN (
			SELECT domain FROM domains WHERE manual_override IS NULL)`); err != nil {
			return 0, err
		}
	}
	if resetPolluted {
		if _, err := tx.Exec(`UPDATE ip_cidrs SET active=0 WHERE kind='polluted'`); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_meta(key, value) VALUES('classification_epoch', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(now)); err != nil {
		return 0, err
	}
	requeue, err := tx.Prepare(`INSERT INTO candidates(domain, first_seen_at, last_seen_at, occurrence_count, consumed)
		VALUES(?,?,?,1,0)
		ON CONFLICT(domain) DO UPDATE SET last_seen_at=excluded.last_seen_at, consumed=0`)
	if err != nil {
		return 0, err
	}
	defer requeue.Close()
	for _, domain := range names {
		if _, err := requeue.Exec(domain, now, now); err != nil {
			return 0, err
		}
	}
	return len(names), tx.Commit()
}

func (s *Store) StartRun(mode string, requested int, guard string, guardOK bool) (int64, error) {
	result, err := s.db.Exec(`INSERT INTO runs(mode, started_at, requested_count, guard_ok, guard)
		VALUES(?,?,?,?,?)`, mode, s.unix(), requested, boolInt(guardOK), guard)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) FinishRun(id int64, checked, changed int, failure string) error {
	if len(failure) > 500 {
		failure = failure[:500]
	}
	var errValue any
	if failure != "" {
		errValue = failure
	}
	if _, err := s.db.Exec(`UPDATE runs SET completed_at=?, checked_count=?, changed_count=?, error=? WHERE id=?`,
		s.unix(), checked, changed, errValue, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT ?)`,
		runHistoryLimit)
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

type Counts struct {
	CN                int `json:"cn"`
	GFW               int `json:"gfw"`
	Unknown           int `json:"unknown"`
	PendingCandidates int `json:"pending_candidates"`
	PublicCN          int `json:"public_cn"`
	PublicForeign     int `json:"public_foreign"`
}

func (s *Store) Counts() (Counts, error) {
	var out Counts
	err := s.db.QueryRow(`SELECT
			SUM(status='cn'), SUM(status='gfw'), SUM(status='unknown'),
			SUM(static_rule='cn' AND publication_scope='public'),
			SUM(static_rule='foreign-dns' AND publication_scope='public')
		FROM domains`).Scan(
		&nullableInt{&out.CN}, &nullableInt{&out.GFW}, &nullableInt{&out.Unknown},
		&nullableInt{&out.PublicCN}, &nullableInt{&out.PublicForeign})
	if err != nil {
		return out, err
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE consumed=0`).Scan(&out.PendingCandidates)
	return out, err
}

type Observation struct {
	At       int64  `json:"at"`
	Status   string `json:"status"`
	Route    string `json:"route"`
	Reason   string `json:"reason"`
	Landing  string `json:"landing"`
	FinalIPs string `json:"final_ips"`
}

func (s *Store) History(domain string, limit int) ([]Observation, error) {
	rows, err := s.db.Query(`SELECT observed_at, status, route, reason, landing, final_ips
		FROM observations WHERE domain=? ORDER BY id DESC LIMIT ?`, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Observation{}
	for rows.Next() {
		var item Observation
		if err := rows.Scan(&item.At, &item.Status, &item.Route, &item.Reason,
			&item.Landing, &item.FinalIPs); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
