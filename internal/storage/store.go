// Package storage persists normalized LFI evidence records in SQLite and
// exposes a review view that joins each record to its counterpart in the
// other snapshot by correlation id.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"lfireview/internal/model"
)

// Store wraps a SQLite database file holding reviewable evidence.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the database at path and applies the
// schema. Call Close when done.
func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS runs(
			run_id        TEXT PRIMARY KEY,
			started_at    TEXT NOT NULL,
			finished_at   TEXT,
			status        TEXT NOT NULL,
			object_total  INTEGER NOT NULL DEFAULT 0,
			object_failed INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS evidence(
			record_id           INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id              TEXT NOT NULL,
			correlation_id      TEXT NOT NULL,
			snapshot_version    TEXT NOT NULL,
			source_object       TEXT NOT NULL,
			attack_input        TEXT NOT NULL,
			trigger_file        TEXT NOT NULL,
			trigger_line        INTEGER NOT NULL,
			trigger_symbol      TEXT NOT NULL,
			permission_decision TEXT NOT NULL,
			permission_rule     TEXT NOT NULL,
			log_path            TEXT NOT NULL,
			log_line            INTEGER NOT NULL,
			log_snippet         TEXT NOT NULL,
			parse_status        TEXT NOT NULL,
			parse_error         TEXT NOT NULL,
			raw_object          BLOB NOT NULL,
			ingested_at         TEXT NOT NULL,
			FOREIGN KEY(run_id) REFERENCES runs(run_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_corr
			ON evidence(correlation_id, snapshot_version)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(parse_status)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return s.recreateView(ctx)
}

// recreateView rebuilds the review view. It is recreated rather than altered
// so schema changes across runs stay idempotent.
func (s *Store) recreateView(ctx context.Context) error {
	view := `
CREATE VIEW IF NOT EXISTS review_pairs AS
SELECT
	COALESCE(v1.correlation_id, v2.correlation_id) AS correlation_id,
	v1.source_object    AS v1_object,
	v2.source_object    AS v2_object,
	v1.attack_input     AS v1_attack_input,
	v2.attack_input     AS v2_attack_input,
	v1.trigger_file     AS v1_trigger_file,
	v1.trigger_line     AS v1_trigger_line,
	v2.trigger_file     AS v2_trigger_file,
	v2.trigger_line     AS v2_trigger_line,
	v1.permission_decision AS v1_permission_decision,
	v2.permission_decision AS v2_permission_decision,
	v1.log_path         AS v1_log_path,
	v1.log_line         AS v1_log_line,
	v2.log_path         AS v2_log_path,
	v2.log_line         AS v2_log_line,
	v1.parse_status     AS v1_parse_status,
	v2.parse_status     AS v2_parse_status
FROM (SELECT * FROM evidence WHERE snapshot_version = 'v1') AS v1
FULL OUTER JOIN (SELECT * FROM evidence WHERE snapshot_version = 'v2') AS v2
	ON v1.correlation_id = v2.correlation_id
	AND v1.run_id = v2.run_id`
	if _, err := s.db.ExecContext(ctx, "DROP VIEW IF EXISTS review_pairs"); err != nil {
		return fmt.Errorf("drop view: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, view); err != nil {
		return fmt.Errorf("create view: %w", err)
	}
	return nil
}

// BeginRun records a new ingestion run and returns its id.
func (s *Store) BeginRun(ctx context.Context, runID, startedAt string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runs(run_id, started_at, status) VALUES(?, ?, 'running')`,
		runID, startedAt)
	if err != nil {
		return fmt.Errorf("begin run: %w", err)
	}
	return nil
}

// InsertRecord stores one evidence record, including its raw bytes.
func (s *Store) InsertRecord(ctx context.Context, runID, ingestedAt string, rec model.EvidenceRecord) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO evidence(
		run_id, correlation_id, snapshot_version, source_object,
		attack_input, trigger_file, trigger_line, trigger_symbol,
		permission_decision, permission_rule,
		log_path, log_line, log_snippet,
		parse_status, parse_error, raw_object, ingested_at
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		runID, rec.CorrelationID, rec.SnapshotVersion, rec.SourceObject,
		rec.AttackInput, rec.TriggerFile, rec.TriggerLine, rec.TriggerSymbol,
		string(rec.PermissionDecision), rec.PermissionRule,
		rec.LogPath, rec.LogLine, rec.LogSnippet,
		string(rec.Status), rec.ParseError, rec.Raw, ingestedAt)
	if err != nil {
		return 0, fmt.Errorf("insert evidence %s/%s: %w",
			rec.SnapshotVersion, rec.SourceObject, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	return id, nil
}

// FinishRun marks the run complete with object counters.
func (s *Store) FinishRun(ctx context.Context, runID, finishedAt, status string, total, failed int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET finished_at = ?, status = ?,
			object_total = ?, object_failed = ? WHERE run_id = ?`,
		finishedAt, status, total, failed, runID)
	if err != nil {
		return fmt.Errorf("finish run: %w", err)
	}
	return nil
}

// TruncatedRow is one truncated record returned for reviewer follow-up.
type TruncatedRow struct {
	CorrelationID string
	Version       string
	SourceObject  string
	ParseError    string
	Recovered     map[string]string
}

// QueryTruncated returns every truncated record, newest run first.
func (s *Store) QueryTruncated(ctx context.Context) ([]TruncatedRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT correlation_id, snapshot_version,
		source_object, parse_error, attack_input, trigger_file, trigger_line,
		permission_decision, log_path, log_line
		FROM evidence WHERE parse_status = 'truncated'
		ORDER BY record_id`)
	if err != nil {
		return nil, fmt.Errorf("query truncated: %w", err)
	}
	defer rows.Close()

	var out []TruncatedRow
	for rows.Next() {
		var t TruncatedRow
		var line, logLine int
		var attack, trigFile, verdict, logPath string
		if err := rows.Scan(&t.CorrelationID, &t.Version, &t.SourceObject,
			&t.ParseError, &attack, &trigFile, &line, &verdict, &logPath, &logLine); err != nil {
			return nil, fmt.Errorf("scan truncated: %w", err)
		}
		t.Recovered = map[string]string{
			"attack_input":        attack,
			"trigger_file":        trigFile,
			"trigger_line":        fmt.Sprintf("%d", line),
			"permission_decision": verdict,
			"log_path":            logPath,
			"log_line":            fmt.Sprintf("%d", logLine),
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Close checkpoints WAL state and closes the database handle.
func (s *Store) Close(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		s.db.Close()
		return fmt.Errorf("wal checkpoint: %w", err)
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Remove deletes the database file and its WAL/SHM sidecars. Use only after
// Close; it is the cleanup hook for temporary review databases.
func (s *Store) Remove() error {
	if s.path == "" || s.path == ":memory:" {
		return nil
	}
	var errs []error
	for _, suffix := range []string{"", "-wal", "-shm"} {
		name := s.path + suffix
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DBPath reports the on-disk location of the database.
func (s *Store) DBPath() string { return s.path }
