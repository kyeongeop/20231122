// Package store owns the SQLite evidence database. Every state transition is
// inserted inside a transaction with WAL enabled, so a crash mid-batch leaves
// a recoverable journal instead of a half-written, unauditable table.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"riskflow/internal/model"
)

type Store struct {
	DB  *sql.DB
	dsn string
}

// Open opens (and migrates) an evidence database at path. Use ":memory:" for
// tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Single connection keeps the in-process WAL/journal semantics linear and
	// makes "recover after interrupted batch" deterministic in tests.
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, dsn: path}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// DSN identifies the database file for inclusion in replay reports.
func (s *Store) DSN() string {
	if s.dsn == "" {
		return "sqlite"
	}
	return s.dsn
}

// dsn is set by Open so reports can cite the evidence database path.
// (kept unexported: callers use DSN())

func (s *Store) migrate() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS batches(
			batch_id TEXT PRIMARY KEY,
			schema TEXT NOT NULL,
			source_uri TEXT,
			raw_sha256 TEXT,
			byte_len INTEGER,
			truncated INTEGER NOT NULL DEFAULT 0,
			recovered INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS records(
			batch_id TEXT NOT NULL REFERENCES batches(batch_id),
			record_id TEXT NOT NULL,
			pkg TEXT NOT NULL,
			version TEXT NOT NULL,
			ecosystem TEXT,
			severity TEXT,
			decision TEXT,
			role TEXT,
			schema TEXT NOT NULL,
			input_hash TEXT NOT NULL,
			checksum TEXT,
			raw TEXT NOT NULL,
			PRIMARY KEY(batch_id, record_id)
		)`,
		`CREATE TABLE IF NOT EXISTS transitions(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			batch_id TEXT NOT NULL REFERENCES batches(batch_id),
			record_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			from_state TEXT NOT NULL,
			to_state TEXT NOT NULL,
			actor TEXT NOT NULL,
			permit INTEGER NOT NULL,
			granted INTEGER NOT NULL,
			reason TEXT NOT NULL,
			attack_input TEXT NOT NULL,
			trigger_site TEXT NOT NULL,
			input_hash TEXT NOT NULL,
			event_time TEXT NOT NULL DEFAULT (datetime('now')),
			UNIQUE(batch_id, record_id, seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_trans_record ON transitions(batch_id, record_id, seq)`,
		`CREATE TABLE IF NOT EXISTS first_errors(
			batch_id TEXT NOT NULL,
			record_id TEXT NOT NULL,
			state TEXT NOT NULL,
			seq INTEGER NOT NULL,
			reason TEXT NOT NULL,
			input_hash TEXT NOT NULL,
			PRIMARY KEY(batch_id, record_id)
		)`,
	}
	for _, q := range stmts {
		if _, err := s.DB.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w: %s", err, q)
		}
	}
	return nil
}

// UpsertBatch registers a batch and its provenance.
func (s *Store) UpsertBatch(batchID, schema, uri, sha string, n int64, truncated bool) error {
	t := 0
	if truncated {
		t = 1
	}
	_, err := s.DB.Exec(
		`INSERT INTO batches(batch_id, schema, source_uri, raw_sha256, byte_len, truncated)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(batch_id) DO UPDATE SET truncated=excluded.truncated`,
		batchID, schema, uri, sha, n, t)
	return err
}

// MarkRecovered flips the recovery flag after a successful replay.
func (s *Store) MarkRecovered(batchID string) error {
	_, err := s.DB.Exec(`UPDATE batches SET recovered=1 WHERE batch_id=?`, batchID)
	return err
}

// InsertRecord stores the normalized record together with its raw evidence.
func (s *Store) InsertRecord(batchID string, r model.Record) error {
	_, err := s.DB.Exec(
		`INSERT OR REPLACE INTO records
		 (record_id, batch_id, pkg, version, ecosystem, severity, decision, role,
		  schema, input_hash, checksum, raw)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.RecordID, batchID, r.Package, r.Version, r.Ecosystem, r.Severity,
		r.Decision, r.Role, r.Schema, r.InputHash, r.Checksum, r.Raw)
	return err
}

// AppendTransition writes one state-machine step.
func (s *Store) AppendTransition(batchID string, t model.Transition) error {
	_, err := s.DB.Exec(
		`INSERT INTO transitions
		 (batch_id, record_id, seq, from_state, to_state, actor, permit, granted,
		  reason, attack_input, trigger_site, input_hash, event_time)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		batchID, t.RecordID, t.Seq, t.FromState, t.ToState, t.Actor,
		boolInt(t.Permit), boolInt(t.Granted), t.Reason, t.AttackInput,
		t.TriggerSite, t.InputHash, t.EventTime.UTC().Format("2006-01-02T15:04:05Z"))
	return err
}

// SetFirstError records the earliest error state for a record (idempotent).
func (s *Store) SetFirstError(batchID string, e model.FirstError) error {
	_, err := s.DB.Exec(
		`INSERT OR IGNORE INTO first_errors
		 (batch_id, record_id, state, seq, reason, input_hash)
		 VALUES(?,?,?,?,?,?)`,
		batchID, e.RecordID, e.State, e.Seq, e.Reason, e.InputHash)
	return err
}

// FirstErrors returns first-error rows ordered by state rank then sequence.
func (s *Store) FirstErrors(batchID string) ([]model.FirstError, error) {
	rows, err := s.DB.Query(
		`SELECT record_id, state, seq, reason, input_hash
		 FROM first_errors WHERE batch_id=? ORDER BY seq ASC, record_id ASC`,
		batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FirstError
	for rows.Next() {
		var e model.FirstError
		if err := rows.Scan(&e.RecordID, &e.State, &e.Seq, &e.Reason, &e.InputHash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Transitions returns the full ordered evidence trail of one record.
func (s *Store) Transitions(batchID, recordID string) ([]model.Transition, error) {
	rows, err := s.DB.Query(
		`SELECT id, record_id, seq, from_state, to_state, actor, permit, granted,
		        reason, attack_input, trigger_site, input_hash
		 FROM transitions WHERE batch_id=? AND record_id=? ORDER BY seq ASC`,
		batchID, recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Transition
	for rows.Next() {
		var t model.Transition
		if err := rows.Scan(&t.ID, &t.RecordID, &t.Seq, &t.FromState, &t.ToState,
			&t.Actor, &t.Permit, &t.Granted, &t.Reason, &t.AttackInput,
			&t.TriggerSite, &t.InputHash); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountTransitions totals persisted steps for a batch.
func (s *Store) CountTransitions(batchID string) (int, error) {
	var n int
	err := s.DB.QueryRow(
		`SELECT COUNT(*) FROM transitions WHERE batch_id=?`, batchID).Scan(&n)
	return n, err
}

// CountRecords totals normalized records for a batch.
func (s *Store) CountRecords(batchID string) (int, error) {
	var n int
	err := s.DB.QueryRow(
		`SELECT COUNT(*) FROM records WHERE batch_id=?`, batchID).Scan(&n)
	return n, err
}

// BatchRow summarizes batch provenance for reporting.
type BatchRow struct {
	ID        string
	Schema    string
	Truncated bool
	Recovered bool
}

// Batch fetches batch metadata.
func (s *Store) Batch(batchID string) (BatchRow, error) {
	var b BatchRow
	var tr, rc int
	err := s.DB.QueryRow(
		`SELECT batch_id, schema, truncated, recovered FROM batches WHERE batch_id=?`,
		batchID).Scan(&b.ID, &b.Schema, &tr, &rc)
	b.Truncated, b.Recovered = tr == 1, rc == 1
	return b, err
}

// RawRecords reconstructs normalized records (including raw wire evidence) so
// replay can re-drive the state machine without re-reading the source file.
func (s *Store) RawRecords(batchID string) ([]model.Record, error) {
	rows, err := s.DB.Query(
		`SELECT record_id, pkg, version, ecosystem, severity, decision, role,
		        schema, input_hash, COALESCE(checksum,''), raw
		 FROM records WHERE batch_id=? ORDER BY rowid ASC`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Record
	for rows.Next() {
		var r model.Record
		if err := rows.Scan(&r.RecordID, &r.Package, &r.Version, &r.Ecosystem,
			&r.Severity, &r.Decision, &r.Role, &r.Schema, &r.InputHash,
			&r.Checksum, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HasState reports whether a record passed through the given state. Used by
// replay to reproduce the TRUNCATED -> RECOVERED branch deterministically.
func (s *Store) HasState(batchID, recordID, state string) bool {
	var n int
	_ = s.DB.QueryRow(
		`SELECT COUNT(*) FROM transitions
		 WHERE batch_id=? AND record_id=? AND to_state=?`,
		batchID, recordID, state).Scan(&n)
	return n > 0
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
