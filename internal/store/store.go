package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed durable event journal and replay evidence table.
type Store struct {
	db *sql.DB
}

// EventRow is one journal record.
type EventRow struct {
	RunID      string
	Seq        int64
	Kind       string
	MsgID      string
	Accepted   bool
	Duplicate  bool
	Reason     string
	StateAfter string
	HashAfter  string
}

// Open opens (creating if needed) the SQLite database and initializes schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS events (
			run_id      TEXT NOT NULL,
			seq         INTEGER NOT NULL,
			kind        TEXT NOT NULL,
			msg_id      TEXT NOT NULL,
			accepted    INTEGER NOT NULL,
			duplicate   INTEGER NOT NULL,
			reason      TEXT NOT NULL,
			state_after TEXT NOT NULL,
			hash_after  TEXT NOT NULL,
			PRIMARY KEY (run_id, seq)
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			run_id     TEXT PRIMARY KEY,
			mode       TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS replay_checks (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id       TEXT NOT NULL,
			seq          INTEGER NOT NULL,
			original_hash TEXT NOT NULL,
			replay_hash   TEXT NOT NULL,
			match        INTEGER NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// EnsureRun registers a run idempotently.
func (s *Store) EnsureRun(runID, mode string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO runs(run_id, mode) VALUES(?, ?)`, runID, mode)
	return err
}

// AppendEvent writes one processed step durably inside its own transaction.
func (s *Store) AppendEvent(r EventRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO events(run_id, seq, kind, msg_id, accepted, duplicate,
			reason, state_after, hash_after)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		r.RunID, r.Seq, r.Kind, r.MsgID, r.Accepted, r.Duplicate,
		r.Reason, r.StateAfter, r.HashAfter)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Events returns the ordered input stream for a run (lowest seq first).
func (s *Store) Events(runID string) ([]EventRow, error) {
	rows, err := s.db.Query(
		`SELECT run_id, seq, kind, msg_id, accepted, duplicate, reason,
		        state_after, hash_after
		 FROM events WHERE run_id = ? ORDER BY seq ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EventRow
	for rows.Next() {
		var r EventRow
		if err := rows.Scan(&r.RunID, &r.Seq, &r.Kind, &r.MsgID,
			&r.Accepted, &r.Duplicate, &r.Reason, &r.StateAfter,
			&r.HashAfter); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordReplayCheck persists one original-vs-replay hash comparison.
func (s *Store) RecordReplayCheck(runID string, seq int64, orig, replay string, match bool) error {
	_, err := s.db.Exec(
		`INSERT INTO replay_checks(run_id, seq, original_hash, replay_hash, match)
		 VALUES(?,?,?,?,?)`, runID, seq, orig, replay, match)
	return err
}

// ReplayMismatchCount returns how many replayed steps diverged from the journal.
func (s *Store) ReplayMismatchCount(runID string) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM replay_checks WHERE run_id = ? AND match = 0`,
		runID).Scan(&n)
	return n, err
}
