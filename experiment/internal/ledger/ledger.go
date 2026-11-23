// Package ledger records every experiment step (input, state, result)
// into SQLite so the whole run is replayable and auditable.
package ledger

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Ledger struct {
	db    *sql.DB
	RunID string
	seq   int
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	run_id     TEXT PRIMARY KEY,
	started_at TEXT NOT NULL,
	meta       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS objects (
	sha256       TEXT NOT NULL,
	name         TEXT NOT NULL,
	ext          TEXT NOT NULL,
	size         INTEGER NOT NULL,
	submit_count INTEGER NOT NULL DEFAULT 1,
	first_run    TEXT NOT NULL,
	PRIMARY KEY (sha256, name)
);
CREATE TABLE IF NOT EXISTS steps (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id      TEXT NOT NULL,
	seq         INTEGER NOT NULL,
	phase       TEXT NOT NULL,
	object_id   TEXT NOT NULL DEFAULT '',
	snapshot    TEXT NOT NULL DEFAULT '',
	input_sha256 TEXT NOT NULL DEFAULT '',
	input_bytes INTEGER NOT NULL DEFAULT 0,
	state       TEXT NOT NULL DEFAULT '{}',
	result      TEXT NOT NULL,
	detail      TEXT NOT NULL DEFAULT '{}',
	created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_run ON steps(run_id, seq);
`

func Open(path, runID, meta string) (*Ledger, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	l := &Ledger{db: db, RunID: runID}
	_, err = db.Exec(`INSERT INTO runs(run_id, started_at, meta) VALUES(?,?,?)`,
		runID, time.Now().UTC().Format(time.RFC3339Nano), meta)
	if err != nil {
		return nil, fmt.Errorf("begin run: %w", err)
	}
	return l, nil
}

func (l *Ledger) Close() error {
	if _, err := l.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	return l.db.Close()
}

// Checkpoint flushes WAL into the main database file so it can be
// safely copied as evidence while the ledger is still open.
func (l *Ledger) Checkpoint() error {
	_, err := l.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// RegisterObject records a submission; returns submit count for this sha256.
func (l *Ledger) RegisterObject(sha256, name, ext string, size int64) (int, error) {
	if _, err := l.db.Exec(
		`INSERT INTO objects(sha256, name, ext, size, submit_count, first_run)
		 VALUES(?,?,?,?,1,?)
		 ON CONFLICT(sha256, name) DO UPDATE SET submit_count = submit_count + 1`,
		sha256, name, ext, size, l.RunID); err != nil {
		return 0, err
	}
	var count int
	err := l.db.QueryRow(
		`SELECT COALESCE(SUM(submit_count),0) FROM objects WHERE sha256=?`, sha256,
	).Scan(&count)
	return count, err
}

// SeenBefore reports whether this content hash was submitted in an earlier step.
func (l *Ledger) SeenBefore(sha256 string) (bool, error) {
	var n int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM objects WHERE sha256=?`, sha256).Scan(&n)
	return n > 0, err
}

type Step struct {
	Phase, ObjectID, Snapshot string
	InputSHA256               string
	InputBytes                int64
	State, Result, Detail     string
}

func (l *Ledger) AddStep(s Step) (int64, error) {
	l.seq++
	res, err := l.db.Exec(
		`INSERT INTO steps(run_id, seq, phase, object_id, snapshot,
		 input_sha256, input_bytes, state, result, detail, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		l.RunID, l.seq, s.Phase, s.ObjectID, s.Snapshot,
		s.InputSHA256, s.InputBytes, s.State, s.Result, s.Detail,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// QuerySteps returns steps of the current run ordered by seq, as raw rows.
func (l *Ledger) QuerySteps() ([]Step, error) {
	rows, err := l.db.Query(
		`SELECT phase, object_id, snapshot, input_sha256, input_bytes,
		        state, result, detail
		 FROM steps WHERE run_id=? ORDER BY seq`, l.RunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var s Step
		if err := rows.Scan(&s.Phase, &s.ObjectID, &s.Snapshot,
			&s.InputSHA256, &s.InputBytes, &s.State, &s.Result, &s.Detail); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
