// Package evidence persists the review trail in SQLite: for every
// processed object it links the attack input, the trigger location,
// the permission decision and the log lines that prove what happened.
package evidence

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is one row of reviewable evidence.
type Entry struct {
	Snapshot   string // snapshot label, e.g. "snapshot_v1"
	LineNo     int    // 1-based line number inside the snapshot file
	RecordID   string // canonical record id, "" when unparseable
	Format     string // v1 / v2 / unknown
	InputHash  string // sha256 of the raw input line
	InputHead  string // first bytes of the raw input (key evidence excerpt)
	InputLen   int    // full length of the raw input
	Trigger    string // ok / depth_exceeded / truncated / syntax / ...
	Location   string // offset=.. depth=.. path=.. at the trigger point
	Decision   string // allow / deny:unparseable / deny:policy
	LogExcerpt string // log lines emitted while handling this record
	CreatedAt  time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot     TEXT NOT NULL,
    line_no      INTEGER NOT NULL,
    record_id    TEXT NOT NULL,
    format       TEXT NOT NULL,
    input_hash   TEXT NOT NULL,
    input_head   TEXT NOT NULL,
    input_len    INTEGER NOT NULL,
    trigger      TEXT NOT NULL,
    location     TEXT NOT NULL,
    decision     TEXT NOT NULL,
    log_excerpt  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_decision ON evidence(decision);
`

// Store wraps the SQLite handle.
type Store struct {
	db *sql.DB
}

// Open creates (or opens) the evidence database and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close flushes and closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Add persists one evidence entry.
func (s *Store) Add(ctx context.Context, e Entry) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO evidence (snapshot, line_no, record_id, format, input_hash,
    input_head, input_len, trigger, location, decision, log_excerpt, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Snapshot, e.LineNo, e.RecordID, e.Format, e.InputHash,
		e.InputHead, e.InputLen, string(e.Trigger), e.Location,
		e.Decision, e.LogExcerpt, e.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// List returns all entries in insertion order, for the review report.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT snapshot, line_no, record_id, format, input_hash, input_head,
       input_len, trigger, location, decision, log_excerpt, created_at
FROM evidence ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.Snapshot, &e.LineNo, &e.RecordID, &e.Format,
			&e.InputHash, &e.InputHead, &e.InputLen, &e.Trigger,
			&e.Location, &e.Decision, &e.LogExcerpt, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
