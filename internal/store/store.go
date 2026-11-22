// Package store persists every resumable-processing state and every piece of
// evidence in a single SQLite database. The schema is created with explicit
// column order and strict typing so a reopened artifact keeps fields and
// ordering identical across processes and machines.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store wraps one SQLite file.
type Store struct {
	db *sql.DB
}

// SchemaVersion is bumped whenever the DDL changes; an artifact written by
// another version is rejected rather than silently misread.
const SchemaVersion = 1

const ddl = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS runs(
  run_id            TEXT PRIMARY KEY,
  object_id         TEXT NOT NULL,
  state             TEXT NOT NULL,
  created_unix_nano INTEGER NOT NULL,
  updated_unix_nano INTEGER NOT NULL,
  input_sha256      TEXT NOT NULL,
  input_size        INTEGER NOT NULL,
  input_truncated   INTEGER NOT NULL,
  parse_error_class TEXT NOT NULL,
  budget_tokens     INTEGER NOT NULL,
  budget_bytes      INTEGER NOT NULL,
  tokens_used       INTEGER NOT NULL,
  bytes_used        INTEGER NOT NULL,
  degrade_level     INTEGER NOT NULL,
  last_checkpoint_seq INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS checkpoints(
  run_id        TEXT NOT NULL,
  seq           INTEGER NOT NULL,
  frame_offset  INTEGER NOT NULL,
  frame_crc32   INTEGER NOT NULL,
  state_json    TEXT NOT NULL,
  state_sha256  TEXT NOT NULL,
  created_unix_nano INTEGER NOT NULL,
  PRIMARY KEY(run_id, seq),
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS evidence(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id        TEXT NOT NULL,
  kind          TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  content       BLOB NOT NULL,
  created_unix_nano INTEGER NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS degradation_events(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id        TEXT NOT NULL,
  level         INTEGER NOT NULL,
  reason        TEXT NOT NULL,
  detail        TEXT NOT NULL,
  created_unix_nano INTEGER NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS reports(
  run_id        TEXT PRIMARY KEY,
  report_json   TEXT NOT NULL,
  report_sha256 TEXT NOT NULL,
  created_unix_nano INTEGER NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
) WITHOUT ROWID;
`

// Open opens (and initializes) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=strict(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := s.setMeta("schema_version", fmt.Sprint(SchemaVersion)); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the handle for callers that need direct queries (verifier).
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) setMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Meta returns a meta value or "" when absent.
func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}
