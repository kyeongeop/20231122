// Package store persists run evidence in SQLite: every parse result,
// smuggled request, permission decision, boundary sample and log line is
// tied to one run id so an audit can replay the reconstruction.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the evidence database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL,
  started_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS parse_results(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  case_name TEXT NOT NULL,
  layer TEXT NOT NULL,
  profile TEXT NOT NULL,
  idx INTEGER NOT NULL,
  status TEXT NOT NULL,
  method TEXT, path TEXT,
  consumed INTEGER,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS smuggled_requests(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  case_name TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  evidence_path TEXT
);
CREATE TABLE IF NOT EXISTS permissions(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  case_name TEXT NOT NULL,
  path TEXT NOT NULL,
  identity TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT
);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  case_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  snippet TEXT
);
CREATE TABLE IF NOT EXISTS boundaries(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  parameter TEXT NOT NULL,
  limit_value INTEGER NOT NULL,
  side TEXT NOT NULL,
  size INTEGER NOT NULL,
  status TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  ts TEXT NOT NULL,
  level TEXT NOT NULL,
  layer TEXT NOT NULL,
  message TEXT NOT NULL
);
`

// Open creates/opens the SQLite database at path and ensures the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CreateRun registers a new reconstruction run and returns its id.
func (s *Store) CreateRun(label string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO runs(label, started_at) VALUES(?,?)`,
		label, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
