package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const schemaSQL = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS schema_meta (
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  source_path TEXT NOT NULL,
  source_name TEXT NOT NULL,
  source_size INTEGER NOT NULL,
  source_sha256 TEXT NOT NULL,
  original BLOB NOT NULL,
  artifact_path TEXT NOT NULL,
  format TEXT NOT NULL,
  status TEXT NOT NULL,
  next_stage INTEGER NOT NULL,
  degraded INTEGER NOT NULL DEFAULT 0,
  limits_json TEXT NOT NULL,
  final_digest TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS anchors (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  number INTEGER NOT NULL,
  label TEXT NOT NULL,
  offset INTEGER NOT NULL,
  line INTEGER NOT NULL,
  captured_at TEXT NOT NULL,
  explicit INTEGER NOT NULL,
  declared_offset INTEGER NOT NULL DEFAULT -1,
  PRIMARY KEY (run_id, number)
);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  stage INTEGER NOT NULL,
  anchor_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  anchor_offset INTEGER NOT NULL,
  anchor_line INTEGER NOT NULL,
  segment_sha256 TEXT NOT NULL,
  result_json TEXT NOT NULL,
  result_sha256 TEXT NOT NULL,
  degraded INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id, stage)
);

CREATE TABLE IF NOT EXISTS records (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  stage INTEGER NOT NULL,
  mount_id TEXT NOT NULL,
  parent_id TEXT NOT NULL,
  major_minor TEXT NOT NULL,
  root TEXT NOT NULL,
  mount_point TEXT NOT NULL,
  mount_options TEXT NOT NULL,
  optional TEXT NOT NULL,
  fs_type TEXT NOT NULL,
  source TEXT NOT NULL,
  super_options TEXT NOT NULL,
  read_only INTEGER NOT NULL,
  no_suid INTEGER NOT NULL,
  no_dev INTEGER NOT NULL,
  no_exec INTEGER NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  line INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS findings (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  stage INTEGER NOT NULL,
  severity TEXT NOT NULL,
  code TEXT NOT NULL,
  mount_point TEXT NOT NULL,
  source TEXT NOT NULL,
  detail TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  line INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS evidence (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  kind TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS comparisons (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  compared_at TEXT NOT NULL,
  scope TEXT NOT NULL,
  prior_sha256 TEXT NOT NULL,
  current_sha256 TEXT NOT NULL,
  equal INTEGER NOT NULL,
  detail_json TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal)
);

CREATE INDEX IF NOT EXISTS records_stage_idx ON records(run_id, stage);
CREATE INDEX IF NOT EXISTS findings_stage_idx ON findings(run_id, stage);
`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute}).String() +
		"?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on&_txlock=immediate"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize sqlite schema: %w", err)
	}
	var version int
	err = db.QueryRow(`SELECT version FROM schema_meta LIMIT 1`).Scan(&version)
	if err == sql.ErrNoRows {
		_, err = db.Exec(`INSERT INTO schema_meta(version) VALUES (1)`)
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("record schema version: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
