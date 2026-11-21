package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	baseDir string
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	s := &Store{db: db, baseDir: filepath.Dir(path)}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.seed(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	schema := `
CREATE TABLE IF NOT EXISTS samples (
	id TEXT PRIMARY KEY, case_no TEXT NOT NULL, incident TEXT NOT NULL,
	filename TEXT NOT NULL, extension TEXT NOT NULL, size INTEGER NOT NULL,
	sha256 TEXT NOT NULL, original BLOB NOT NULL, status TEXT NOT NULL,
	severity TEXT NOT NULL, summary TEXT NOT NULL, owner TEXT NOT NULL,
	received_at TEXT NOT NULL, recovered_at TEXT NOT NULL,
	frozen_at TEXT NOT NULL, storage_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	seq INTEGER NOT NULL, phase TEXT NOT NULL, title TEXT NOT NULL,
	status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
	command TEXT NOT NULL, detail TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	step_id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
	mime TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
	created_at TEXT NOT NULL, path TEXT NOT NULL, content BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS conclusions (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	origin TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL,
	detail TEXT NOT NULL, status TEXT NOT NULL, confidence REAL NOT NULL,
	severity TEXT NOT NULL, rule_id TEXT NOT NULL, step_id TEXT NOT NULL,
	evidence_ids TEXT NOT NULL, input_ref TEXT NOT NULL, boundary INTEGER NOT NULL,
	undecidable_reason TEXT NOT NULL, manual_check_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manual_checks (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	conclusion_id TEXT NOT NULL, question TEXT NOT NULL,
	guidance TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT NOT NULL,
	note TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replay_runs (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	attempt INTEGER NOT NULL, started_at TEXT NOT NULL,
	finished_at TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER NOT NULL,
	reproduced INTEGER NOT NULL, total INTEGER NOT NULL,
	crash_hash TEXT NOT NULL, note TEXT NOT NULL, evidence_id TEXT NOT NULL,
	recovered_from_job TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unknown_extensions (
	id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
	tag TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
	data_offset INTEGER NOT NULL, boundary INTEGER NOT NULL,
	registry_status TEXT NOT NULL, parser_action TEXT NOT NULL,
	raw_hex TEXT NOT NULL, evidence_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_sample ON steps(sample_id, seq);
CREATE INDEX IF NOT EXISTS idx_evidence_sample ON evidence(sample_id);
CREATE INDEX IF NOT EXISTS idx_conclusions_sample ON conclusions(sample_id);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
