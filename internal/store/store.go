// Package store persists audit evidence in SQLite so that every crash,
// permission decision and anchor hit can be traced back to the original input.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the evidence database and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS evidence(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_time TEXT NOT NULL,
			case_id TEXT NOT NULL,
			anchor TEXT NOT NULL,
			raw_offset INTEGER NOT NULL,
			cursor INTEGER NOT NULL,
			length INTEGER NOT NULL,
			offset_field INTEGER NOT NULL,
			input_size INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			input_path TEXT NOT NULL,
			permission TEXT NOT NULL,
			decision TEXT NOT NULL,
			parser_mode TEXT NOT NULL,
			err_text TEXT,
			wrapped TEXT,
			log_line TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_anchor ON evidence(anchor);`,
		`CREATE TABLE IF NOT EXISTS permission_decisions(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_time TEXT NOT NULL,
			case_id TEXT NOT NULL,
			anchor TEXT NOT NULL,
			principal TEXT NOT NULL,
			granted INTEGER NOT NULL,
			reason TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS anchor_hits(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			case_id TEXT NOT NULL,
			anchor TEXT NOT NULL,
			cursor INTEGER NOT NULL,
			UNIQUE(case_id, anchor)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}
