// Package store persists fuzz runs, original inputs, anchor offsets,
// processing steps, findings, permission verdicts, evidence and follow-up
// actions in SQLite, so every conclusion can be traced to a concrete
// timestamp and an original byte offset.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// Store wraps the SQLite handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path.
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

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// Reset drops every evidence table and re-applies the schema, making seed
// runs idempotent. The preserved files under evidence/raw are untouched.
func (s *Store) Reset() error {
	tables := []string{
		"next_actions", "evidence", "conclusions", "findings",
		"steps", "anchors", "inputs", "run_events", "runs",
	}
	for _, t := range tables {
		if _, err := s.db.Exec("DROP TABLE IF EXISTS " + t); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(schema)
	return err
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// CreateRun inserts a run in "running" state and records a started event.
func (s *Store) CreateRun(name, tool string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO runs (name, tool, status, started_at) VALUES (?,?,?,?)`,
		name, tool, "running", now())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, s.AddEvent(id, "started", "run created")
}

// AddEvent appends a lifecycle event with a monotonically increasing seq.
func (s *Store) AddEvent(runID int64, kind, detail string) error {
	var seq int
	if err := s.db.QueryRow(
		`SELECT COALESCE(MAX(seq),0)+1 FROM run_events WHERE run_id=?`, runID).Scan(&seq); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO run_events (run_id, seq, kind, detail, at) VALUES (?,?,?,?,?)`,
		runID, seq, kind, detail, now())
	return err
}

// FinishRun sets the terminal status and records the matching event.
func (s *Store) FinishRun(runID int64, status, detail string) error {
	if _, err := s.db.Exec(
		`UPDATE runs SET status=?, ended_at=? WHERE id=?`, status, now(), runID); err != nil {
		return err
	}
	kind := "finished"
	switch status {
	case "cancelled":
		kind = "cancelled"
	case "failed":
		kind = "failed"
	}
	return s.AddEvent(runID, kind, detail)
}
