// Package store persists runs, inputs, processing steps, conclusions,
// evidence and follow-up actions in SQLite so the report page can trace
// every conclusion back to its original input and processing steps.
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

// Open opens (and creates if needed) the database at path.
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

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// CreateRun inserts a new run in "running" state and returns its id.
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

// AddEvent appends a lifecycle event to a run.
func (s *Store) AddEvent(runID int64, kind, detail string) error {
	var seq int
	err := s.db.QueryRow(
		`SELECT COALESCE(MAX(seq),0)+1 FROM run_events WHERE run_id=?`, runID).Scan(&seq)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO run_events (run_id, seq, kind, detail, at) VALUES (?,?,?,?,?)`,
		runID, seq, kind, detail, now())
	return err
}

// FinishRun sets the terminal status of a run and records an event.
func (s *Store) FinishRun(runID int64, status, detail string) error {
	if _, err := s.db.Exec(
		`UPDATE runs SET status=?, ended_at=? WHERE id=?`, status, now(), runID); err != nil {
		return err
	}
	kind := "finished"
	if status == "cancelled" {
		kind = "cancelled"
	} else if status == "failed" {
		kind = "failed"
	}
	return s.AddEvent(runID, kind, detail)
}

// RecordInput stores an original input together with its processing steps.
func (s *Store) RecordInput(runID int64, label, sha256, content string,
	steps []struct{ Name, Detail string }) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO inputs (run_id, label, sha256, content) VALUES (?,?,?,?)`,
		runID, label, sha256, content)
	if err != nil {
		return 0, err
	}
	inputID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for i, st := range steps {
		if _, err := s.db.Exec(
			`INSERT INTO steps (input_id, seq, name, detail) VALUES (?,?,?,?)`,
			inputID, i+1, st.Name, st.Detail); err != nil {
			return 0, err
		}
	}
	return inputID, nil
}

// AddConclusion stores a conclusion (automated or manual) for an input.
func (s *Store) AddConclusion(inputID int64, kind, verdict, rationale, createdBy string) error {
	_, err := s.db.Exec(
		`INSERT INTO conclusions (input_id, kind, verdict, rationale, created_by, created_at)
		 VALUES (?,?,?,?,?,?)`,
		inputID, kind, verdict, rationale, createdBy, now())
	return err
}

// AddEvidence stores a key evidence blob for an input.
func (s *Store) AddEvidence(inputID int64, label, content string) error {
	_, err := s.db.Exec(
		`INSERT INTO evidence (input_id, label, content) VALUES (?,?,?)`,
		inputID, label, content)
	return err
}

// AddNextAction stores an actionable follow-up for a run and/or input.
func (s *Store) AddNextAction(runID, inputID int64, action, reason string) error {
	_, err := s.db.Exec(
		`INSERT INTO next_actions (run_id, input_id, action, reason) VALUES (?,?,?,?)`,
		nullInt(runID), nullInt(inputID), action, reason)
	return err
}

func nullInt(v int64) any {
	if v <= 0 {
		return nil
	}
	return v
}
