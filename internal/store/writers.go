package store

import (
	"database/sql"
	"time"
)

// Log appends one structured log line to the run.
func (s *Store) Log(runID int64, level, layer, message string) error {
	_, err := s.db.Exec(`INSERT INTO logs(run_id, ts, level, layer, message) VALUES(?,?,?,?,?)`,
		runID, time.Now().UTC().Format(time.RFC3339Nano), level, layer, message)
	return err
}

// ParseResult records one parse attempt at one layer.
func (s *Store) ParseResult(runID int64, caseName, layer, profile string, idx int,
	status, method, path string, consumed int, detail string) error {
	_, err := s.db.Exec(`INSERT INTO parse_results
	  (run_id, case_name, layer, profile, idx, status, method, path, consumed, detail)
	  VALUES(?,?,?,?,?,?,?,?,?,?)`,
		runID, caseName, layer, profile, idx, status, method, path, consumed, detail)
	return err
}

// Smuggled records one smuggled request with its preserved evidence file.
func (s *Store) Smuggled(runID int64, caseName, method, path, sha256, evidencePath string) error {
	_, err := s.db.Exec(`INSERT INTO smuggled_requests
	  (run_id, case_name, method, path, sha256, evidence_path) VALUES(?,?,?,?,?,?)`,
		runID, caseName, method, path, sha256, evidencePath)
	return err
}

// Permission records one authorization decision.
func (s *Store) Permission(runID int64, caseName, path, identity, decision, reason string) error {
	_, err := s.db.Exec(`INSERT INTO permissions
	  (run_id, case_name, path, identity, decision, reason) VALUES(?,?,?,?,?,?)`,
		runID, caseName, path, identity, decision, reason)
	return err
}

// Evidence records a preserved artifact (hash + bounded snippet).
func (s *Store) Evidence(runID int64, caseName, kind, sha256 string, size int, snippet string) error {
	_, err := s.db.Exec(`INSERT INTO evidence
	  (run_id, case_name, kind, sha256, size, snippet) VALUES(?,?,?,?,?,?)`,
		runID, caseName, kind, sha256, size, snippet)
	return err
}

// Boundary records one boundary sample (before/after a limit).
func (s *Store) Boundary(runID int64, parameter string, limitValue int64, side string,
	size int, status, detail string) error {
	_, err := s.db.Exec(`INSERT INTO boundaries
	  (run_id, parameter, limit_value, side, size, status, detail) VALUES(?,?,?,?,?,?,?)`,
		runID, parameter, limitValue, side, size, status, detail)
	return err
}

// Query returns rows for the report: generic helper for the CLI.
func (s *Store) Query(query string, args ...any) (*sql.Rows, error) {
	return s.db.Query(query, args...)
}
