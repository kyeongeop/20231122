package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	caseID string
}

func openStore(path, caseID string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	store := &Store{db: db, caseID: caseID}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.seed(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  target TEXT NOT NULL,
  toolchain TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  label TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  media_type TEXT NOT NULL,
  content TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  origin TEXT NOT NULL,
  immutable INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  sequence INTEGER NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  status TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  evidence_id TEXT,
  command TEXT NOT NULL DEFAULT '',
  output TEXT NOT NULL DEFAULT '',
  refs_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  disposition TEXT NOT NULL,
  refs_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  decision TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  refs_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS followups (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  title TEXT NOT NULL,
  reason TEXT NOT NULL,
  commands_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replays (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  attempt INTEGER NOT NULL,
  status TEXT NOT NULL,
  command TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  exit_code INTEGER NOT NULL,
  stdout TEXT NOT NULL DEFAULT '',
  stderr TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_steps_case_seq ON steps(case_id, sequence);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_replays_case_attempt ON replays(case_id, attempt);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func (s *Store) caseExists() (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM cases WHERE id = ?`, s.caseID).Scan(&count)
	return count > 0, err
}

func (s *Store) loadCaseDetail() (CaseDetail, error) {
	var detail CaseDetail
	detail.ServerTime = nowISO()
	err := s.db.QueryRow(`
SELECT id, title, status, severity, summary, target, toolchain, created_at, updated_at
FROM cases WHERE id = ?`, s.caseID).Scan(
		&detail.Case.ID, &detail.Case.Title, &detail.Case.Status, &detail.Case.Severity,
		&detail.Case.Summary, &detail.Case.Target, &detail.Case.Toolchain,
		&detail.Case.CreatedAt, &detail.Case.UpdatedAt,
	)
	if err != nil {
		return detail, fmt.Errorf("load case: %w", err)
	}
	if detail.Evidence, err = s.loadEvidence(); err != nil {
		return detail, err
	}
	if detail.Steps, err = s.loadSteps(); err != nil {
		return detail, err
	}
	if detail.Findings, err = s.loadFindings(); err != nil {
		return detail, err
	}
	if detail.Reviews, err = s.loadReviews(); err != nil {
		return detail, err
	}
	if detail.Followups, err = s.loadFollowups(); err != nil {
		return detail, err
	}
	if detail.Replays, err = s.loadReplays(); err != nil {
		return detail, err
	}
	detail.Revision = int64(len(detail.Evidence) + len(detail.Steps) + len(detail.Findings) +
		len(detail.Reviews) + len(detail.Followups) + len(detail.Replays))
	return detail, nil
}

func (s *Store) loadEvidence() ([]Evidence, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, label, kind, sha256, size, media_type, content, captured_at, origin, immutable
FROM evidence WHERE case_id = ?
ORDER BY CASE id
  WHEN 'EV-RAW' THEN 0
  WHEN 'EV-FAIL' THEN 1
  WHEN 'EV-DECODE' THEN 2
  WHEN 'EV-LEGACY' THEN 3
  WHEN 'EV-HARDENED' THEN 4
  ELSE 5
END, id`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Evidence{}
	for rows.Next() {
		var item Evidence
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Label, &item.Kind, &item.SHA256,
			&item.Size, &item.MediaType, &item.Content, &item.CapturedAt, &item.Origin,
			&item.Immutable); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadSteps() ([]Step, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, sequence, kind, title, detail, status, occurred_at, evidence_id,
       command, output, refs_json
FROM steps WHERE case_id = ? ORDER BY sequence`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Step{}
	for rows.Next() {
		var item Step
		var evidenceID sql.NullString
		var refsJSON string
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Sequence, &item.Kind, &item.Title,
			&item.Detail, &item.Status, &item.OccurredAt, &evidenceID, &item.Command,
			&item.Output, &refsJSON); err != nil {
			return nil, err
		}
		item.EvidenceID = evidenceID.String
		item.Refs = decodeStrings(refsJSON)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadFindings() ([]Finding, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, title, detail, severity, confidence, disposition, refs_json, created_at
FROM findings WHERE case_id = ? ORDER BY id`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Finding{}
	for rows.Next() {
		var item Finding
		var refsJSON string
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Title, &item.Detail, &item.Severity,
			&item.Confidence, &item.Disposition, &refsJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Refs = decodeStrings(refsJSON)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadReviews() ([]Review, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, decision, reviewer, note, refs_json, created_at
FROM reviews WHERE case_id = ? ORDER BY created_at DESC`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Review{}
	for rows.Next() {
		var item Review
		var refsJSON string
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Decision, &item.Reviewer,
			&item.Note, &refsJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Refs = decodeStrings(refsJSON)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadFollowups() ([]Followup, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, title, reason, commands_json, status, owner, created_at
FROM followups WHERE case_id = ? ORDER BY id`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Followup{}
	for rows.Next() {
		var item Followup
		var commandsJSON string
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Title, &item.Reason, &commandsJSON,
			&item.Status, &item.Owner, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Commands = decodeStrings(commandsJSON)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadReplays() ([]Replay, error) {
	rows, err := s.db.Query(`
SELECT id, case_id, attempt, status, command, started_at, finished_at, exit_code, stdout, stderr
FROM replays WHERE case_id = ? ORDER BY attempt DESC`, s.caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Replay{}
	for rows.Next() {
		var item Replay
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Attempt, &item.Status, &item.Command,
			&item.StartedAt, &item.FinishedAt, &item.ExitCode, &item.Stdout, &item.Stderr); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func decodeStrings(raw string) []string {
	var values []string
	if strings.TrimSpace(raw) == "" {
		return values
	}
	_ = json.Unmarshal([]byte(raw), &values)
	return values
}

func encodeStrings(values []string) string {
	if values == nil {
		values = []string{}
	}
	raw, _ := json.Marshal(values)
	return string(raw)
}
