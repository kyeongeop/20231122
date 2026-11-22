package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type Summary struct {
	ID         string `json:"id"`
	CaseID     string `json:"caseId"`
	Label      string `json:"label"`
	Title      string `json:"title"`
	CapturedAt string `json:"capturedAt"`
	State      string `json:"state"`
	Verdict    string `json:"verdict"`
	ReplayOf   string `json:"replayOf,omitempty"`
}

func Open(path string) (*Store, error) {
	dsn := path + "?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.seed(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS audits (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  label TEXT NOT NULL,
  title TEXT NOT NULL,
  method TEXT NOT NULL,
  target TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  source TEXT NOT NULL,
  state TEXT NOT NULL,
  verdict TEXT NOT NULL,
  replay_of TEXT,
  boundary_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  kind TEXT NOT NULL,
  mime TEXT NOT NULL,
  content TEXT NOT NULL,
  captured_bytes INTEGER NOT NULL,
  expected_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  immutable INTEGER NOT NULL,
  redactions INTEGER NOT NULL,
  note TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT NOT NULL,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  step_key TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  detail TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  evidence_artifact_id TEXT NOT NULL DEFAULT '',
  evidence_start INTEGER NOT NULL DEFAULT 0,
  evidence_end INTEGER NOT NULL DEFAULT 0,
  evidence_excerpt TEXT NOT NULL DEFAULT '',
  evidence_hash TEXT NOT NULL DEFAULT '',
  evidence_note TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (audit_id, id)
);
CREATE TABLE IF NOT EXISTS conclusions (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  sort_order INTEGER NOT NULL,
  code TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  step_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL DEFAULT '',
  start_offset INTEGER NOT NULL DEFAULT 0,
  end_offset INTEGER NOT NULL DEFAULT 0,
  excerpt TEXT NOT NULL DEFAULT '',
  evidence_hash TEXT NOT NULL DEFAULT '',
  evidence_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS replays (
  id TEXT PRIMARY KEY,
  truncated_audit_id TEXT NOT NULL REFERENCES audits(id),
  replay_audit_id TEXT NOT NULL REFERENCES audits(id),
  recovered_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  recovered_bytes INTEGER NOT NULL,
  seam_offset INTEGER NOT NULL,
  seam_verified INTEGER NOT NULL,
  note TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_audit ON steps(audit_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_conclusions_audit ON conclusions(audit_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_artifacts_audit ON artifacts(audit_id);
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) seed(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audits").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	items := SeedAudits()
	for _, item := range items {
		if err := insertAudit(ctx, tx, item); err != nil {
			return fmt.Errorf("seed %s: %w", item.ID, err)
		}
	}
	seenReplay := map[string]bool{}
	for _, item := range items {
		if item.Replay == nil || seenReplay[item.Replay.ID] {
			continue
		}
		seenReplay[item.Replay.ID] = true
		if _, err := tx.ExecContext(ctx, `
INSERT INTO replays (id, truncated_audit_id, replay_audit_id, recovered_artifact_id,
  recovered_bytes, seam_offset, seam_verified, note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			item.Replay.ID, item.Replay.TruncatedAuditID, item.Replay.ReplayAuditID,
			item.Replay.RecoveredArtifactID, item.Replay.RecoveredBytes, item.Replay.SeamOffset,
			item.Replay.SeamVerified, item.Replay.Note); err != nil {
			return fmt.Errorf("seed replay %s: %w", item.Replay.ID, err)
		}
	}
	return tx.Commit()
}

func insertAudit(ctx context.Context, tx *sql.Tx, item Audit) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO audits (id, case_id, label, title, method, target, captured_at, source, state, verdict, replay_of, boundary_note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.CaseID, item.Label, item.Title, item.Method, item.Target,
		item.CapturedAt, item.Source, item.State, item.Verdict, nullString(item.ReplayOf), item.BoundaryNote)
	if err != nil {
		return err
	}
	for _, artifact := range item.Artifacts {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO artifacts (id, audit_id, label, kind, mime, content, captured_bytes, expected_bytes, sha256, immutable, redactions, note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			artifact.ID, artifact.AuditID, artifact.Label, artifact.Kind, artifact.MIME, artifact.Content,
			artifact.CapturedBytes, artifact.ExpectedBytes, artifact.SHA256, artifact.Immutable,
			artifact.Redactions, artifact.Note); err != nil {
			return err
		}
	}
	for _, step := range item.Steps {
		evidence := Evidence{}
		if step.Evidence != nil {
			evidence = *step.Evidence
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO steps (id, audit_id, ordinal, step_key, label, status, summary, detail, duration_ms,
  evidence_artifact_id, evidence_start, evidence_end, evidence_excerpt, evidence_hash, evidence_note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			step.ID, item.ID, step.Ordinal, step.Key, step.Label, step.Status, step.Summary, step.Detail,
			step.Duration, evidence.ArtifactID, evidence.Start, evidence.End, evidence.Excerpt, evidence.Hash,
			evidence.Note); err != nil {
			return err
		}
	}
	for i, conclusion := range item.Conclusions {
		evidence := conclusion.Evidence
		if _, err := tx.ExecContext(ctx, `
INSERT INTO conclusions (id, audit_id, sort_order, code, status, severity, title, detail, step_id,
  artifact_id, start_offset, end_offset, excerpt, evidence_hash, evidence_note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			conclusion.ID, item.ID, i, conclusion.Code, conclusion.Status, conclusion.Severity,
			conclusion.Title, conclusion.Detail, conclusion.StepID, evidence.ArtifactID,
			evidence.Start, evidence.End, evidence.Excerpt, evidence.Hash, evidence.Note); err != nil {
			return err
		}
	}
	return nil
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Store) List(ctx context.Context) ([]Summary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, case_id, label, title, captured_at, state, verdict, COALESCE(replay_of, '')
FROM audits ORDER BY captured_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Summary, 0, 2)
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Label, &item.Title, &item.CapturedAt,
			&item.State, &item.Verdict, &item.ReplayOf); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (Audit, error) {
	item := Audit{}
	var replayOf sql.NullString
	err := s.db.QueryRowContext(ctx, `
SELECT id, case_id, label, title, method, target, captured_at, source, state, verdict,
  replay_of, boundary_note FROM audits WHERE id = ?`, id).
		Scan(&item.ID, &item.CaseID, &item.Label, &item.Title, &item.Method, &item.Target,
			&item.CapturedAt, &item.Source, &item.State, &item.Verdict, &replayOf, &item.BoundaryNote)
	if errors.Is(err, sql.ErrNoRows) {
		return Audit{}, ErrNotFound
	}
	if err != nil {
		return Audit{}, err
	}
	item.ReplayOf = replayOf.String
	if item.Artifacts, err = s.loadArtifacts(ctx, id); err != nil {
		return Audit{}, err
	}
	if item.Steps, err = s.loadSteps(ctx, id); err != nil {
		return Audit{}, err
	}
	if item.Conclusions, err = s.loadConclusions(ctx, id); err != nil {
		return Audit{}, err
	}
	if item.Replay, err = s.loadReplay(ctx, id); err != nil {
		return Audit{}, err
	}
	for i := range item.Steps {
		step := &item.Steps[i]
		switch step.Status {
		case StatusPass:
			item.Counts.Pass++
		case StatusFail:
			item.Counts.Fail++
			if item.FirstError == nil {
				item.FirstError = step
			}
		case StatusUndecided:
			item.Counts.Undecided++
			if item.Boundary == nil {
				item.Boundary = step
			}
		case StatusBlocked:
			item.Counts.Blocked++
		case StatusTruncated:
			item.Counts.Truncated++
			if item.FirstError == nil {
				item.FirstError = step
			}
		}
	}
	return item, nil
}

var ErrNotFound = errors.New("audit not found")

func (s *Store) loadArtifacts(ctx context.Context, auditID string) ([]Artifact, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, audit_id, label, kind, mime, content, captured_bytes, expected_bytes, sha256,
  immutable, redactions, note FROM artifacts WHERE audit_id = ? ORDER BY rowid`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Artifact
	for rows.Next() {
		var item Artifact
		if err := rows.Scan(&item.ID, &item.AuditID, &item.Label, &item.Kind, &item.MIME, &item.Content,
			&item.CapturedBytes, &item.ExpectedBytes, &item.SHA256, &item.Immutable,
			&item.Redactions, &item.Note); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadSteps(ctx context.Context, auditID string) ([]Step, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ordinal, step_key, label, status, summary, detail, duration_ms,
  evidence_artifact_id, evidence_start, evidence_end, evidence_excerpt, evidence_hash, evidence_note
FROM steps WHERE audit_id = ? ORDER BY ordinal`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Step
	for rows.Next() {
		var item Step
		evidence := Evidence{}
		if err := rows.Scan(&item.ID, &item.Ordinal, &item.Key, &item.Label, &item.Status,
			&item.Summary, &item.Detail, &item.Duration, &evidence.ArtifactID, &evidence.Start,
			&evidence.End, &evidence.Excerpt, &evidence.Hash, &evidence.Note); err != nil {
			return nil, err
		}
		if evidence.ArtifactID != "" {
			item.Evidence = &evidence
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadConclusions(ctx context.Context, auditID string) ([]Conclusion, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, code, status, severity, title, detail, step_id, artifact_id, start_offset,
  end_offset, excerpt, evidence_hash, evidence_note
FROM conclusions WHERE audit_id = ? ORDER BY sort_order`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Conclusion
	for rows.Next() {
		var item Conclusion
		if err := rows.Scan(&item.ID, &item.Code, &item.Status, &item.Severity, &item.Title,
			&item.Detail, &item.StepID, &item.Evidence.ArtifactID, &item.Evidence.Start,
			&item.Evidence.End, &item.Evidence.Excerpt, &item.Evidence.Hash,
			&item.Evidence.Note); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) loadReplay(ctx context.Context, auditID string) (*Replay, error) {
	var item Replay
	var verified bool
	err := s.db.QueryRowContext(ctx, `
SELECT id, truncated_audit_id, replay_audit_id, recovered_artifact_id, recovered_bytes,
  seam_offset, seam_verified, note FROM replays
WHERE truncated_audit_id = ? OR replay_audit_id = ? LIMIT 1`, auditID, auditID).
		Scan(&item.ID, &item.TruncatedAuditID, &item.ReplayAuditID, &item.RecoveredArtifactID,
			&item.RecoveredBytes, &item.SeamOffset, &verified, &item.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.SeamVerified = verified
	return &item, nil
}

func (s *Store) Stats(ctx context.Context) (map[string]any, error) {
	var audits, steps, conclusions int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audits").Scan(&audits); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM steps").Scan(&steps); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM conclusions").Scan(&conclusions); err != nil {
		return nil, err
	}
	return map[string]any{
		"engine": "Go " + runtime.Version(), "storage": "SQLite", "fuzz": "libFuzzer",
		"audits": audits, "steps": steps, "conclusions": conclusions,
		"checkedAt": time.Now().UTC().Format(time.RFC3339),
	}, nil
}
