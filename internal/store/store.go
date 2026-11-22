package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"tracecheck/internal/model"
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	s := &Store{db: db}
	if err := s.seed(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) ListChecks(ctx context.Context) ([]model.Check, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, source, input_name, raw_sha256, created_at, status,
		       auto_verdict, auto_label, confidence, human_verdict, human_label
		FROM checks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var checks []model.Check
	for rows.Next() {
		var c model.Check
		var created string
		if err := rows.Scan(&c.ID, &c.Title, &c.Source, &c.InputName, &c.RawSHA256, &created,
			&c.Status, &c.AutoVerdict, &c.AutoLabel, &c.Confidence, &c.HumanVerdict, &c.HumanLabel); err != nil {
			return nil, err
		}
		c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

func (s *Store) GetCheck(ctx context.Context, id string) (*model.Check, error) {
	var c model.Check
	var raw []byte
	var created, humanAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, source, input_name, raw_input, raw_sha256, created_at, status,
		       auto_verdict, auto_label, confidence, auto_summary, ambiguous_rule, ambiguous_note,
		       human_verdict, human_label, human_reviewer, human_note, COALESCE(human_at,''),
		       fuzzer_version, fuzzer_execs, fuzzer_artifact
		FROM checks WHERE id = ?`, id).Scan(
		&c.ID, &c.Title, &c.Source, &c.InputName, &raw, &c.RawSHA256, &created, &c.Status,
		&c.AutoVerdict, &c.AutoLabel, &c.Confidence, &c.AutoSummary, &c.AmbiguousRule, &c.AmbiguousNote,
		&c.HumanVerdict, &c.HumanLabel, &c.HumanReviewer, &c.HumanNote, &humanAt,
		&c.FuzzerVersion, &c.FuzzerExecs, &c.FuzzerArtifact,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	c.RawInput = string(raw)
	c.InputSize = int64(len(raw))
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if humanAt != "" {
		t, _ := time.Parse(time.RFC3339Nano, humanAt)
		c.HumanAt = &t
	}
	if c.Attempts, err = s.loadAttempts(ctx, id); err != nil {
		return nil, err
	}
	if c.Evidence, err = s.loadEvidence(ctx, id); err != nil {
		return nil, err
	}
	if c.Findings, err = s.loadFindings(ctx, id); err != nil {
		return nil, err
	}
	if c.Audits, err = s.loadAudits(ctx, id); err != nil {
		return nil, err
	}
	for i := len(c.Attempts) - 1; i >= 0; i-- {
		if c.Attempts[i].Status == "completed" {
			c.SelectedAttempt = &c.Attempts[i]
			break
		}
	}
	if c.SelectedAttempt == nil && len(c.Attempts) > 0 {
		c.SelectedAttempt = &c.Attempts[0]
	}
	c.Normalized = normalizeForDisplay(c.RawInput)
	return &c, nil
}

func (s *Store) loadAttempts(ctx context.Context, checkID string) ([]model.Attempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, check_id, number, status, started_at, COALESCE(ended_at,''),
		       cancelled_by, cancel_reason, error_code, error_message, next_actions, evidence_count
		FROM attempts WHERE check_id = ? ORDER BY number DESC`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attempts []model.Attempt
	for rows.Next() {
		var a model.Attempt
		var started, ended, actions string
		if err := rows.Scan(&a.ID, &a.CheckID, &a.Number, &a.Status, &started, &ended,
			&a.CancelledBy, &a.CancelReason, &a.ErrorCode, &a.ErrorMessage, &actions, &a.EvidenceCount); err != nil {
			return nil, err
		}
		a.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if ended != "" {
			t, _ := time.Parse(time.RFC3339Nano, ended)
			a.EndedAt = &t
		}
		_ = json.Unmarshal([]byte(actions), &a.NextActions)
		if a.Steps, err = s.loadSteps(ctx, a.ID); err != nil {
			return nil, err
		}
		attempts = append(attempts, a)
	}
	return attempts, rows.Err()
}

func (s *Store) loadSteps(ctx context.Context, attemptID string) ([]model.Step, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, attempt_id, position, phase, title, status, started_at, COALESCE(ended_at,''),
		       summary, input_excerpt, output_excerpt, tool, evidence_ids, ambiguous
		FROM steps WHERE attempt_id = ? ORDER BY position`, attemptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []model.Step
	for rows.Next() {
		var st model.Step
		var started, ended, evIDs string
		var ambiguous int
		if err := rows.Scan(&st.ID, &st.AttemptID, &st.Position, &st.Phase, &st.Title, &st.Status,
			&started, &ended, &st.Summary, &st.InputExcerpt, &st.OutputExcerpt, &st.Tool, &evIDs, &ambiguous); err != nil {
			return nil, err
		}
		st.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if ended != "" {
			t, _ := time.Parse(time.RFC3339Nano, ended)
			st.EndedAt = &t
		}
		st.Ambiguous = ambiguous == 1
		_ = json.Unmarshal([]byte(evIDs), &st.EvidenceIDs)
		steps = append(steps, st)
	}
	return steps, rows.Err()
}

func (s *Store) loadEvidence(ctx context.Context, checkID string) ([]model.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, check_id, attempt_id, step_id, label, kind, sha256, size, content, retained, created_at
		FROM evidence WHERE check_id = ? ORDER BY created_at`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.Evidence
	for rows.Next() {
		var e model.Evidence
		var content []byte
		var created string
		var retained int
		if err := rows.Scan(&e.ID, &e.CheckID, &e.AttemptID, &e.StepID, &e.Label, &e.Kind,
			&e.SHA256, &e.Size, &content, &retained, &created); err != nil {
			return nil, err
		}
		e.Content = string(content)
		e.Retained = retained == 1
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		items = append(items, e)
	}
	return items, rows.Err()
}

func (s *Store) loadFindings(ctx context.Context, checkID string) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, rule, title, severity, confidence, detail, step_id, evidence_id
		FROM findings WHERE check_id = ? ORDER BY position`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.ID, &f.Rule, &f.Title, &f.Severity, &f.Confidence,
			&f.Detail, &f.StepID, &f.EvidenceID); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (s *Store) loadAudits(ctx context.Context, checkID string) ([]model.Audit, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, check_id, attempt_id, event, actor, detail, created_at
		FROM audits WHERE check_id = ? ORDER BY created_at DESC`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var audits []model.Audit
	for rows.Next() {
		var a model.Audit
		var created string
		if err := rows.Scan(&a.ID, &a.CheckID, &a.AttemptID, &a.Event, &a.Actor, &a.Detail, &created); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		audits = append(audits, a)
	}
	return audits, rows.Err()
}

func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeForDisplay(raw string) string {
	return raw
}
