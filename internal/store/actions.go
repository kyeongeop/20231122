package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"tracecheck/internal/detector"
	"tracecheck/internal/model"
)

var ErrAttemptFinalized = errors.New("attempt is already finalized")

func NewID(prefix string) string {
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return prefix + strings.ToUpper(hex.EncodeToString(buf))
}

func (s *Store) CreateCheck(ctx context.Context, title, source, inputName string, raw []byte) (string, string, error) {
	checkID := "CHK-" + time.Now().UTC().Format("0102") + "-" + NewID("")[0:4]
	attemptID := checkID + "-A01"
	now := time.Now().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO checks (id, title, source, input_name, raw_input, raw_sha256, created_at, status,
			fuzzer_version, fuzzer_execs)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 'libFuzzer / LLVM 20.1.8', 0)`,
		checkID, title, source, inputName, raw, Hash(raw), now); err != nil {
		return "", "", fmt.Errorf("insert check: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO attempts (id, check_id, number, status, started_at, next_actions)
		VALUES (?, ?, 1, 'running', ?, '[]')`, attemptID, checkID, now); err != nil {
		return "", "", fmt.Errorf("insert attempt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audits (id, check_id, attempt_id, event, actor, detail, created_at)
		VALUES (?, ?, ?, 'check.created', 'console', ?, ?)`,
		NewID("AUD-"), checkID, attemptID, fmt.Sprintf("接收 %d B 原始输入。", len(raw)), now); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return checkID, attemptID, nil
}

func (s *Store) AddPendingStep(ctx context.Context, step model.Step) error {
	ev, _ := json.Marshal(step.EvidenceIDs)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO steps (id, attempt_id, position, phase, title, status, started_at, ended_at,
			summary, input_excerpt, output_excerpt, tool, evidence_ids, ambiguous)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
		step.ID, step.AttemptID, step.Position, step.Phase, step.Title, step.Status,
		step.StartedAt.Format(time.RFC3339Nano), step.Summary, step.InputExcerpt,
		step.OutputExcerpt, step.Tool, string(ev), boolInt(step.Ambiguous))
	return err
}

func (s *Store) UpdateStep(ctx context.Context, stepID, status, summary, input, output string, evidenceIDs []string) error {
	ev, _ := json.Marshal(evidenceIDs)
	now := time.Now().Format(time.RFC3339Nano)
	var ended any
	if status == "completed" || status == "cancelled" || status == "failed" {
		ended = now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE steps SET status = ?, summary = ?, input_excerpt = ?, output_excerpt = ?,
		       evidence_ids = ?, ended_at = COALESCE(?, ended_at)
		WHERE id = ?`,
		status, summary, input, output, string(ev), ended, stepID)
	return err
}

func (s *Store) InsertEvidence(ctx context.Context, e model.Evidence) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO evidence
			(id, check_id, attempt_id, step_id, label, kind, sha256, size, content, retained, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.CheckID, e.AttemptID, e.StepID, e.Label, e.Kind, e.SHA256,
		e.Size, []byte(e.Content), boolInt(e.Retained), e.CreatedAt.Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return nil
}

func (s *Store) CompleteAttempt(ctx context.Context, checkID, attemptID string, r detector.Result, evidenceCount int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE checks SET status = 'completed', auto_verdict = ?, auto_label = ?, confidence = ?,
		       auto_summary = ?, ambiguous_rule = ?, ambiguous_note = ?,
		       fuzzer_version = ?, fuzzer_execs = ?, fuzzer_artifact = ?
		WHERE id = ? AND status = 'running'`,
		r.AutoVerdict, r.AutoLabel, r.Confidence, r.Summary, r.AmbiguousRule, r.AmbiguousNote,
		"libFuzzer / LLVM 20.1.8", r.FuzzerExecs, "artifact-"+attemptID, checkID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE attempts SET status = 'completed', ended_at = ?, evidence_count = ?
		WHERE id = ? AND status = 'running'`, now, evidenceCount, attemptID)
	if err != nil {
		return err
	}
	updated, _ := res.RowsAffected()
	if updated == 0 {
		return nil
	}
	for i, f := range r.Findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR REPLACE INTO findings
				(id, check_id, rule, title, severity, confidence, detail, step_id, evidence_id, position)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, checkID, f.Rule, f.Title, f.Severity, f.Confidence, f.Detail,
			f.StepID, f.EvidenceID, i+1,
		); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audits (id, check_id, attempt_id, event, actor, detail, created_at)
		VALUES (?, ?, ?, 'attempt.completed', 'detector-worker', ?, ?)`,
		NewID("AUD-"), checkID, attemptID,
		fmt.Sprintf("%d 项证据封存，自动结论已生成。", evidenceCount), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CancelAttempt(ctx context.Context, checkID, attemptID, actor, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
		UPDATE attempts SET status = 'cancelled', ended_at = ?, cancelled_by = ?, cancel_reason = ?,
		       evidence_count = (SELECT COUNT(*) FROM evidence WHERE attempt_id = ?)
		WHERE id = ? AND status = 'running'`, now, actor, reason, attemptID, attemptID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrAttemptFinalized
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE steps SET status = 'cancelled', ended_at = ?
		WHERE attempt_id = ? AND status IN ('running', 'pending')`, now, attemptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE checks SET status = 'cancelled' WHERE id = ? AND status = 'running'`, checkID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audits (id, check_id, attempt_id, event, actor, detail, created_at)
		VALUES (?, ?, ?, 'attempt.cancelled', ?, ?, ?)`,
		NewID("AUD-"), checkID, attemptID, actor, reason, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FailAttempt(ctx context.Context, checkID, attemptID, code, message string, actions []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Format(time.RFC3339Nano)
	rawActions, _ := json.Marshal(actions)
	res, err := tx.ExecContext(ctx, `
		UPDATE attempts SET status = 'failed', ended_at = ?, error_code = ?, error_message = ?, next_actions = ?
		WHERE id = ? AND status = 'running'`, now, code, message, string(rawActions), attemptID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrAttemptFinalized
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE checks SET status = 'failed' WHERE id = ?`, checkID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audits (id, check_id, attempt_id, event, actor, detail, created_at)
		VALUES (?, ?, ?, 'attempt.failed', 'detector-worker', ?, ?)`,
		NewID("AUD-"), checkID, attemptID, code+": "+message, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConfirmCheck(ctx context.Context, checkID, verdict, label, reviewer, note string) error {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE checks SET human_verdict = ?, human_label = ?, human_reviewer = ?,
		       human_note = ?, human_at = ?
		WHERE id = ?`,
		verdict, label, reviewer, note, now.Format(time.RFC3339Nano), checkID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audits (id, check_id, event, actor, detail, created_at)
		VALUES (?, ?, 'human.confirmed', ?, ?, ?)`,
		NewID("AUD-"), checkID, reviewer, note, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EvidenceByID(ctx context.Context, id string) (*model.Evidence, error) {
	var e model.Evidence
	var content []byte
	var created string
	var retained int
	err := s.db.QueryRowContext(ctx, `
		SELECT id, check_id, attempt_id, step_id, label, kind, sha256, size, content, retained, created_at
		FROM evidence WHERE id = ?`, id).Scan(
		&e.ID, &e.CheckID, &e.AttemptID, &e.StepID, &e.Label, &e.Kind,
		&e.SHA256, &e.Size, &content, &retained, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	e.Content = string(content)
	e.Retained = retained == 1
	e.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return &e, nil
}

func (s *Store) CheckStatus(ctx context.Context, id string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM checks WHERE id = ?`, id).Scan(&status)
	return status, err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
