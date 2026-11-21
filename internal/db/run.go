package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"auditfix/internal/model"
)

func (s *Store) InsertRun(ctx context.Context, run model.Run) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO runs(
			run_id, case_id, harness_sha256, harness_path, timeout_ms, fuzz_args,
			status, created_at,
			started_at, finished_at, requested_limit, completed_count,
			attempt_count, resumed_count, schema_version
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		run.RunID, run.CaseID, run.HarnessSHA256, run.HarnessPath,
		run.TimeoutMS, run.FuzzArgs, run.Status,
		run.CreatedAt, run.StartedAt, run.FinishedAt, run.RequestedLimit,
		run.CompletedCount, run.AttemptCount, run.ResumedCount, run.SchemaVersion)
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	return nil
}

func (s *Store) GetRun(ctx context.Context, runID string) (model.Run, error) {
	var run model.Run
	err := s.db.QueryRowContext(ctx, `
		SELECT run_id, case_id, harness_sha256, harness_path, timeout_ms, fuzz_args,
			status, created_at,
			started_at, finished_at, requested_limit, completed_count,
			attempt_count, resumed_count, schema_version
		FROM runs WHERE run_id = ?`, runID).Scan(
		&run.RunID, &run.CaseID, &run.HarnessSHA256, &run.HarnessPath,
		&run.TimeoutMS, &run.FuzzArgs,
		&run.Status, &run.CreatedAt, &run.StartedAt, &run.FinishedAt,
		&run.RequestedLimit, &run.CompletedCount, &run.AttemptCount,
		&run.ResumedCount, &run.SchemaVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Run{}, fmt.Errorf("run %q: %w", runID, ErrNotFound)
	}
	if err != nil {
		return model.Run{}, err
	}
	return run, nil
}

func (s *Store) ListRuns(ctx context.Context, caseID string) ([]model.Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT run_id, case_id, harness_sha256, harness_path, timeout_ms, fuzz_args,
			status, created_at,
			started_at, finished_at, requested_limit, completed_count,
			attempt_count, resumed_count, schema_version
		FROM runs WHERE case_id = ? ORDER BY created_at, run_id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Run
	for rows.Next() {
		var run model.Run
		if err := rows.Scan(&run.RunID, &run.CaseID, &run.HarnessSHA256,
			&run.HarnessPath, &run.TimeoutMS, &run.FuzzArgs,
			&run.Status, &run.CreatedAt, &run.StartedAt,
			&run.FinishedAt, &run.RequestedLimit, &run.CompletedCount,
			&run.AttemptCount, &run.ResumedCount, &run.SchemaVersion); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (s *Store) UpdateRunStatus(ctx context.Context, runID, status, finishedAt string,
	completed, attempts, resumed int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE runs SET status=?, finished_at=?, completed_count=?,
			attempt_count=?, resumed_count=? WHERE run_id=?`,
		status, finishedAt, completed, attempts, resumed, runID)
	return err
}

func (s *Store) MarkRunningAttemptsInterrupted(ctx context.Context, runID, finishedAt string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE attempts SET status='interrupted', finished_at=?,
			error='process restarted before completion'
		WHERE run_id = ? AND status = 'running'`, finishedAt, runID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) NextAttemptNo(ctx context.Context, runID, sampleID string) (int, error) {
	var next int
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(attempt_no), 0) + 1 FROM attempts
		WHERE run_id = ? AND sample_id = ?`, runID, sampleID).Scan(&next)
	return next, err
}

func (s *Store) InsertRunningAttempt(ctx context.Context, attempt model.Attempt) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO attempts(
			run_id, sample_id, attempt_no, status, started_at, finished_at,
			exit_code, signal, timed_out, stdout, stderr, stdout_sha256, stderr_sha256,
			harness_output, result_json, error, evidence_sha256
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		attempt.RunID, attempt.SampleID, attempt.AttemptNo, "running",
		attempt.StartedAt, "", 0, 0, 0, "", "", "", "", "", "", "",
		attempt.EvidenceSHA256)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinishAttempt(ctx context.Context, a model.Attempt) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE attempts SET status=?, finished_at=?, exit_code=?, signal=?,
			timed_out=?, stdout=?, stderr=?, stdout_sha256=?, stderr_sha256=?, harness_output=?,
			result_json=?, error=?, evidence_sha256=? WHERE attempt_id=?`,
		a.Status, a.FinishedAt, a.ExitCode, a.Signal, boolInt(a.TimedOut),
		a.Stdout, a.Stderr, a.StdoutSHA256, a.StderrSHA256, a.HarnessOutput, a.ResultJSON,
		a.Error, a.EvidenceSHA256, a.AttemptID)
	return err
}

func (s *Store) ListAttempts(ctx context.Context, runID string) ([]model.Attempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.attempt_id, a.run_id, a.sample_id, s.sample_index, a.attempt_no,
			a.status, a.started_at, a.finished_at, a.exit_code, a.signal,
			a.timed_out, a.stdout, a.stderr, a.stdout_sha256, a.stderr_sha256, a.harness_output,
			a.result_json, a.error, a.evidence_sha256
		FROM attempts a JOIN samples s ON s.sample_id = a.sample_id
		WHERE a.run_id = ?
		ORDER BY s.sample_index, a.attempt_no`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Attempt
	for rows.Next() {
		var a model.Attempt
		var timedOut int
		if err := rows.Scan(&a.AttemptID, &a.RunID, &a.SampleID, &a.SampleIndex,
			&a.AttemptNo, &a.Status, &a.StartedAt, &a.FinishedAt, &a.ExitCode,
			&a.Signal, &timedOut, &a.Stdout, &a.Stderr, &a.StdoutSHA256, &a.StderrSHA256,
			&a.HarnessOutput, &a.ResultJSON, &a.Error, &a.EvidenceSHA256); err != nil {
			return nil, err
		}
		a.TimedOut = intBool(timedOut)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CountCompletedSamples(ctx context.Context, runID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT sample_id) FROM attempts
		WHERE run_id = ? AND status IN ('complete','crash','timeout')`, runID).Scan(&count)
	return count, err
}

func (s *Store) CountAttempts(ctx context.Context, runID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attempts WHERE run_id = ?`, runID).Scan(&count)
	return count, err
}
