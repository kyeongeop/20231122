package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"idorfix/internal/domain"
)

// NextAttempt returns the next attempt number for a sample.
func (s *Store) NextAttempt(ctx context.Context, sampleID string) (int, error) {
	var maxAttempt sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(attempt) FROM runs WHERE sample_id = ?`, sampleID).Scan(&maxAttempt)
	if err != nil {
		return 0, err
	}
	return int(maxAttempt.Int64) + 1, nil
}

// NextRunSeq returns the global run ordering counter.
func (s *Store) NextRunSeq(ctx context.Context) (int, error) {
	var maxSeq sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(seq) FROM runs`).Scan(&maxSeq); err != nil {
		return 0, err
	}
	return int(maxSeq.Int64) + 1, nil
}

// InsertPendingRun persists a run in PENDING state before analysis starts.
// This write-ahead design is what makes mid-exit recovery possible.
func (s *Store) InsertPendingRun(ctx context.Context, run *domain.Run, seq int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runs(run_id, sample_id, attempt, status, started_at, finished_at, pid,
		                  input_sha256, rule_version, outcome, findings_json, fragments_json, error_text, seq)
		 VALUES(?, ?, ?, ?, ?, NULL, ?, ?, ?, '', '', '', '', ?)`,
		run.RunID, run.SampleID, run.Attempt, domain.StatusPending,
		run.StartedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		run.PID, run.InputSHA256, run.RuleVersion, seq)
	return err
}

// MarkRunning transitions PENDING -> RUNNING.
func (s *Store) MarkRunning(ctx context.Context, runID string) error {
	return s.updateStatus(ctx, runID, domain.StatusRunning, "", "", "", "")
}

// CompleteRun stores the verdict and marks the run completed.
func (s *Store) CompleteRun(ctx context.Context, runID, outcome, findingsJSON, fragmentsJSON, finishedAt string) error {
	return s.updateStatus(ctx, runID, domain.StatusCompleted, outcome, findingsJSON, fragmentsJSON, finishedAt)
}

// FailRun records an execution error.
func (s *Store) FailRun(ctx context.Context, runID, errorText, finishedAt string) error {
	return s.updateStatus(ctx, runID, domain.StatusFailed, "", "", "", finishedAt, errorText)
}

// MarkInterrupted records a run that stopped because the operator exited or
// the process was terminated before analysis completed.
func (s *Store) MarkInterrupted(ctx context.Context, runID, errorText, finishedAt string) error {
	return s.updateStatus(ctx, runID, domain.StatusInterrupted, "", "", "", finishedAt, errorText)
}

func (s *Store) updateStatus(ctx context.Context, runID, status, outcome, findingsJSON, fragmentsJSON, finishedAt string, extra ...string) error {
	errorText := ""
	if len(extra) > 0 {
		errorText = extra[0]
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs
		 SET status = ?, outcome = ?, findings_json = ?, fragments_json = ?,
		     finished_at = NULLIF(?, ''), error_text = ?
		 WHERE run_id = ?`,
		status, outcome, findingsJSON, fragmentsJSON, finishedAt, errorText, runID)
	return err
}

// RecoverInterrupted flips stale PENDING/RUNNING rows to INTERRUPTED.
// A row whose PID is still alive is left untouched so concurrent processes
// never steal each other's work.
func (s *Store) RecoverInterrupted(ctx context.Context, alive func(pid int) bool) ([]domain.Run, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id, sample_id, attempt, status, started_at, pid, input_sha256, rule_version, seq
		 FROM runs WHERE status IN (?, ?) ORDER BY seq`,
		domain.StatusPending, domain.StatusRunning)
	if err != nil {
		return nil, err
	}
	type pending struct {
		run       domain.Run
		startedAt string
		seq       int
	}
	var stale []pending
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.run.RunID, &item.run.SampleID, &item.run.Attempt,
			&item.run.Status, &item.startedAt, &item.run.PID,
			&item.run.InputSHA256, &item.run.RuleVersion, &item.seq); err != nil {
			rows.Close()
			return nil, err
		}
		stale = append(stale, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	recovered := make([]domain.Run, 0, len(stale))
	for _, item := range stale {
		if alive(item.run.PID) {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE runs SET status = ? WHERE run_id = ? AND status IN (?, ?)`,
			domain.StatusInterrupted, item.run.RunID, domain.StatusPending, domain.StatusRunning); err != nil {
			return nil, err
		}
		item.run.Status = domain.StatusInterrupted
		recovered = append(recovered, item.run)
	}
	return recovered, nil
}

// ListRuns returns every run for one sample, oldest attempt first.
func (s *Store) ListRuns(ctx context.Context, sampleID string) ([]domain.Run, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id, sample_id, attempt, status, started_at,
		        COALESCE(finished_at, ''), pid, input_sha256, rule_version,
		        outcome, findings_json, fragments_json, error_text
		 FROM runs WHERE sample_id = ? ORDER BY attempt`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Run
	for rows.Next() {
		var run domain.Run
		var startedAt, finishedAt string
		if err := rows.Scan(&run.RunID, &run.SampleID, &run.Attempt, &run.Status,
			&startedAt, &finishedAt, &run.PID, &run.InputSHA256, &run.RuleVersion,
			&run.Outcome, &run.FindingsJSON, &run.FragmentsJSON, &run.ErrorText); err != nil {
			return nil, err
		}
		run.StartedAt = parseSQLiteTime(startedAt)
		if finishedAt != "" {
			t := parseSQLiteTime(finishedAt)
			run.FinishedAt = &t
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// GetRun loads one run by ID.
func (s *Store) GetRun(ctx context.Context, runID string) (*domain.Run, error) {
	runs, err := s.queryRuns(ctx, `WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("run %q not found", runID)
	}
	return &runs[0], nil
}

// LatestCompletedRun returns the most recent completed run of a sample.
func (s *Store) LatestCompletedRun(ctx context.Context, sampleID string) (*domain.Run, error) {
	runs, err := s.queryRuns(ctx,
		`WHERE sample_id = ? AND status = ? ORDER BY attempt DESC LIMIT 1`,
		sampleID, domain.StatusCompleted)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return &runs[0], nil
}

func (s *Store) queryRuns(ctx context.Context, where string, args ...any) ([]domain.Run, error) {
	query := `SELECT run_id, sample_id, attempt, status, started_at,
	                 COALESCE(finished_at, ''), pid, input_sha256, rule_version,
	                 outcome, findings_json, fragments_json, error_text
	          FROM runs ` + where
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Run
	for rows.Next() {
		var run domain.Run
		var startedAt, finishedAt string
		if err := rows.Scan(&run.RunID, &run.SampleID, &run.Attempt, &run.Status,
			&startedAt, &finishedAt, &run.PID, &run.InputSHA256, &run.RuleVersion,
			&run.Outcome, &run.FindingsJSON, &run.FragmentsJSON, &run.ErrorText); err != nil {
			return nil, err
		}
		run.StartedAt = parseSQLiteTime(startedAt)
		if finishedAt != "" {
			t := parseSQLiteTime(finishedAt)
			run.FinishedAt = &t
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z"

func parseSQLiteTime(value string) time.Time {
	if parsed, err := time.Parse(sqliteTimeLayout, value); err == nil {
		return parsed
	}
	// Tolerate timestamps with fewer than nanosecond digits.
	if parsed, err := time.Parse("2006-01-02T15:04:05Z", value); err == nil {
		return parsed
	}
	return time.Time{}
}
