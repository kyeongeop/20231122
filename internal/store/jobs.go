package store

import (
	"context"
	"database/sql"
)

// EnsureJob creates the two per-sample jobs (vuln, fixed) if absent.
func EnsureJob(ctx context.Context, db *sql.DB, sampleID int64, phase string) (int64, error) {
	_, err := db.ExecContext(ctx,
		`INSERT INTO jobs(sample_id,phase,state,attempts,created_at_utc)
		 VALUES(?,?, 'pending', 0, ?)
		 ON CONFLICT(sample_id,phase) DO NOTHING`,
		sampleID, phase, NowUTC())
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx,
		`SELECT id FROM jobs WHERE sample_id=? AND phase=?`,
		sampleID, phase).Scan(&id)
	return id, err
}

// ClaimJob marks a pending or interrupted job as running and bumps attempts.
// Returns sql.ErrNoRows when no claimable job matches the filter.
func ClaimJob(ctx context.Context, db *sql.DB, sampleName, phase string) (*Job, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`SELECT j.id,j.sample_id,j.phase,j.state,j.attempts,j.created_at_utc,
		        j.started_at_utc,j.finished_at_utc
		 FROM jobs j JOIN samples s ON s.id=j.sample_id
		 WHERE (?='' OR s.name=?) AND (?='' OR j.phase=?)
		   AND j.state IN ('pending','interrupted')
		 ORDER BY s.name, j.phase
		 LIMIT 1`,
		sampleName, sampleName, phase, phase)
	j := &Job{}
	if err := row.Scan(&j.ID, &j.SampleID, &j.Phase, &j.State, &j.Attempts,
		&j.CreatedAtUTC, &j.StartedAtUTC, &j.FinishedAtUTC); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE jobs SET state='running', attempts=attempts+1,
		        started_at_utc=COALESCE(started_at_utc, ?)
		 WHERE id=?`, NowUTC(), j.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	j.State = "running"
	j.Attempts++
	return j, nil
}

// FinishJob sets the terminal job state.
func FinishJob(ctx context.Context, db *sql.DB, jobID int64, state string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE jobs SET state=?, finished_at_utc=? WHERE id=?`,
		state, NowUTC(), jobID)
	return err
}

// ReopenJob moves a finished job back to pending so --redo can claim it
// again. Historical run rows are retained as evidence.
func ReopenJob(ctx context.Context, db *sql.DB, sampleID int64, phase string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE jobs SET state='pending', finished_at_utc=NULL
		 WHERE sample_id=? AND phase=? AND state='done'`,
		sampleID, phase)
	return err
}

// ResetRunningOnStartup recovers jobs left in 'running' by an interrupted
// process so a re-entered session can claim them again.
func ResetRunningOnStartup(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx,
		`UPDATE jobs SET state='interrupted'
		 WHERE state='running'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// InsertRun opens a run row for a claimed job.
func InsertRun(ctx context.Context, db *sql.DB, jobID int64, attempt int) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO runs(job_id,attempt,started_at_utc)
		 VALUES(?,?,?)`, jobID, attempt, NowUTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishRun records the verdict and timing of a run.
func FinishRun(ctx context.Context, db *sql.DB, runID int64,
	exitCode, durationNS int64, label string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE runs SET verdict_code=?, verdict_label=?, exit_code=?,
		        duration_ns=?, finished_at_utc=?
		 WHERE id=?`,
		exitCode, label, exitCode, durationNS, NowUTC(), runID)
	return err
}

// InsertEvidence stores one evidence artifact pointer with hash and time.
func InsertEvidence(ctx context.Context, db *sql.DB, sampleID, runID int64,
	kind, path, sha, note string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO evidence(sample_id,run_id,kind,path,sha256,note,captured_at_utc)
		 VALUES(?,?,?,?,?,?,?)`,
		sampleID, runID, kind, path, sha, note, NowUTC())
	return err
}

// JobState returns the current state of a sample/phase job.
func JobState(ctx context.Context, db *sql.DB, sampleName, phase string) (string, error) {
	var state string
	err := db.QueryRowContext(ctx,
		`SELECT j.state FROM jobs j JOIN samples s ON s.id=j.sample_id
		 WHERE s.name=? AND j.phase=?`, sampleName, phase).Scan(&state)
	return state, err
}
