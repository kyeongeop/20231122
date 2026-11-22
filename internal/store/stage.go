package store

import (
	"context"
	"fmt"

	"mountaudit/internal/audit"
)

func (s *Store) CommitStage(ctx context.Context, runID string, commit StageCommit) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin stage transaction: %w", err)
	}
	defer tx.Rollback()

	for _, record := range commit.Records {
		_, err = tx.ExecContext(ctx, `
INSERT OR REPLACE INTO records (
  run_id, ordinal, stage, mount_id, parent_id, major_minor, root,
  mount_point, mount_options, optional, fs_type, source, super_options,
  read_only, no_suid, no_dev, no_exec, start_offset, end_offset, line, observed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, record.Ordinal, record.Stage, record.MountID, record.ParentID,
			record.MajorMinor, record.Root, record.MountPoint, record.MountOptions,
			record.Optional, record.FSType, record.Source, record.SuperOptions,
			boolInt(record.Permissions.ReadOnly), boolInt(record.Permissions.NoSUID),
			boolInt(record.Permissions.NoDev), boolInt(record.Permissions.NoExec),
			record.StartOffset, record.EndOffset, record.Line, record.ObservedAt)
		if err != nil {
			return fmt.Errorf("insert record %d: %w", record.Ordinal, err)
		}
	}
	for _, finding := range commit.Findings {
		_, err = tx.ExecContext(ctx, `
INSERT OR REPLACE INTO findings (
  run_id, ordinal, stage, severity, code, mount_point, source, detail,
  start_offset, end_offset, line, observed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, finding.Ordinal, finding.Stage, finding.Severity, finding.Code,
			finding.MountPoint, finding.Source, finding.Detail, finding.StartOffset,
			finding.EndOffset, finding.Line, finding.ObservedAt)
		if err != nil {
			return fmt.Errorf("insert finding %d: %w", finding.Ordinal, err)
		}
	}
	if err := insertEvidence(ctx, tx, runID, commit.Evidence); err != nil {
		return err
	}
	checkpoint := commit.Checkpoint
	_, err = tx.ExecContext(ctx, `
INSERT OR REPLACE INTO checkpoints (
  run_id, stage, anchor_number, status, started_at, finished_at,
  start_offset, end_offset, anchor_offset, anchor_line, segment_sha256,
  result_json, result_sha256, degraded
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, checkpoint.Stage, checkpoint.AnchorNumber, checkpoint.Status,
		checkpoint.StartedAt, checkpoint.FinishedAt, checkpoint.StartOffset,
		checkpoint.EndOffset, checkpoint.AnchorOffset, checkpoint.AnchorLine,
		checkpoint.SegmentSHA, checkpoint.ResultJSON, checkpoint.ResultSHA,
		boolInt(checkpoint.Degraded))
	if err != nil {
		return fmt.Errorf("insert checkpoint: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
UPDATE runs
SET status = ?, next_stage = ?, degraded = ?, final_digest = ?, error = ?, updated_at = ?
WHERE id = ?`,
		commit.RunStatus, commit.NextStage, boolInt(commit.Degraded),
		commit.FinalDigest, commit.RunError, commit.UpdatedAt, runID)
	if err != nil {
		return fmt.Errorf("update run after stage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit stage: %w", err)
	}
	return nil
}

func (s *Store) GetCheckpoints(ctx context.Context, runID string) ([]Checkpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT run_id, stage, anchor_number, status, started_at, finished_at,
       start_offset, end_offset, anchor_offset, anchor_line, segment_sha256,
       result_json, result_sha256, degraded
FROM checkpoints WHERE run_id = ? ORDER BY stage`, runID)
	if err != nil {
		return nil, fmt.Errorf("query checkpoints: %w", err)
	}
	defer rows.Close()
	checkpoints := make([]Checkpoint, 0, 3)
	for rows.Next() {
		var checkpoint Checkpoint
		var degraded int
		if err := rows.Scan(&checkpoint.RunID, &checkpoint.Stage,
			&checkpoint.AnchorNumber, &checkpoint.Status, &checkpoint.StartedAt,
			&checkpoint.FinishedAt, &checkpoint.StartOffset, &checkpoint.EndOffset,
			&checkpoint.AnchorOffset, &checkpoint.AnchorLine, &checkpoint.SegmentSHA,
			&checkpoint.ResultJSON, &checkpoint.ResultSHA, &degraded); err != nil {
			return nil, fmt.Errorf("scan checkpoint: %w", err)
		}
		checkpoint.Degraded = degraded != 0
		checkpoints = append(checkpoints, checkpoint)
	}
	return checkpoints, rows.Err()
}

func (s *Store) GetRecords(ctx context.Context, runID string) ([]RecordRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ordinal, stage, mount_id, parent_id, major_minor, root, mount_point,
       mount_options, optional, fs_type, source, super_options, read_only,
       no_suid, no_dev, no_exec, start_offset, end_offset, line, observed_at
FROM records WHERE run_id = ? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, fmt.Errorf("query records: %w", err)
	}
	defer rows.Close()
	records := make([]RecordRow, 0)
	for rows.Next() {
		var record RecordRow
		var readOnly, noSUID, noDev, noExec int
		if err := rows.Scan(&record.Ordinal, &record.Stage, &record.MountID,
			&record.ParentID, &record.MajorMinor, &record.Root, &record.MountPoint,
			&record.MountOptions, &record.Optional, &record.FSType, &record.Source,
			&record.SuperOptions, &readOnly, &noSUID, &noDev, &noExec,
			&record.StartOffset, &record.EndOffset, &record.Line, &record.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		record.Permissions = audit.Permissions{
			ReadOnly: readOnly != 0,
			NoSUID:   noSUID != 0,
			NoDev:    noDev != 0,
			NoExec:   noExec != 0,
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) GetFindings(ctx context.Context, runID string) ([]FindingRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ordinal, stage, severity, code, mount_point, source, detail,
       start_offset, end_offset, line, observed_at
FROM findings WHERE run_id = ? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	findings := make([]FindingRow, 0)
	for rows.Next() {
		var finding FindingRow
		if err := rows.Scan(&finding.Ordinal, &finding.Stage, &finding.Severity,
			&finding.Code, &finding.MountPoint, &finding.Source, &finding.Detail,
			&finding.StartOffset, &finding.EndOffset, &finding.Line,
			&finding.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) SetRunError(ctx context.Context, runID, status, errorText, updatedAt string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status = ?, error = ?, updated_at = ? WHERE id = ?`,
		status, errorText, updatedAt, runID)
	if err != nil {
		return fmt.Errorf("set run error: %w", err)
	}
	return nil
}

func (s *Store) NextFindingOrdinal(ctx context.Context, runID string) (int, error) {
	var next int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ordinal), 0) + 1 FROM findings WHERE run_id = ?`,
		runID).Scan(&next)
	if err != nil {
		return 0, fmt.Errorf("allocate finding ordinal: %w", err)
	}
	return next, nil
}

func (s *Store) NextEvidenceOrdinal(ctx context.Context, runID string) (int, error) {
	var next int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ordinal), 0) + 1 FROM evidence WHERE run_id = ?`,
		runID).Scan(&next)
	if err != nil {
		return 0, fmt.Errorf("allocate evidence ordinal: %w", err)
	}
	return next, nil
}
