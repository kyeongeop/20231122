package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"mountaudit/internal/audit"
)

func (s *Store) CreateRun(ctx context.Context, run Run, anchors []audit.Anchor, evidence []Evidence) error {
	limitsJSON, err := json.Marshal(run.Limits)
	if err != nil {
		return fmt.Errorf("encode limits: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create run: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO runs (
  id, created_at, updated_at, source_path, source_name, source_size,
  source_sha256, original, artifact_path, format, status, next_stage,
  degraded, limits_json, final_digest, error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.CreatedAt, run.UpdatedAt, run.SourcePath, run.SourceName,
		run.SourceSize, run.SourceSHA256, run.Original, run.ArtifactPath,
		run.Format, run.Status, run.NextStage, boolInt(run.Degraded),
		string(limitsJSON), run.FinalDigest, run.Error)
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	for _, anchor := range anchors {
		_, err = tx.ExecContext(ctx, `
INSERT INTO anchors (
  run_id, number, label, offset, line, captured_at, explicit, declared_offset
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			run.ID, anchor.Number, anchor.Label, anchor.Offset, anchor.Line,
			anchor.CapturedAt, boolInt(anchor.Explicit), anchor.DeclaredOffset)
		if err != nil {
			return fmt.Errorf("insert anchor %d: %w", anchor.Number, err)
		}
	}
	if err := insertEvidence(ctx, tx, run.ID, evidence); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create run: %w", err)
	}
	return nil
}

func (s *Store) ResolveRunID(ctx context.Context, id string) (string, error) {
	if id != "" {
		return id, nil
	}
	var resolved string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM runs ORDER BY created_at DESC LIMIT 1`).Scan(&resolved)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no runs in database")
	}
	if err != nil {
		return "", fmt.Errorf("select latest run: %w", err)
	}
	return resolved, nil
}

func (s *Store) GetRun(ctx context.Context, id string) (Run, error) {
	var run Run
	var degraded int
	var limitsJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT id, created_at, updated_at, source_path, source_name, source_size,
       source_sha256, original, artifact_path, format, status, next_stage,
       degraded, limits_json, final_digest, error
FROM runs WHERE id = ?`, id).Scan(
		&run.ID, &run.CreatedAt, &run.UpdatedAt, &run.SourcePath,
		&run.SourceName, &run.SourceSize, &run.SourceSHA256, &run.Original,
		&run.ArtifactPath, &run.Format, &run.Status, &run.NextStage,
		&degraded, &limitsJSON, &run.FinalDigest, &run.Error)
	if err == sql.ErrNoRows {
		return run, fmt.Errorf("run %q not found", id)
	}
	if err != nil {
		return run, fmt.Errorf("load run: %w", err)
	}
	run.Degraded = degraded != 0
	if err := json.Unmarshal([]byte(limitsJSON), &run.Limits); err != nil {
		return run, fmt.Errorf("decode limits: %w", err)
	}
	return run, nil
}

func (s *Store) GetAnchors(ctx context.Context, runID string) ([]audit.Anchor, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT number, label, offset, line, captured_at, explicit, declared_offset
FROM anchors WHERE run_id = ? ORDER BY number`, runID)
	if err != nil {
		return nil, fmt.Errorf("query anchors: %w", err)
	}
	defer rows.Close()
	anchors := make([]audit.Anchor, 0, 3)
	for rows.Next() {
		var anchor audit.Anchor
		var explicit int
		if err := rows.Scan(&anchor.Number, &anchor.Label, &anchor.Offset,
			&anchor.Line, &anchor.CapturedAt, &explicit, &anchor.DeclaredOffset); err != nil {
			return nil, fmt.Errorf("scan anchor: %w", err)
		}
		anchor.Explicit = explicit != 0
		anchors = append(anchors, anchor)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate anchors: %w", err)
	}
	if len(anchors) != 3 {
		return nil, fmt.Errorf("expected 3 anchors, found %d", len(anchors))
	}
	return anchors, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
