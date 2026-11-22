package store

import (
	"context"
	"database/sql"
	"fmt"
)

func insertEvidence(ctx context.Context, tx *sql.Tx, runID string, evidence []Evidence) error {
	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ordinal), 0) + 1 FROM evidence WHERE run_id = ?`,
		runID).Scan(&next); err != nil {
		return fmt.Errorf("allocate evidence ordinal: %w", err)
	}
	for _, item := range evidence {
		_, err := tx.ExecContext(ctx, `
INSERT INTO evidence (
  run_id, ordinal, kind, captured_at, start_offset, end_offset, sha256, detail_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, next, item.Kind, item.CapturedAt, item.StartOffset,
			item.EndOffset, item.SHA256, item.DetailJSON)
		if err != nil {
			return fmt.Errorf("insert evidence %s: %w", item.Kind, err)
		}
		next++
	}
	return nil
}

func (s *Store) AddEvidence(ctx context.Context, runID string, evidence ...Evidence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evidence transaction: %w", err)
	}
	defer tx.Rollback()
	if err := insertEvidence(ctx, tx, runID, evidence); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence: %w", err)
	}
	return nil
}

func (s *Store) GetEvidence(ctx context.Context, runID string) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ordinal, kind, captured_at, start_offset, end_offset, sha256, detail_json
FROM evidence WHERE run_id = ? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()
	items := make([]Evidence, 0)
	for rows.Next() {
		var item Evidence
		if err := rows.Scan(&item.Ordinal, &item.Kind, &item.CapturedAt,
			&item.StartOffset, &item.EndOffset, &item.SHA256, &item.DetailJSON); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
