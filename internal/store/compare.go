package store

import (
	"context"
	"fmt"
)

func (s *Store) AddComparison(ctx context.Context, runID string, comparison Comparison) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin comparison: %w", err)
	}
	defer tx.Rollback()
	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ordinal), 0) + 1 FROM comparisons WHERE run_id = ?`,
		runID).Scan(&next); err != nil {
		return fmt.Errorf("allocate comparison ordinal: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO comparisons (
  run_id, ordinal, compared_at, scope, prior_sha256, current_sha256, equal, detail_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, next, comparison.ComparedAt, comparison.Scope,
		comparison.PriorSHA256, comparison.CurrentSHA, boolInt(comparison.Equal),
		comparison.DetailJSON)
	if err != nil {
		return fmt.Errorf("insert comparison: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit comparison: %w", err)
	}
	return nil
}

func (s *Store) GetComparisons(ctx context.Context, runID string) ([]Comparison, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ordinal, compared_at, scope, prior_sha256, current_sha256, equal, detail_json
FROM comparisons WHERE run_id = ? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, fmt.Errorf("query comparisons: %w", err)
	}
	defer rows.Close()
	items := make([]Comparison, 0)
	for rows.Next() {
		var item Comparison
		var equal int
		if err := rows.Scan(&item.Ordinal, &item.ComparedAt, &item.Scope,
			&item.PriorSHA256, &item.CurrentSHA, &equal, &item.DetailJSON); err != nil {
			return nil, fmt.Errorf("scan comparison: %w", err)
		}
		item.Equal = equal != 0
		items = append(items, item)
	}
	return items, rows.Err()
}
