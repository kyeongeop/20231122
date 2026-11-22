package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"seedreview/internal/model"
)

func (s *Store) SetManualCheck(
	ctx context.Context,
	runID int64,
	code, status, owner, notes string,
) error {
	switch status {
	case "pending", "confirmed", "rejected":
	default:
		return fmt.Errorf("invalid manual status %q", status)
	}
	if status != "pending" && owner == "" {
		return fmt.Errorf("owner is required for %s manual checks", status)
	}
	decidedAt := ""
	if status != "pending" {
		decidedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE manual_checks
SET status=?, owner=?, notes=?, decided_at=?
WHERE run_id=? AND code=?`,
		status, owner, notes, decidedAt, runID, code,
	)
	if err != nil {
		return fmt.Errorf("update manual check: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("read manual check result: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return s.addAuditEvent(ctx, runID, "manual.confirm", map[string]any{
		"code": code, "status": status, "owner": owner, "notes": notes,
	})
}

func (s *Store) addAuditEvent(ctx context.Context, runID int64, action string, detail any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit transaction: %w", err)
	}
	defer tx.Rollback()
	if err := saveAuditEvent(ctx, tx, runID, action, detail); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AllEvidence(ctx context.Context) ([]model.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT sha256, kind, relative_path, size, media_type, created_at
FROM evidence ORDER BY sha256`)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()
	var result []model.Evidence
	for rows.Next() {
		var record model.Evidence
		var created string
		if err := rows.Scan(
			&record.SHA256, &record.Kind, &record.RelativePath,
			&record.Size, &record.MediaType, &created,
		); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		record.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Store) AuditEvents(ctx context.Context, runID int64) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT at, actor, action, detail_json
FROM audit_events WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var at, actor, action, detail string
		if err := rows.Scan(&at, &actor, &action, &detail); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		var decoded any
		if err := json.Unmarshal([]byte(detail), &decoded); err != nil {
			decoded = detail
		}
		result = append(result, map[string]any{
			"at": at, "actor": actor, "action": action, "detail": decoded,
		})
	}
	return result, rows.Err()
}

func (s *Store) CountEvidenceLinks(ctx context.Context, hash string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM recovery_sessions WHERE manifest_evidence=?) +
  (SELECT COUNT(*) FROM replay_runs WHERE input_evidence=? OR
      stdout_evidence=? OR stderr_evidence=? OR trace_evidence=?)`,
		hash, hash, hash, hash, hash,
	).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("count evidence links: %w", err)
	}
	return count, nil
}
