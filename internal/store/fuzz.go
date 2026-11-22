package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"tracecheck/internal/model"
)

// ImportFuzzArtifact records a libFuzzer corpus/crash artifact and, when a
// check is supplied, attaches the same bytes to that check's evidence chain.
func (s *Store) ImportFuzzArtifact(ctx context.Context, checkID string, artifact []byte, minimized bool, logExcerpt string) (string, string, error) {
	if len(artifact) == 0 {
		return "", "", errors.New("artifact is empty")
	}
	id := NewID("FUZZ-")
	now := time.Now()
	if len(logExcerpt) > 8000 {
		logExcerpt = logExcerpt[:8000]
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO fuzz_imports (id, check_id, artifact_sha256, artifact_size, minimized, log_excerpt, imported_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, checkID, Hash(artifact), len(artifact), boolInt(minimized), logExcerpt,
		now.Format(time.RFC3339Nano),
	); err != nil {
		return "", "", fmt.Errorf("insert fuzz import: %w", err)
	}

	evidenceID := ""
	if checkID != "" {
		var attemptID string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM attempts WHERE check_id = ?
			ORDER BY number DESC LIMIT 1`, checkID).Scan(&attemptID)
		if errors.Is(err, sql.ErrNoRows) {
			return id, "", fmt.Errorf("check %s has no attempts", checkID)
		}
		if err != nil {
			return id, "", err
		}
		evidenceID = NewID("E-FUZZ-")
		e := model.Evidence{
			ID: evidenceID, CheckID: checkID, AttemptID: attemptID,
			StepID: attemptID + "-S3", Label: "libFuzzer 导入产物",
			Kind: "fuzzer-artifact", SHA256: Hash(artifact), Size: int64(len(artifact)),
			Content: string(artifact), Retained: true, CreatedAt: now,
		}
		if err := s.InsertEvidence(ctx, e); err != nil {
			return id, "", fmt.Errorf("attach evidence: %w", err)
		}
	}
	return id, evidenceID, nil
}

func (s *Store) FindCheckByInputPrefix(ctx context.Context, prefix string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM checks WHERE raw_sha256 LIKE ? ORDER BY created_at DESC LIMIT 1`,
		strings.TrimSpace(prefix)+"%").Scan(&id)
	return id, err
}
