package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"crashprovenance/internal/forensics"
)

var (
	ErrInvalidReview = errors.New("invalid manual review")
	ErrSampleMissing = errors.New("sample not found")
)

func (s *Store) ReviewManual(ctx context.Context, sampleID, checkID, status, reviewer, note string) (Report, error) {
	if status != "confirmed" && status != "rejected" {
		return Report{}, fmt.Errorf("%w: status must be confirmed or rejected", ErrInvalidReview)
	}
	if reviewer == "" {
		return Report{}, fmt.Errorf("%w: reviewer is required", ErrInvalidReview)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE manual_checks
		SET status = ?, reviewer = ?, note = ?, updated_at = ?
		WHERE id = ? AND sample_id = ?`,
		status, reviewer, note, now(), checkID, sampleID)
	if err != nil {
		return Report{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Report{}, err
	}
	if affected == 0 {
		return Report{}, ErrSampleMissing
	}
	return s.GetReport(ctx, sampleID)
}

func (s *Store) RunReplay(ctx context.Context, sampleID string) (Report, error) {
	original, err := s.SampleOriginal(ctx, sampleID)
	if err != nil {
		return Report{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Report{}, err
	}
	defer tx.Rollback()

	var nextSeq int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM steps WHERE sample_id = ?`, sampleID).Scan(&nextSeq); err != nil {
		return Report{}, err
	}
	var nextAttempt int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(attempt), 0) + 1 FROM replay_runs WHERE sample_id = ?`, sampleID).Scan(&nextAttempt); err != nil {
		return Report{}, err
	}
	var evidenceCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence WHERE sample_id = ?`, sampleID).Scan(&evidenceCount); err != nil {
		return Report{}, err
	}

	started := time.Now().UTC()
	reproduced := 0
	var analysis forensics.Analysis
	for i := 0; i < 3; i++ {
		analysis, err = forensics.AnalyzeSample(original)
		if errors.Is(err, forensics.ErrUnknownExtension) {
			reproduced++
		}
	}
	stepID := fmt.Sprintf("S-%03d", nextSeq)
	replayID := fmt.Sprintf("R-%03d", nextAttempt)
	evidenceID := fmt.Sprintf("E-%03d", evidenceCount+1)
	finished := time.Now().UTC()

	traceContent, err := json.MarshalIndent(map[string]any{
		"sample_id":      sampleID,
		"sha256":         forensics.Digest(original),
		"analysis":       analysis,
		"runs":           3,
		"reproduced":     reproduced,
		"triggered_by":   "manual_replay",
		"stopped_before": "semantic_attribution",
	}, "", "  ")
	if err != nil {
		return Report{}, err
	}
	digest := contentDigest(traceContent)
	path := objectPath(s.baseDir, digest, ".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(path, traceContent, 0o444); err != nil {
		return Report{}, err
	}

	stepStatus := "passed"
	if reproduced != 3 {
		stepStatus = "failed"
	}
	stepDetail := "再次执行 Go 来源解析 3 次，均命中同一 0x7E 未知扩展边界；未执行新的语义归属。"
	if reproduced != 3 {
		stepDetail = "来源解析未稳定命中边界，已保留本轮 trace 和失败状态，等待人工处理。"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO steps
		(id, sample_id, seq, phase, title, status, started_at, finished_at,
		 command, detail, hash) VALUES (?, ?, ?, 'replay', '人工触发：重跑来源解析',
		?, ?, ?, 'POST /api/replay', ?, ?)`,
		stepID, sampleID, nextSeq, stepStatus, started.Format(time.RFC3339),
		finished.Format(time.RFC3339), stepDetail, digest)
	if err != nil {
		return Report{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO evidence
		(id, sample_id, step_id, kind, label, mime, sha256, size, created_at, path, content)
		VALUES (?, ?, ?, 'trace', '人工重放 trace', 'application/json', ?, ?, ?, ?, ?)`,
		evidenceID, sampleID, stepID, digest, len(traceContent),
		finished.Format(time.RFC3339), path, traceContent)
	if err != nil {
		return Report{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO replay_runs
		(id, sample_id, attempt, started_at, finished_at, status, exit_code,
		 reproduced, total, crash_hash, note, evidence_id, recovered_from_job)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 3, ?, ?, ?, ?)`,
		replayID, sampleID, nextAttempt, started.Format(time.RFC3339),
		finished.Format(time.RFC3339), map[bool]string{true: "reproduced", false: "failed"}[reproduced == 3],
		0, reproduced, "boundary:0x7e", stepDetail, evidenceID, "manual")
	if err != nil {
		return Report{}, err
	}
	if err := tx.Commit(); err != nil {
		return Report{}, err
	}
	return s.GetReport(ctx, sampleID)
}

func (s *Store) Export(ctx context.Context, sampleID string) (ExportPackage, error) {
	report, err := s.GetReport(ctx, sampleID)
	if err != nil {
		return ExportPackage{}, err
	}
	original, err := s.SampleOriginal(ctx, sampleID)
	if err != nil {
		return ExportPackage{}, err
	}
	pkg := ExportPackage{
		Report:   report,
		Original: base64.StdEncoding.EncodeToString(original),
	}
	for _, item := range report.Evidence {
		content, _, err := s.EvidenceContent(ctx, item.ID)
		if err != nil {
			return ExportPackage{}, err
		}
		pkg.Evidence = append(pkg.Evidence, ExportedEvidence{
			ID: item.ID, Label: item.Label, SHA256: item.SHA256,
			Content: base64.StdEncoding.EncodeToString(content),
		})
	}
	return pkg, nil
}

func (s *Store) HasSample(ctx context.Context, sampleID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE id = ?`, sampleID).Scan(&exists)
	return exists > 0, err
}

func (s *Store) IsNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
