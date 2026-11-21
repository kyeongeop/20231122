package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Store) GetReport(ctx context.Context, sampleID string) (Report, error) {
	var report Report
	err := s.db.QueryRowContext(ctx, `SELECT id, case_no, incident, filename,
		extension, size, sha256, status, severity, summary, owner, received_at,
		recovered_at, frozen_at, storage_path FROM samples WHERE id = ?`, sampleID).
		Scan(&report.Sample.ID, &report.Sample.CaseNo, &report.Sample.Incident,
			&report.Sample.Filename, &report.Sample.Extension, &report.Sample.Size,
			&report.Sample.SHA256, &report.Sample.Status, &report.Sample.Severity,
			&report.Sample.Summary, &report.Sample.Owner, &report.Sample.ReceivedAt,
			&report.Sample.RecoveredAt, &report.Sample.FrozenAt, &report.Sample.StoragePath)
	if err != nil {
		return report, err
	}

	if report.Steps, err = s.steps(ctx, sampleID); err != nil {
		return report, err
	}
	if report.Evidence, err = s.evidence(ctx, sampleID); err != nil {
		return report, err
	}
	if report.Conclusions, err = s.conclusions(ctx, sampleID); err != nil {
		return report, err
	}
	if report.ManualChecks, err = s.manualChecks(ctx, sampleID); err != nil {
		return report, err
	}
	if report.Replays, err = s.replays(ctx, sampleID); err != nil {
		return report, err
	}
	if report.UnknownExtensions, err = s.unknownExtensions(ctx, sampleID); err != nil {
		return report, err
	}
	report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	report.Summary = summarize(report)
	return report, nil
}

func (s *Store) steps(ctx context.Context, sampleID string) ([]Step, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, seq, phase, title,
		status, started_at, finished_at, command, detail, hash FROM steps
		WHERE sample_id = ? ORDER BY seq`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var v Step
		if err := rows.Scan(&v.ID, &v.SampleID, &v.Seq, &v.Phase, &v.Title, &v.Status,
			&v.StartedAt, &v.FinishedAt, &v.Command, &v.Detail, &v.Hash); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) evidence(ctx context.Context, sampleID string) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, step_id, kind, label,
		mime, sha256, size, created_at, substr(content, 1, 128) FROM evidence
		WHERE sample_id = ? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var v Evidence
		var preview []byte
		if err := rows.Scan(&v.ID, &v.SampleID, &v.StepID, &v.Kind, &v.Label,
			&v.MIME, &v.SHA256, &v.Size, &v.CreatedAt, &preview); err != nil {
			return nil, err
		}
		v.PreviewHex = hex.EncodeToString(preview)
		v.DownloadURL = "/api/evidence/" + v.ID
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) conclusions(ctx context.Context, sampleID string) ([]Conclusion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, origin, category,
		title, detail, status, confidence, severity, rule_id, step_id,
		evidence_ids, input_ref, boundary, undecidable_reason, manual_check_id
		FROM conclusions WHERE sample_id = ? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conclusion
	for rows.Next() {
		var v Conclusion
		var evidenceJSON string
		if err := rows.Scan(&v.ID, &v.SampleID, &v.Origin, &v.Category, &v.Title,
			&v.Detail, &v.Status, &v.Confidence, &v.Severity, &v.RuleID,
			&v.StepID, &evidenceJSON, &v.InputRef, &v.Boundary,
			&v.Undecidable, &v.ManualCheckID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &v.EvidenceIDs); err != nil {
			return nil, fmt.Errorf("decode evidence ids for %s: %w", v.ID, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) manualChecks(ctx context.Context, sampleID string) ([]ManualCheck, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, conclusion_id,
		question, guidance, status, reviewer, note, updated_at FROM manual_checks
		WHERE sample_id = ? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManualCheck
	for rows.Next() {
		var v ManualCheck
		if err := rows.Scan(&v.ID, &v.SampleID, &v.ConclusionID, &v.Question,
			&v.Guidance, &v.Status, &v.Reviewer, &v.Note, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) replays(ctx context.Context, sampleID string) ([]ReplayRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, attempt, started_at,
		finished_at, status, exit_code, reproduced, total, crash_hash, note,
		evidence_id, recovered_from_job FROM replay_runs WHERE sample_id = ?
		ORDER BY attempt`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReplayRun
	for rows.Next() {
		var v ReplayRun
		if err := rows.Scan(&v.ID, &v.SampleID, &v.Attempt, &v.StartedAt,
			&v.FinishedAt, &v.Status, &v.ExitCode, &v.Reproduced, &v.Total,
			&v.CrashHash, &v.Note, &v.EvidenceID, &v.RecoveredFromJob); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) unknownExtensions(ctx context.Context, sampleID string) ([]UnknownExtensionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sample_id, tag, offset, length,
		data_offset, boundary, registry_status, parser_action, raw_hex, evidence_id
		FROM unknown_extensions WHERE sample_id = ? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnknownExtensionRecord
	for rows.Next() {
		var v UnknownExtensionRecord
		if err := rows.Scan(&v.ID, &v.SampleID, &v.Tag, &v.Offset, &v.Length,
			&v.DataOffset, &v.Boundary, &v.RegistryStatus, &v.ParserAction,
			&v.RawHex, &v.EvidenceID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func summarize(report Report) Summary {
	var summary Summary
	for _, c := range report.Conclusions {
		if c.Origin != "automatic" {
			continue
		}
		summary.AutoCount++
		if c.Status == "confirmed" {
			summary.AutoConfirmed++
		}
		if c.Status == "undecided" {
			summary.AutoUndecided++
		}
	}
	for _, check := range report.ManualChecks {
		summary.ManualCount++
		switch check.Status {
		case "pending":
			summary.ManualPending++
		default:
			summary.ManualResolved++
		}
	}
	summary.EvidenceCount = len(report.Evidence)
	summary.ReplayCount = len(report.Replays)
	summary.Status = "needs_review"
	summary.StatusLabel = "待人工确认"
	if summary.ManualPending == 0 && summary.ManualResolved > 0 {
		summary.Status = "reviewed"
		summary.StatusLabel = "人工已复核"
	}
	if summary.ManualPending == 0 && summary.AutoUndecided > 0 {
		if summary.ManualResolved == 0 {
			summary.Status = "boundary_blocked"
			summary.StatusLabel = "边界待补证"
		}
	}
	if summary.ManualPending == 0 && summary.AutoUndecided == 0 {
		summary.Status = "confirmed"
		summary.StatusLabel = "归因已确认"
	}
	return summary
}

func (s *Store) EvidenceContent(ctx context.Context, evidenceID string) ([]byte, string, error) {
	var content []byte
	var label string
	err := s.db.QueryRowContext(ctx, `SELECT content, label FROM evidence WHERE id = ?`, evidenceID).
		Scan(&content, &label)
	if err != nil {
		return nil, "", err
	}
	return content, label, nil
}

func (s *Store) SampleOriginal(ctx context.Context, sampleID string) ([]byte, error) {
	var original []byte
	err := s.db.QueryRowContext(ctx, `SELECT original FROM samples WHERE id = ?`, sampleID).
		Scan(&original)
	return original, err
}

func isNotFound(err error) bool {
	return err == sql.ErrNoRows
}
