package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"auditfix/internal/model"
)

type EvidenceBlob struct {
	Role       string
	SourceName string
	SHA256     string
	Data       []byte
}

func (s *Store) CreateCaseAtomic(ctx context.Context, c model.Case, blobs []EvidenceBlob,
	events []model.Event, corrections []model.Correction) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists int
	err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cases WHERE case_id = ?`, c.CaseID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists != 0 {
		return fmt.Errorf("case %q already exists", c.CaseID)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cases(
			case_id, created_at, description, status, analyzer_version,
			clock_offset_ns, chain_status, anchor_pair_count,
			device_a_event_rows, device_b_event_rows, correction_count
		) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		c.CaseID, c.CreatedAt, c.Description, c.Status, c.AnalyzerVersion,
		c.ClockOffsetNS, c.ChainStatus, c.AnchorPairCount,
		c.DeviceAEventRows, c.DeviceBEventRows, c.CorrectionCount); err != nil {
		return fmt.Errorf("insert case: %w", err)
	}
	for _, blob := range blobs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO evidence_blobs(case_id, role, source_name, sha256, size, bytes)
			VALUES(?,?,?,?,?,?)`,
			c.CaseID, blob.Role, blob.SourceName, blob.SHA256,
			len(blob.Data), blob.Data); err != nil {
			return fmt.Errorf("insert evidence %s: %w", blob.Role, err)
		}
	}
	for _, event := range events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO events(
				case_id, device, ordinal, seq, time_unix_ns, corrected_time_unix_ns,
				kind, anchor_id, subject, payload_sha256, prev_hash, record_hash,
				line_no, raw_line, hash_valid, chain_relation
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.CaseID, event.Device, event.Ordinal, event.Seq, event.TimeUnixNS,
			event.CorrectedNS, event.Kind, event.AnchorID, event.Subject,
			event.PayloadSHA256, event.PrevHash, event.RecordHash, event.LineNo,
			event.RawLine, boolInt(event.HashValid), event.ChainRelation); err != nil {
			return fmt.Errorf("insert event %s/%d: %w", event.Device, event.Seq, err)
		}
	}
	for _, correction := range corrections {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO corrections(
				correction_id, case_id, device, seq_from, seq_to, missing_count,
				left_seq, left_hash, right_seq, right_prev_hash,
				corrected_time_from_unix_ns, corrected_time_to_unix_ns,
				anchor_pairs_used, rationale_code, status, created_at
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			correction.CorrectionID, correction.CaseID, correction.Device,
			correction.SeqFrom, correction.SeqTo, correction.MissingCount,
			correction.LeftSeq, correction.LeftHash, correction.RightSeq,
			correction.RightPrevHash, correction.CorrectedTimeFrom,
			correction.CorrectedTimeTo, correction.AnchorPairsUsed,
			correction.RationaleCode, correction.Status,
			correction.CreatedAt); err != nil {
			return fmt.Errorf("insert correction %s: %w", correction.CorrectionID, err)
		}
	}
	return tx.Commit()
}

func (s *Store) CaseExists(ctx context.Context, caseID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cases WHERE case_id = ?`, caseID).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return count > 0, err
}
