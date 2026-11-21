package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"auditfix/internal/model"
)

var ErrNotFound = errors.New("not found")

func (s *Store) GetCase(ctx context.Context, caseID string) (model.Case, error) {
	var c model.Case
	err := s.db.QueryRowContext(ctx, `
		SELECT case_id, created_at, description, status, analyzer_version,
			clock_offset_ns, chain_status, anchor_pair_count,
			device_a_event_rows, device_b_event_rows, correction_count
		FROM cases WHERE case_id = ?`, caseID).Scan(
		&c.CaseID, &c.CreatedAt, &c.Description, &c.Status, &c.AnalyzerVersion,
		&c.ClockOffsetNS, &c.ChainStatus, &c.AnchorPairCount,
		&c.DeviceAEventRows, &c.DeviceBEventRows, &c.CorrectionCount)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Case{}, fmt.Errorf("case %q: %w", caseID, ErrNotFound)
	}
	if err != nil {
		return model.Case{}, err
	}
	return c, nil
}

func (s *Store) ListCases(ctx context.Context) ([]model.Case, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT case_id, created_at, description, status, analyzer_version,
			clock_offset_ns, chain_status, anchor_pair_count,
			device_a_event_rows, device_b_event_rows, correction_count
		FROM cases ORDER BY created_at, case_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Case
	for rows.Next() {
		var c model.Case
		if err := rows.Scan(&c.CaseID, &c.CreatedAt, &c.Description, &c.Status,
			&c.AnalyzerVersion, &c.ClockOffsetNS, &c.ChainStatus,
			&c.AnchorPairCount, &c.DeviceAEventRows, &c.DeviceBEventRows,
			&c.CorrectionCount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) InsertEvidence(ctx context.Context, caseID, role, source string,
	sum string, data []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO evidence_blobs(case_id, role, source_name, sha256, size, bytes)
		VALUES(?,?,?,?,?,?)`, caseID, role, source, sum, len(data), data)
	return err
}

func (s *Store) ListEvidence(ctx context.Context, caseID string) ([]model.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT blob_id, case_id, role, source_name, sha256, size
		FROM evidence_blobs WHERE case_id = ?
		ORDER BY blob_id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Evidence
	for rows.Next() {
		var e model.Evidence
		if err := rows.Scan(&e.BlobID, &e.CaseID, &e.Role, &e.SourceName,
			&e.SHA256, &e.Size); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetEvidenceBytes(ctx context.Context, blobID int64) ([]byte, error) {
	var b []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT bytes FROM evidence_blobs WHERE blob_id = ?`, blobID).Scan(&b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) ListEvents(ctx context.Context, caseID string) ([]model.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT device, ordinal, seq, time_unix_ns, corrected_time_unix_ns,
			kind, anchor_id, subject, payload_sha256, prev_hash, record_hash,
			line_no, raw_line, hash_valid, chain_relation
		FROM events WHERE case_id = ?
		ORDER BY CASE device WHEN 'device-a' THEN 0 ELSE 1 END, ordinal`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var valid int
		if err := rows.Scan(&e.Device, &e.Ordinal, &e.Seq, &e.TimeUnixNS,
			&e.CorrectedNS, &e.Kind, &e.AnchorID, &e.Subject, &e.PayloadSHA256,
			&e.PrevHash, &e.RecordHash, &e.LineNo, &e.RawLine, &valid,
			&e.ChainRelation); err != nil {
			return nil, err
		}
		e.HashValid = intBool(valid)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListCorrections(ctx context.Context, caseID string) ([]model.Correction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT correction_id, case_id, device, seq_from, seq_to, missing_count,
			left_seq, left_hash, right_seq, right_prev_hash,
			corrected_time_from_unix_ns, corrected_time_to_unix_ns,
			anchor_pairs_used, rationale_code, status, created_at
		FROM corrections WHERE case_id = ?
		ORDER BY CASE device WHEN 'device-a' THEN 0 ELSE 1 END, seq_from`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Correction
	for rows.Next() {
		var c model.Correction
		if err := rows.Scan(&c.CorrectionID, &c.CaseID, &c.Device, &c.SeqFrom,
			&c.SeqTo, &c.MissingCount, &c.LeftSeq, &c.LeftHash, &c.RightSeq,
			&c.RightPrevHash, &c.CorrectedTimeFrom, &c.CorrectedTimeTo,
			&c.AnchorPairsUsed, &c.RationaleCode, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
