package store

import (
	"example.com/replay-review/internal/model"
	"example.com/replay-review/internal/review"
)

// StoredEvent pairs a raw event with its evidence hash for export.
type StoredEvent struct {
	model.Event
	RawSHA256 string `json:"raw_sha256"`
}

// LoadEvents returns all input evidence in input order (sequence then device).
func (s *Store) LoadEvents() ([]StoredEvent, error) {
	rows, err := s.db.Query(
		`SELECT seq, device_id, code, user_id, kind, observed_at, offset_ms, raw_sha256
		 FROM input_events ORDER BY seq, device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		var se StoredEvent
		if err := rows.Scan(&se.Sequence, &se.DeviceID, &se.Code, &se.UserID,
			&se.Kind, &se.ObservedAt, &se.OffsetMs, &se.RawSHA256); err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// LoadDecisions returns verdicts in global processing order.
func (s *Store) LoadDecisions() ([]review.ReplayRow, error) {
	rows, err := s.db.Query(
		`SELECT seq, device_id, code, user_id, outcome, severity, reason,
		        matched_issue_seq, age_ms, window_ms
		 FROM decisions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []review.ReplayRow
	for rows.Next() {
		var r review.ReplayRow
		if err := rows.Scan(&r.Sequence, &r.DeviceID, &r.Code, &r.UserID,
			&r.Outcome, &r.Severity, &r.Reason, &r.MatchedIssue,
			&r.AgeMs, &r.WindowMs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadGaps returns missing-fragment evidence in discovery order.
func (s *Store) LoadGaps() ([]model.Gap, error) {
	rows, err := s.db.Query(
		`SELECT kind, device_id, after_seq, before_seq, missing_from, missing_to, detail
		 FROM gaps ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Gap
	for rows.Next() {
		var g model.Gap
		if err := rows.Scan(&g.Kind, &g.DeviceID, &g.AfterSeq, &g.BeforeSeq,
			&g.MissingFrom, &g.MissingTo, &g.Detail); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CheckpointRow is the exported checkpoint projection with stable fields.
type CheckpointRow struct {
	SegmentID    int64  `json:"segment_id"`
	Reason       string `json:"reason"`
	Paused       bool   `json:"paused"`
	Processed    int    `json:"processed"`
	Degraded     bool   `json:"degraded"`
	BudgetUsed   int    `json:"budget_used"`
	NextInputPos int    `json:"next_input_pos"`
	CreatedAtMs  int64  `json:"created_at_ms"`
}

// LoadCheckpoints returns resume points in segment order.
func (s *Store) LoadCheckpoints() ([]CheckpointRow, error) {
	rows, err := s.db.Query(
		`SELECT segment_id, reason, paused, processed, degraded, budget_used,
		        next_input_pos, created_at_ms
		 FROM checkpoints ORDER BY segment_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckpointRow
	for rows.Next() {
		var (
			r        CheckpointRow
			paused   int
			degraded int
		)
		if err := rows.Scan(&r.SegmentID, &r.Reason, &paused, &r.Processed,
			&degraded, &r.BudgetUsed, &r.NextInputPos, &r.CreatedAtMs); err != nil {
			return nil, err
		}
		r.Paused = paused == 1
		r.Degraded = degraded == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountReplay returns the number of critical replay verdicts.
func (s *Store) CountReplay() (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM decisions WHERE outcome = ?`,
		model.OutcomeReplay).Scan(&n)
	return n, err
}

// Degraded reports whether any checkpoint recorded memory-pressure degradation.
func (s *Store) Degraded() (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM checkpoints WHERE degraded = 1`).Scan(&n)
	return n > 0, err
}
