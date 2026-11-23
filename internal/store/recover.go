package store

import (
	"errors"
	"fmt"
	"time"

	"trustaudit/internal/record"
)

// RecoveryReport describes one recovery pass over the audit log.
type RecoveryReport struct {
	Scanned       int   `json:"scanned"`
	Salvaged      int   `json:"salvaged"`       // rows proven decodable
	FirstBadLogID int64 `json:"first_bad_log"`  // first corrupt state, 0 if none
	Quarantined   int   `json:"quarantined"`    // rows moved to evidence
	Unreachable   int   `json:"unreachable"`    // rows after the truncation point
	RecoveryID    int64 `json:"recovery_row"`   // id of the recovery table entry
}

// Recover scans pending rows in order, marks decodable rows valid, and
// stops at the first undecodable (truncated) row: that row is copied
// into the evidence table with its raw bytes and hash, marked
// quarantined, and every row after it is marked unreachable, because a
// torn tail write invalidates everything that claims to follow it.
// The recovery point itself is persisted in the recovery table.
func (s *Store) Recover() (*RecoveryReport, error) {
	entries, err := s.Entries()
	if err != nil {
		return nil, err
	}
	rep := &RecoveryReport{}
	var firstBad int64
	for _, e := range entries {
		if e.Status != StatusPending {
			continue
		}
		rep.Scanned++
		if firstBad != 0 {
			rep.Unreachable++
			if _, err := s.db.Exec(
				`UPDATE audit_log SET status='unreachable' WHERE id=?`, e.ID); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := record.Decode(e.Raw); err != nil {
			if !errors.Is(err, record.ErrTruncated) {
				return nil, fmt.Errorf("log %d: %w", e.ID, err)
			}
			firstBad = e.ID
			rep.FirstBadLogID = e.ID
			rep.Quarantined++
			detail := fmt.Sprintf("truncated record: %v", err)
			if _, err := s.db.Exec(
				`INSERT INTO evidence(log_id, kind, raw, sha256, detail, created_at)
				 VALUES(?,?,?,?,?,?)`,
				e.ID, "truncated-record", e.Raw, e.SHA256, detail, time.Now().Unix()); err != nil {
				return nil, err
			}
			if _, err := s.db.Exec(
				`UPDATE audit_log SET status=? WHERE id=?`, StatusQuarantine, e.ID); err != nil {
				return nil, err
			}
			continue
		}
		rep.Salvaged++
		if _, err := s.db.Exec(
			`UPDATE audit_log SET status=? WHERE id=?`, StatusValid, e.ID); err != nil {
			return nil, err
		}
	}
	note := "log clean"
	if firstBad != 0 {
		note = fmt.Sprintf("truncated tail at log %d; %d salvaged, %d unreachable",
			firstBad, rep.Salvaged, rep.Unreachable)
	}
	res, err := s.db.Exec(
		`INSERT INTO recovery(at, first_bad_log_id, salvaged, note) VALUES(?,?,?,?)`,
		time.Now().Unix(), firstBad, rep.Salvaged, note)
	if err != nil {
		return nil, err
	}
	rep.RecoveryID, _ = res.LastInsertId()
	return rep, nil
}
