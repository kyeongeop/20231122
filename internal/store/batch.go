package store

import (
	"database/sql"

	"example.com/replay-review/internal/detect"
)

// flushInBatches invokes fn over contiguous [start, end) windows of at most
// batch rows. A single call is used when the payload is smaller than batch.
func flushInBatches(batch, total int, fn func(start, end int) error) error {
	if batch <= 0 || total <= batch {
		return fn(0, total)
	}
	for start := 0; start < total; start += batch {
		end := start + batch
		if end > total {
			end = total
		}
		if err := fn(start, end); err != nil {
			return err
		}
	}
	return nil
}

// flushEvidence writes one window of decisions, gaps and validation errors.
// The three slices are treated as one logical stream indexed 0..total-1.
func flushEvidence(tx *sql.Tx, segmentID int64, res detect.Result,
	start, end int) error {
	nDec, nGap := len(res.Decisions), len(res.Gaps)
	nErr := len(res.Errors)

	decLo, decHi := window(start, end, nDec)
	for i := decLo; i < decHi; i++ {
		dec := res.Decisions[i]
		if _, err := tx.Exec(
			`INSERT INTO decisions(seq, device_id, code, user_id, outcome, severity,
			   reason, matched_issue_seq, age_ms, window_ms, segment_id)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			dec.Sequence, dec.DeviceID, dec.Code, dec.UserID, dec.Outcome,
			dec.Severity, dec.Reason, dec.MatchedIssue, dec.AgeMs, dec.WindowMs,
			segmentID); err != nil {
			return err
		}
	}

	gapLo, gapHi := window(start-nDec, end-nDec, nGap)
	for i := gapLo; i < gapHi; i++ {
		gap := res.Gaps[i]
		if _, err := tx.Exec(
			`INSERT INTO gaps(kind, device_id, after_seq, before_seq, missing_from,
			   missing_to, detail, segment_id)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			gap.Kind, gap.DeviceID, gap.AfterSeq, gap.BeforeSeq, gap.MissingFrom,
			gap.MissingTo, gap.Detail, segmentID); err != nil {
			return err
		}
	}

	errLo, errHi := window(start-nDec-nGap, end-nDec-nGap, nErr)
	for i := errLo; i < errHi; i++ {
		verr := res.Errors[i]
		if _, err := tx.Exec(
			`INSERT INTO validation_errors(seq, device_id, message, segment_id)
			 VALUES(?, ?, ?, ?)`,
			verr.Sequence, verr.DeviceID, verr.Message, segmentID); err != nil {
			return err
		}
	}
	return nil
}

// window clamps a logical [lo, hi) range to a slice of length n.
func window(lo, hi, n int) (int, int) {
	if lo < 0 {
		lo = 0
	}
	if hi > n {
		hi = n
	}
	if lo > n {
		lo = n
	}
	if hi < lo {
		return lo, lo
	}
	return lo, hi
}
