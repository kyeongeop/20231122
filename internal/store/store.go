package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"example.com/replay-review/internal/detect"
	"example.com/replay-review/internal/model"

	_ "modernc.org/sqlite"
)

const schemaVersion = "1"

// Store is the durable, append-only evidence database.
type Store struct {
	db *sql.DB
}

// Open creates or opens the evidence database and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	s := &Store{db: db}
	if err := s.upsertMeta("schema_version", schemaVersion); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) upsertMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Checkpoint is one resume point plus its detector snapshot.
type Checkpoint struct {
	SegmentID    int64
	Reason       string
	Paused       bool
	Processed    int
	Degraded     bool
	BudgetUsed   int
	NextInputPos int
	BatchSize    int
	Snapshot     detect.Snapshot
	CreatedAtMs  int64
}

// RecordSegment atomically persists everything a segment produced: decisions,
// gaps, validation errors, normalized issue/cursor state and the checkpoint.
func (s *Store) RecordSegment(cp Checkpoint, res detect.Result, nowMs int64, note string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	pausedInt := 0
	if cp.Paused {
		pausedInt = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO segments(segment_id, started_ms, ended_ms, paused, reason, note)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(segment_id) DO UPDATE SET
		   ended_ms=excluded.ended_ms, paused=excluded.paused,
		   reason=excluded.reason, note=excluded.note`,
		cp.SegmentID, nowMs, nowMs, pausedInt, cp.Reason, note); err != nil {
		return err
	}

	// BatchSize bounds the number of rows flushed between savepoints inside
	// the segment transaction, keeping rollback journals small under pressure.
	batch := cp.BatchSize
	if batch <= 0 {
		batch = len(res.Decisions) + len(res.Gaps) + len(res.Errors) + 1
	}
	if err := flushInBatches(batch, len(res.Decisions)+len(res.Gaps)+len(res.Errors),
		func(start, end int) error {
			return flushEvidence(tx, cp.SegmentID, res, start, end)
		}); err != nil {
		return err
	}

	for _, iss := range cp.Snapshot.Issues {
		if _, err := tx.Exec(
			`INSERT INTO issues(code, user_id, issue_sequence, device_id, issued_at_ref,
			   window_ms, consume_count, first_consume_seq)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(code, user_id) DO UPDATE SET
			   issue_sequence=excluded.issue_sequence,
			   device_id=excluded.device_id,
			   issued_at_ref=excluded.issued_at_ref,
			   window_ms=excluded.window_ms,
			   consume_count=excluded.consume_count,
			   first_consume_seq=excluded.first_consume_seq`,
			iss.Code, iss.UserID, iss.Sequence, iss.DeviceID, iss.IssuedAtRef,
			iss.WindowMs, iss.ConsumeCount, iss.FirstConsumeSeq); err != nil {
			return err
		}
	}
	for _, cur := range cp.Snapshot.Devices {
		if _, err := tx.Exec(
			`INSERT INTO device_cursors(device_id, last_sequence, last_reference)
			 VALUES(?, ?, ?)
			 ON CONFLICT(device_id) DO UPDATE SET
			   last_sequence=excluded.last_sequence,
			   last_reference=excluded.last_reference`,
			cur.DeviceID, cur.LastSequence, cur.LastReference); err != nil {
			return err
		}
	}

	raw, err := json.Marshal(cp.Snapshot)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO checkpoints(segment_id, reason, paused, processed, degraded,
		   budget_used, next_input_pos, detector_json, created_at_ms)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(segment_id) DO UPDATE SET
		   reason=excluded.reason, paused=excluded.paused,
		   processed=excluded.processed, degraded=excluded.degraded,
		   budget_used=excluded.budget_used, next_input_pos=excluded.next_input_pos,
		   detector_json=excluded.detector_json, created_at_ms=excluded.created_at_ms`,
		cp.SegmentID, cp.Reason, pausedInt, res.Processed, boolInt(cp.Degraded),
		cp.BudgetUsed, cp.NextInputPos, string(raw), nowMs); err != nil {
		return err
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FindIssue implements detect.IssueFinder as the durable degradation path.
func (s *Store) FindIssue(code, userID string) (model.IssueState, bool, error) {
	var iss model.IssueState
	err := s.db.QueryRow(
		`SELECT issue_sequence, device_id, code, user_id, issued_at_ref, window_ms,
		        consume_count, first_consume_seq
		 FROM issues WHERE code = ? AND user_id = ?`, code, userID).
		Scan(&iss.Sequence, &iss.DeviceID, &iss.Code, &iss.UserID,
			&iss.IssuedAtRef, &iss.WindowMs, &iss.ConsumeCount, &iss.FirstConsumeSeq)
	if err == sql.ErrNoRows {
		return model.IssueState{}, false, nil
	}
	if err != nil {
		return model.IssueState{}, false, err
	}
	return iss, true, nil
}

// SaveIssue implements detect.IssueSink. Upserts keep the durable issue table
// authoritative while the in-memory cache is saturated.
func (s *Store) SaveIssue(iss model.IssueState) error {
	_, err := s.db.Exec(
		`INSERT INTO issues(code, user_id, issue_sequence, device_id, issued_at_ref,
		   window_ms, consume_count, first_consume_seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(code, user_id) DO UPDATE SET
		   issue_sequence=excluded.issue_sequence,
		   device_id=excluded.device_id,
		   issued_at_ref=excluded.issued_at_ref,
		   window_ms=excluded.window_ms,
		   consume_count=excluded.consume_count,
		   first_consume_seq=excluded.first_consume_seq`,
		iss.Code, iss.UserID, iss.Sequence, iss.DeviceID, iss.IssuedAtRef,
		iss.WindowMs, iss.ConsumeCount, iss.FirstConsumeSeq)
	return err
}

// LatestCheckpoint returns the most recent resume point, if any.
func (s *Store) LatestCheckpoint() (Checkpoint, bool, error) {
	var (
		cp       Checkpoint
		paused   int
		degraded int
		raw      string
	)
	err := s.db.QueryRow(
		`SELECT segment_id, reason, paused, processed, degraded, budget_used,
		        next_input_pos, detector_json, created_at_ms
		 FROM checkpoints ORDER BY segment_id DESC LIMIT 1`).
		Scan(&cp.SegmentID, &cp.Reason, &paused, &cp.Processed, &degraded,
			&cp.BudgetUsed, &cp.NextInputPos, &raw, &cp.CreatedAtMs)
	if err == sql.ErrNoRows {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	cp.Paused = paused == 1
	cp.Degraded = degraded == 1
	if err := json.Unmarshal([]byte(raw), &cp.Snapshot); err != nil {
		return Checkpoint{}, false, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return cp, true, nil
}

// IngestEvents stores raw input records with their canonical SHA-256 hash.
func (s *Store) IngestEvents(events []model.Event, hashes []string) error {
	if len(events) != len(hashes) {
		return fmt.Errorf("events/hashes length mismatch: %d vs %d",
			len(events), len(hashes))
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO input_events(seq, device_id, code, user_id, kind,
		   observed_at, offset_ms, raw_sha256)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, ev := range events {
		if _, err := stmt.Exec(ev.Sequence, ev.DeviceID, ev.Code, ev.UserID,
			ev.Kind, ev.ObservedAt, ev.OffsetMs, hashes[i]); err != nil {
			return err
		}
	}
	return tx.Commit()
}
