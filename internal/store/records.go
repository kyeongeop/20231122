package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"corpusd/internal/model"
)

func (s *Store) SaveResult(runID string, rec model.Record, ts string) error {
	data, err := model.MarshalRecord(rec)
	if err != nil {
		return err
	}
	return s.RetryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO results(run_id, seq, record_json, record_digest, ts_utc)
			VALUES (?,?,?,?,?)
			ON CONFLICT(run_id, seq) DO UPDATE SET
				record_json=excluded.record_json,
				record_digest=excluded.record_digest,
				ts_utc=excluded.ts_utc`,
			runID, rec.Seq, string(data), model.RecordDigest(rec), ts)
		return err
	})
}

func (s *Store) Results(runID string, through int64) ([]model.Record, error) {
	query := `SELECT record_json FROM results WHERE run_id=?`
	args := []any{runID}
	if through > 0 {
		query += ` AND seq<=?`
		args = append(args, through)
	}
	query += ` ORDER BY seq`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Record
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var rec model.Record
		if err := json.Unmarshal([]byte(data), &rec); err != nil {
			return nil, fmt.Errorf("decode result: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) SaveCheckpoint(c model.Checkpoint) error {
	c.StateDigest = model.CheckpointDigest(c)
	data, err := model.MarshalCheckpoint(c)
	if err != nil {
		return err
	}
	return s.RetryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO checkpoints
			(run_id, seq, cursor, completed_count, degraded, mode, result_digest,
			 reason, ts_utc, state_digest, block_json)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(run_id, seq) DO UPDATE SET
				cursor=excluded.cursor,
				completed_count=excluded.completed_count,
				degraded=excluded.degraded,
				mode=excluded.mode,
				result_digest=excluded.result_digest,
				reason=excluded.reason,
				ts_utc=excluded.ts_utc,
				state_digest=excluded.state_digest,
				block_json=excluded.block_json`,
			c.RunID, c.Seq, c.Cursor, c.CompletedCount, boolInt(c.Degraded),
			c.Mode, c.ResultDigest, c.Reason, c.TSUTC, c.StateDigest, string(data))
		return err
	})
}

func (s *Store) LatestCheckpoint(runID string) (*model.Checkpoint, error) {
	var data string
	err := s.db.QueryRow(`SELECT block_json FROM checkpoints WHERE run_id=?
		ORDER BY seq DESC LIMIT 1`, runID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c model.Checkpoint
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, err
	}
	if want := model.CheckpointDigest(c); want != c.StateDigest {
		return nil, fmt.Errorf("checkpoint %d digest mismatch: want %s got %s",
			c.Seq, want, c.StateDigest)
	}
	return &c, nil
}

func (s *Store) AppendEvent(e model.Event) (int64, error) {
	var seq int64
	err := s.RetryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE run_id=?`,
			e.RunID).Scan(&seq); err != nil {
			return err
		}
		e.Seq = seq
		data, err := model.MarshalEvent(e)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO events(run_id, seq, event_json, ts_utc)
			VALUES (?,?,?,?)`, e.RunID, seq, string(data), e.TSUTC); err != nil {
			return err
		}
		return tx.Commit()
	})
	return seq, err
}

func (s *Store) AppendComparison(c model.Comparison) (int64, error) {
	var seq int64
	err := s.RetryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM comparisons WHERE run_id=?`,
			c.RunID).Scan(&seq); err != nil {
			return err
		}
		c.Seq = seq
		data, err := model.MarshalComparison(c)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO comparisons(run_id, seq, comparison_json, ts_utc)
			VALUES (?,?,?,?)`, c.RunID, seq, string(data), c.TSUTC); err != nil {
			return err
		}
		return tx.Commit()
	})
	return seq, err
}

func (s *Store) Checkpoints(runID string) ([]model.Checkpoint, error) {
	rows, err := s.db.Query(`SELECT block_json FROM checkpoints WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Checkpoint
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c model.Checkpoint
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Events(runID string) ([]model.Event, error) {
	rows, err := s.db.Query(`SELECT event_json FROM events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e model.Event
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Comparisons(runID string) ([]model.Comparison, error) {
	rows, err := s.db.Query(`SELECT comparison_json FROM comparisons WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Comparison
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c model.Comparison
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Path() string { return s.path }
