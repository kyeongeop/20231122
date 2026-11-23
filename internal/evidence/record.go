package evidence

import (
	"database/sql"
	"errors"
	"fmt"

	"oauthreview/internal/callback"
)

// ErrCaseExists 同一用例重复入库时返回，避免覆盖原始证据。
var ErrCaseExists = errors.New("case already recorded")

// RecordCase 以事务方式写入原始输入、事件链和自动结论。
func (s *Store) RecordCase(caseID, contentType, source string, cb *callback.Callback, out *callback.Outcome) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existing string
	err = tx.QueryRow(`SELECT case_id FROM cases WHERE case_id = ?`, caseID).Scan(&existing)
	switch {
	case err == nil:
		return ErrCaseExists
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	if _, err := tx.Exec(`INSERT INTO cases
	    (case_id, format, input_hash, content_type, raw_input, source, created_at)
	    VALUES (?, ?, ?, ?, ?, ?, ?)`,
		caseID, string(cb.Format), out.InputHash, contentType,
		cb.Raw, source, cb.ParsedAt.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		return fmt.Errorf("insert case: %w", err)
	}

	for _, ev := range out.Events {
		if _, err := tx.Exec(`INSERT INTO events
		    (case_id, seq, stage, check_name, passed, verdict, reason_code, detail, evidence, at)
		    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ev.CaseID, ev.Seq, string(ev.Stage), ev.Check, ev.Passed,
			string(ev.Verdict), ev.ReasonCode, ev.Detail, ev.Evidence,
			ev.At.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}

	if _, err := tx.Exec(`INSERT INTO decisions
	    (case_id, verdict, trigger_point, reason_code, reason_human, permission_log)
	    VALUES (?, ?, ?, ?, ?, ?)`,
		caseID, string(out.Decision.Verdict), string(out.TriggerPoint),
		out.Decision.ReasonCode, out.Decision.ReasonHuman, out.PermissionLog); err != nil {
		return fmt.Errorf("insert decision: %w", err)
	}
	return tx.Commit()
}

// RecordParseFailure 保留无法解析的原始输入，解析失败同样需要证据。
func (s *Store) RecordParseFailure(caseID, contentType, source string, body []byte, parseErr error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existing string
	err = tx.QueryRow(`SELECT case_id FROM cases WHERE case_id = ?`, caseID).Scan(&existing)
	switch {
	case err == nil:
		return ErrCaseExists
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	if _, err := tx.Exec(`INSERT INTO cases
	    (case_id, format, input_hash, content_type, raw_input, source, created_at)
	    VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		caseID, string(callback.FormatUnknown), hashHex(body), contentType, body, source); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO events
	    (case_id, seq, stage, check_name, passed, verdict, reason_code, detail, evidence, at)
	    VALUES (?, 1, 'parse', 'decode', 0, 'DENY', 'parse.failed', ?, ?,
	            strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		caseID, parseErr.Error(), hashHex(body)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO decisions
	    (case_id, verdict, trigger_point, reason_code, reason_human, permission_log)
	    VALUES (?, 'DENY', 'parse', 'parse.failed', ?, 'rule.parse.failed')`,
		caseID, parseErr.Error()); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveReview 记录人工确认结论，与自动结论分表存放。
func (s *Store) SaveReview(caseID, reviewer string, confirmed bool, notes string) error {
	_, err := s.db.Exec(`INSERT INTO reviews (case_id, reviewer, confirmed, notes, reviewed_at)
	    VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	    ON CONFLICT(case_id) DO UPDATE SET
	      reviewer=excluded.reviewer, confirmed=excluded.confirmed,
	      notes=excluded.notes, reviewed_at=excluded.reviewed_at`,
		caseID, reviewer, confirmed, notes)
	return err
}

func hashHex(b []byte) string {
	return callback.HashExport(b)
}
