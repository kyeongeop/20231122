package store

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	"dnscheck/internal/checker"
)

// Null returns a NULL nullable integer, used for run-level evidence rows.
func Null() sql.NullInt64 { return sql.NullInt64{} }

// InsertCase stores one original raw input and its full evaluation result in
// a single transaction. The raw bytes are written once and never updated,
// preserving the unmodified original material alongside its hex dump.
func (s *Store) InsertCase(runID int64, label, raw string, res checker.Result) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	ins, err := tx.Exec(
		`INSERT INTO inputs (run_id, label, sha256, raw_len, raw, raw_hex)
		 VALUES (?,?,?,?,?,?)`,
		runID, label, checker.Digest(raw), len(raw), raw, hex.EncodeToString([]byte(raw)))
	if err != nil {
		return 0, err
	}
	inputID, err := ins.LastInsertId()
	if err != nil {
		return 0, err
	}

	for seq, step := range res.Steps {
		if _, err := tx.Exec(
			`INSERT INTO steps (input_id, seq, name, detail) VALUES (?,?,?,?)`,
			inputID, seq+1, step.Name, step.Detail); err != nil {
			return 0, err
		}
	}

	for i, a := range res.Anchors {
		if _, err := tx.Exec(
			`INSERT INTO anchors (input_id, seq, marker, marker_off, body_start, body_end, body)
			 VALUES (?,?,?,?,?,?,?)`,
			inputID, i+1, a.Marker, a.Offset, a.BodyStart, a.BodyEnd, a.Body); err != nil {
			return 0, err
		}
	}

	for _, f := range res.Findings {
		if _, err := tx.Exec(
			`INSERT INTO findings (input_id, anchor, marker_off, byte_offset, stage, code, message)
			 VALUES (?,?,?,?,?,?,?)`,
			inputID, f.Anchor, f.Offset, f.ByteOffset, f.Stage, f.Code, f.Message); err != nil {
			return 0, err
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO conclusions (input_id, kind, verdict, rationale, created_by, created_at)
		 VALUES (?,?,?,?,?,?)`,
		inputID, "automated", string(res.Verdict), res.Rationale, "checker.Evaluate", now()); err != nil {
		return 0, err
	}

	for key, val := range res.Evidence {
		if _, err := tx.Exec(
			`INSERT INTO evidence (input_id, label, content) VALUES (?,?,?)`,
			inputID, key, val); err != nil {
			return 0, err
		}
	}
	return inputID, tx.Commit()
}

// AddEvidence attaches an external evidence item (e.g. fuzz log excerpt).
func (s *Store) AddEvidence(inputID sql.NullInt64, label, content string) error {
	var id any
	if inputID.Valid {
		id = inputID.Int64
	}
	_, err := s.db.Exec(
		`INSERT INTO evidence (input_id, label, content) VALUES (?,?,?)`, id, label, content)
	return err
}

// AddAction records an actionable follow-up for a run or input.
func (s *Store) AddAction(runID, inputID int64, action, reason, status string) error {
	_, err := s.db.Exec(
		`INSERT INTO next_actions (run_id, input_id, action, reason, status)
		 VALUES (?,?,?,?,?)`, runID, inputID, action, reason, status)
	return err
}

// CountRow is a generic label/count pair used by the report queries.
type CountRow struct {
	Label string
	Count int
}

// VerdictCounts returns the number of inputs per permission verdict.
func (s *Store) VerdictCounts() ([]CountRow, error) {
	rows, err := s.db.Query(
		`SELECT verdict, COUNT(*) FROM conclusions WHERE kind='automated' GROUP BY verdict ORDER BY verdict`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountRow
	for rows.Next() {
		var r CountRow
		if err := rows.Scan(&r.Label, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CaseRow is one row of the trace view returned by ListCases.
type CaseRow struct {
	ID        int64
	Label     string
	SHA256    string
	RawLen    int
	Verdict   string
	Rationale string
	CreatedAt string
}

// ListCases joins each input with its automated conclusion.
func (s *Store) ListCases() ([]CaseRow, error) {
	rows, err := s.db.Query(
		`SELECT i.id, i.label, i.sha256, i.raw_len, c.verdict, c.rationale, c.created_at
		 FROM inputs i JOIN conclusions c ON c.input_id = i.id
		 WHERE c.kind='automated' ORDER BY i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaseRow
	for rows.Next() {
		var r CaseRow
		if err := rows.Scan(&r.ID, &r.Label, &r.SHA256, &r.RawLen,
			&r.Verdict, &r.Rationale, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FindingRow carries the trigger position of one finding.
type FindingRow struct {
	Anchor     string
	MarkerOff  int
	ByteOffset int
	Stage      string
	Code       string
	Message    string
}

// FindingsOf returns the ordered findings for one input.
func (s *Store) FindingsOf(inputID int64) ([]FindingRow, error) {
	rows, err := s.db.Query(
		`SELECT anchor, marker_off, byte_offset, stage, code, message
		 FROM findings WHERE input_id=? ORDER BY id`, inputID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		if err := rows.Scan(&r.Anchor, &r.MarkerOff, &r.ByteOffset,
			&r.Stage, &r.Code, &r.Message); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IntegrityError is returned when a stored raw blob fails its hash check.
type IntegrityError struct{ label string }

func (e IntegrityError) Error() string {
	return fmt.Sprintf("stored raw input %q failed sha256 integrity check", e.label)
}

// VerifyIntegrity re-hashes every stored raw input and fails on any mismatch,
// proving the retained original material was not modified.
func (s *Store) VerifyIntegrity() error {
	rows, err := s.db.Query(`SELECT label, sha256, raw FROM inputs ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var label, want, raw string
		if err := rows.Scan(&label, &want, &raw); err != nil {
			return err
		}
		if got := checker.Digest(raw); got != want {
			return IntegrityError{label: label}
		}
	}
	return rows.Err()
}
