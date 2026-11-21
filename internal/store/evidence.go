package store

import "database/sql"

// EvidenceRow is one persisted audit record.
type EvidenceRow struct {
	EventTime   string
	CaseID      string
	Anchor      string
	RawOffset   uint32
	Cursor      uint32
	Length      uint32
	OffsetField uint32
	InputSize   int
	SHA256      string
	InputPath   string
	Permission  string
	Decision    string
	ParserMode  string
	ErrText     string
	Wrapped     string
	LogLine     string
}

func (s *Store) InsertEvidence(r EvidenceRow) error {
	_, err := s.db.Exec(`INSERT INTO evidence(
		event_time, case_id, anchor, raw_offset, cursor, length, offset_field,
		input_size, sha256, input_path, permission, decision, parser_mode,
		err_text, wrapped, log_line)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.EventTime, r.CaseID, r.Anchor, r.RawOffset, r.Cursor, r.Length,
		r.OffsetField, r.InputSize, r.SHA256, r.InputPath, r.Permission,
		r.Decision, r.ParserMode, r.ErrText, r.Wrapped, r.LogLine)
	return err
}

// PermissionRow records the allow/deny judgement attached to an anchor hit.
type PermissionRow struct {
	EventTime string
	CaseID    string
	Anchor    string
	Principal string
	Granted   bool
	Reason    string
}

func (s *Store) InsertPermission(p PermissionRow) error {
	granted := 0
	if p.Granted {
		granted = 1
	}
	_, err := s.db.Exec(`INSERT INTO permission_decisions(
		event_time, case_id, anchor, principal, granted, reason)
		VALUES(?,?,?,?,?,?)`,
		p.EventTime, p.CaseID, p.Anchor, p.Principal, granted, p.Reason)
	return err
}

func (s *Store) UpsertAnchorHit(caseID, anchor string, cursor uint32) error {
	_, err := s.db.Exec(`INSERT INTO anchor_hits(case_id, anchor, cursor)
		VALUES(?,?,?) ON CONFLICT(case_id, anchor) DO NOTHING`,
		caseID, anchor, cursor)
	return err
}

// EvidenceByCase returns all rows for one case, ordered by event time.
func (s *Store) EvidenceByCase(caseID string) ([]EvidenceRow, error) {
	rows, err := s.db.Query(`SELECT event_time, case_id, anchor, raw_offset,
		cursor, length, offset_field, input_size, sha256, input_path,
		permission, decision, parser_mode, COALESCE(err_text,''),
		COALESCE(wrapped,''), log_line
		FROM evidence WHERE case_id=? ORDER BY id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var r EvidenceRow
		if err := rows.Scan(&r.EventTime, &r.CaseID, &r.Anchor, &r.RawOffset,
			&r.Cursor, &r.Length, &r.OffsetField, &r.InputSize, &r.SHA256,
			&r.InputPath, &r.Permission, &r.Decision, &r.ParserMode,
			&r.ErrText, &r.Wrapped, &r.LogLine); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Count returns total evidence rows.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM evidence`).Scan(&n)
	return n, err
}

var _ = sql.ErrNoRows
