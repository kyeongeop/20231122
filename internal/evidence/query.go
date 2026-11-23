package evidence

import (
	"database/sql"

	"oauthreview/internal/callback"
)

// CaseRow 是报告渲染需要的单条用例聚合视图。
type CaseRow struct {
	CaseID        string
	Format        string
	InputHash     string
	ContentType   string
	RawInput      []byte
	Source        string
	CreatedAt     string
	Verdict       string
	TriggerPoint  string
	ReasonCode    string
	ReasonHuman   string
	PermissionLog string
	Events        []callback.Event
	Review        *ReviewRow
}

// ReviewRow 是人工确认记录。
type ReviewRow struct {
	Reviewer   string
	Confirmed  bool
	Notes      string
	ReviewedAt string
}

// ListCases 聚合 cases/decisions/events/reviews，供报告层使用。
func (s *Store) ListCases() ([]CaseRow, error) {
	rows, err := s.db.Query(`
	    SELECT c.case_id, c.format, c.input_hash, c.content_type, c.raw_input,
	           c.source, c.created_at,
	           d.verdict, d.trigger_point, d.reason_code, d.reason_human, d.permission_log
	    FROM cases c JOIN decisions d ON d.case_id = c.case_id
	    ORDER BY c.case_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CaseRow
	for rows.Next() {
		var r CaseRow
		if err := rows.Scan(&r.CaseID, &r.Format, &r.InputHash, &r.ContentType,
			&r.RawInput, &r.Source, &r.CreatedAt, &r.Verdict, &r.TriggerPoint,
			&r.ReasonCode, &r.ReasonHuman, &r.PermissionLog); err != nil {
			return nil, err
		}
		evs, err := s.events(r.CaseID)
		if err != nil {
			return nil, err
		}
		r.Events = evs
		r.Review = s.review(r.CaseID)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) events(caseID string) ([]callback.Event, error) {
	rows, err := s.db.Query(`
	    SELECT seq, stage, check_name, passed, verdict, COALESCE(reason_code,''),
	           COALESCE(detail,''), COALESCE(evidence,''), at
	    FROM events WHERE case_id = ? ORDER BY seq`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evs []callback.Event
	for rows.Next() {
		var ev callback.Event
		var passed int
		var at string
		if err := rows.Scan(&ev.Seq, &ev.Stage, &ev.Check, &passed, &ev.Verdict,
			&ev.ReasonCode, &ev.Detail, &ev.Evidence, &at); err != nil {
			return nil, err
		}
		ev.CaseID = caseID
		ev.Passed = passed == 1
		evs = append(evs, ev)
	}
	return evs, rows.Err()
}

func (s *Store) review(caseID string) *ReviewRow {
	var r ReviewRow
	var confirmed int
	err := s.db.QueryRow(`SELECT reviewer, confirmed, COALESCE(notes,''), reviewed_at
	    FROM reviews WHERE case_id = ?`, caseID).
		Scan(&r.Reviewer, &confirmed, &r.Notes, &r.ReviewedAt)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return nil
	}
	r.Confirmed = confirmed == 1
	return &r
}
