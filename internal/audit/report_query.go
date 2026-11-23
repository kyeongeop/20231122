package audit

import "fmt"

func (s *Store) loadReportRows(runID int64) ([]reportRow, error) {
	q := `SELECT o.id, o.label, o.kind, o.raw_input, o.sha256, c.id, c.verdict, c.reason
	      FROM objects o JOIN conclusions c ON c.object_id = o.id
	      WHERE o.run_id = ? ORDER BY o.id`
	rows, err := s.db.Query(q, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportRow
	for rows.Next() {
		var r reportRow
		var conclusionID int64
		if err := rows.Scan(&r.ObjectID, &r.Label, &r.Kind, &r.Raw, &r.SHA,
			&conclusionID, &r.Verdict, &r.Reason); err != nil {
			return nil, err
		}
		if err := s.loadSteps(conclusionID, &r); err != nil {
			return nil, err
		}
		if err := s.loadEvidence(conclusionID, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) loadSteps(conclusionID int64, r *reportRow) error {
	rows, err := s.db.Query(
		`SELECT name, detail FROM steps WHERE conclusion_id=? ORDER BY seq`, conclusionID)
	if err != nil {
		return fmt.Errorf("load steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.Name, &st.Detail); err != nil {
			return err
		}
		r.Steps = append(r.Steps, st)
	}
	return rows.Err()
}

func (s *Store) loadEvidence(conclusionID int64, r *reportRow) error {
	rows, err := s.db.Query(
		`SELECT key, value FROM evidence WHERE conclusion_id=? ORDER BY id`, conclusionID)
	if err != nil {
		return fmt.Errorf("load evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ev Evidence
		if err := rows.Scan(&ev.Key, &ev.Value); err != nil {
			return err
		}
		r.Evidence = append(r.Evidence, ev)
	}
	return rows.Err()
}
