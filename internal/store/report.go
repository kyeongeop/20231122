package store

import "database/sql"

// Report-side read models.

type RunView struct {
	ID        int64
	Name      string
	Tool      string
	Status    string
	StartedAt string
	EndedAt   string
	Events    []EventView
}

type EventView struct {
	Seq    int
	Kind   string
	Detail string
	At     string
}

type InputView struct {
	ID          int64
	RunID       int64
	Label       string
	SHA256      string
	Content     string
	Steps       []StepView
	Evidence    []EvidenceView
	Automated   []ConclusionView
	Manual      []ConclusionView
	NextActions []ActionView
}

type StepView struct {
	Seq    int
	Name   string
	Detail string
}

type ConclusionView struct {
	Verdict   string
	Rationale string
	CreatedBy string
	CreatedAt string
}

type EvidenceView struct {
	Label   string
	Content string
}

type ActionView struct {
	Action string
	Reason string
	Status string
}

// Report is the full page model.
type Report struct {
	Runs   []RunView
	Inputs []InputView
	// RunActions are follow-ups attached to a whole run (e.g. failures).
	RunActions map[int64][]ActionView
}

// LoadReport reads everything the page needs.
func (s *Store) LoadReport() (*Report, error) {
	rep := &Report{RunActions: map[int64][]ActionView{}}

	runRows, err := s.db.Query(
		`SELECT id, name, tool, status, started_at, COALESCE(ended_at,'') FROM runs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer runRows.Close()
	for runRows.Next() {
		var r RunView
		if err := runRows.Scan(&r.ID, &r.Name, &r.Tool, &r.Status, &r.StartedAt, &r.EndedAt); err != nil {
			return nil, err
		}
		rep.Runs = append(rep.Runs, r)
	}
	if err := runRows.Err(); err != nil {
		return nil, err
	}

	for i := range rep.Runs {
		ev, err := s.loadEvents(rep.Runs[i].ID)
		if err != nil {
			return nil, err
		}
		rep.Runs[i].Events = ev
		acts, err := s.loadActions(rep.Runs[i].ID, 0)
		if err != nil {
			return nil, err
		}
		rep.RunActions[rep.Runs[i].ID] = acts
	}

	inRows, err := s.db.Query(
		`SELECT id, run_id, label, sha256, content FROM inputs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer inRows.Close()
	for inRows.Next() {
		var iv InputView
		if err := inRows.Scan(&iv.ID, &iv.RunID, &iv.Label, &iv.SHA256, &iv.Content); err != nil {
			return nil, err
		}
		rep.Inputs = append(rep.Inputs, iv)
	}
	if err := inRows.Err(); err != nil {
		return nil, err
	}

	for i := range rep.Inputs {
		if err := s.fillInput(&rep.Inputs[i]); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func (s *Store) loadEvents(runID int64) ([]EventView, error) {
	rows, err := s.db.Query(
		`SELECT seq, kind, detail, at FROM run_events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventView
	for rows.Next() {
		var e EventView
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) loadActions(runID, inputID int64) ([]ActionView, error) {
	var rows *sql.Rows
	var err error
	if inputID > 0 {
		rows, err = s.db.Query(
			`SELECT action, reason, status FROM next_actions WHERE input_id=? ORDER BY id`, inputID)
	} else {
		rows, err = s.db.Query(
			`SELECT action, reason, status FROM next_actions WHERE run_id=? AND input_id IS NULL ORDER BY id`, runID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionView
	for rows.Next() {
		var a ActionView
		if err := rows.Scan(&a.Action, &a.Reason, &a.Status); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) fillInput(iv *InputView) error {
	stepRows, err := s.db.Query(
		`SELECT seq, name, detail FROM steps WHERE input_id=? ORDER BY seq`, iv.ID)
	if err != nil {
		return err
	}
	defer stepRows.Close()
	for stepRows.Next() {
		var st StepView
		if err := stepRows.Scan(&st.Seq, &st.Name, &st.Detail); err != nil {
			return err
		}
		iv.Steps = append(iv.Steps, st)
	}
	if err := stepRows.Err(); err != nil {
		return err
	}

	conRows, err := s.db.Query(
		`SELECT kind, verdict, rationale, created_by, created_at
		 FROM conclusions WHERE input_id=? ORDER BY id`, iv.ID)
	if err != nil {
		return err
	}
	defer conRows.Close()
	for conRows.Next() {
		var kind string
		var c ConclusionView
		if err := conRows.Scan(&kind, &c.Verdict, &c.Rationale, &c.CreatedBy, &c.CreatedAt); err != nil {
			return err
		}
		if kind == "manual" {
			iv.Manual = append(iv.Manual, c)
		} else {
			iv.Automated = append(iv.Automated, c)
		}
	}
	if err := conRows.Err(); err != nil {
		return err
	}

	evRows, err := s.db.Query(
		`SELECT label, content FROM evidence WHERE input_id=? ORDER BY id`, iv.ID)
	if err != nil {
		return err
	}
	defer evRows.Close()
	for evRows.Next() {
		var e EvidenceView
		if err := evRows.Scan(&e.Label, &e.Content); err != nil {
			return err
		}
		iv.Evidence = append(iv.Evidence, e)
	}
	if err := evRows.Err(); err != nil {
		return err
	}

	iv.NextActions, err = s.loadActions(0, iv.ID)
	return err
}
