package audit

import "fmt"

// ConclusionRecord bundles a verdict with its provenance trail.
type ConclusionRecord struct {
	Verdict  string
	Reason   string
	Steps    []Step
	Evidence []Evidence
}

type Step struct {
	Name   string
	Detail string
}

type Evidence struct {
	Key   string
	Value string
}

func (s *Store) InsertConclusion(objectID int64, rec ConclusionRecord, createdAt string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO conclusions(object_id, verdict, reason, created_at) VALUES(?,?,?,?)`,
		objectID, rec.Verdict, rec.Reason, createdAt)
	if err != nil {
		return 0, fmt.Errorf("insert conclusion: %w", err)
	}
	conclusionID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for i, st := range rec.Steps {
		if _, err := tx.Exec(
			`INSERT INTO steps(conclusion_id, seq, name, detail) VALUES(?,?,?,?)`,
			conclusionID, i, st.Name, st.Detail); err != nil {
			return 0, fmt.Errorf("insert step %d: %w", i, err)
		}
	}
	for _, ev := range rec.Evidence {
		if _, err := tx.Exec(
			`INSERT INTO evidence(conclusion_id, key, value) VALUES(?,?,?)`,
			conclusionID, ev.Key, ev.Value); err != nil {
			return 0, fmt.Errorf("insert evidence %q: %w", ev.Key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return conclusionID, nil
}
