package store

// Event kinds recorded by the runner.
const (
	KindDegraded    = "degraded"
	KindResource    = "resource-exhausted"
	KindPaused      = "paused"
	KindResumed     = "resumed"
	KindCompleted   = "completed"
	KindHardFailure = "hard-failure"
)

// Event is a key-evidence row: what happened, when (UTC), where in the
// record stream, and at which raw offset into the original material.
type Event struct {
	ID          int64
	JobID       int64
	TsUTC       string
	Kind        string
	RecordIndex int64
	RawOffset   int64
	Detail      string
}

// SaveEvent appends an event row.
func (s *Store) SaveEvent(e Event) error {
	st, err := s.db.Prepare(`INSERT INTO events
		(job_id,ts_utc,kind,record_index,raw_offset,detail) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindInt(1, e.JobID); err != nil {
		return err
	}
	if err := st.BindText(2, e.TsUTC); err != nil {
		return err
	}
	if err := st.BindText(3, e.Kind); err != nil {
		return err
	}
	if err := st.BindInt(4, e.RecordIndex); err != nil {
		return err
	}
	if err := st.BindInt(5, e.RawOffset); err != nil {
		return err
	}
	if err := st.BindText(6, e.Detail); err != nil {
		return err
	}
	_, err = st.Step()
	return err
}

// Events lists all events of a job ordered by id.
func (s *Store) Events(jobID int64) ([]Event, error) {
	st, err := s.db.Prepare(`SELECT id,ts_utc,kind,record_index,raw_offset,detail
		FROM events WHERE job_id=? ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return nil, err
	}
	var out []Event
	for {
		row, err := st.Step()
		if err != nil || !row {
			return out, err
		}
		out = append(out, Event{
			ID:          st.ColumnInt(0),
			JobID:       jobID,
			TsUTC:       st.ColumnText(1),
			Kind:        st.ColumnText(2),
			RecordIndex: st.ColumnInt(3),
			RawOffset:   st.ColumnInt(4),
			Detail:      st.ColumnText(5),
		})
	}
}

// SaveMaterial stores the unmodified original material for a job.
func (s *Store) SaveMaterial(jobID int64, sha256 string, bytes []byte) error {
	st, err := s.db.Prepare(`INSERT OR REPLACE INTO material(job_id,sha256,bytes) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return err
	}
	if err := st.BindText(2, sha256); err != nil {
		return err
	}
	if err := st.BindBlob(3, bytes); err != nil {
		return err
	}
	_, err = st.Step()
	return err
}

// LoadMaterial returns the preserved original material and its hash.
func (s *Store) LoadMaterial(jobID int64) (sha256 string, bytes []byte, err error) {
	st, err := s.db.Prepare(`SELECT sha256,bytes FROM material WHERE job_id=?`)
	if err != nil {
		return "", nil, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return "", nil, err
	}
	row, err := st.Step()
	if err != nil || !row {
		return "", nil, err
	}
	return st.ColumnText(0), st.ColumnBlob(1), nil
}
