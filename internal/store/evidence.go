package store

// Checkpoint is a resumable snapshot of the runner state.
type Checkpoint struct {
	JobID       int64
	Seq         int64
	SavedUTC    string
	NextIndex   int64
	HashState   []byte // serialized crypto/sha256 state
	BatchState  []byte
	BatchBytes  int64
	BatchStart  int64
	BatchRawOff int64
	OutBytes    int64
	Processed   int64
	Degraded    int64
}

// SaveCheckpoint appends a checkpoint row (seq must increase per job).
func (s *Store) SaveCheckpoint(c Checkpoint) error {
	st, err := s.db.Prepare(`INSERT INTO checkpoints
		(job_id,seq,saved_utc,next_index,hash_state,batch_state,batch_bytes,batch_start,batch_raw_off,out_bytes,processed,degraded)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, b := range []struct {
		idx int
		v   int64
	}{{1, c.JobID}, {2, c.Seq}, {4, c.NextIndex}, {7, c.BatchBytes}, {8, c.BatchStart}, {9, c.BatchRawOff}, {10, c.OutBytes}, {11, c.Processed}, {12, c.Degraded}} {
		if err := st.BindInt(b.idx, b.v); err != nil {
			return err
		}
	}
	if err := st.BindText(3, c.SavedUTC); err != nil {
		return err
	}
	if err := st.BindBlob(5, c.HashState); err != nil {
		return err
	}
	if err := st.BindBlob(6, c.BatchState); err != nil {
		return err
	}
	_, err = st.Step()
	return err
}

// LatestCheckpoint returns the checkpoint with the highest seq, or nil.
func (s *Store) LatestCheckpoint(jobID int64) (*Checkpoint, error) {
	st, err := s.db.Prepare(`SELECT seq,saved_utc,next_index,hash_state,batch_state,batch_bytes,batch_start,batch_raw_off,out_bytes,processed,degraded
		FROM checkpoints WHERE job_id=? ORDER BY seq DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return nil, err
	}
	row, err := st.Step()
	if err != nil || !row {
		return nil, err
	}
	return &Checkpoint{
		JobID:       jobID,
		Seq:         st.ColumnInt(0),
		SavedUTC:    st.ColumnText(1),
		NextIndex:   st.ColumnInt(2),
		HashState:   st.ColumnBlob(3),
		BatchState:  st.ColumnBlob(4),
		BatchBytes:  st.ColumnInt(5),
		BatchStart:  st.ColumnInt(6),
		BatchRawOff: st.ColumnInt(7),
		OutBytes:    st.ColumnInt(8),
		Processed:   st.ColumnInt(9),
		Degraded:    st.ColumnInt(10),
	}, nil
}

// Checkpoints lists all checkpoints of a job in seq order.
func (s *Store) Checkpoints(jobID int64) ([]Checkpoint, error) {
	st, err := s.db.Prepare(`SELECT seq,saved_utc,next_index,hash_state,batch_state,batch_bytes,batch_start,batch_raw_off,out_bytes,processed,degraded
		FROM checkpoints WHERE job_id=? ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return nil, err
	}
	var out []Checkpoint
	for {
		row, err := st.Step()
		if err != nil || !row {
			return out, err
		}
		out = append(out, Checkpoint{
			JobID:       jobID,
			Seq:         st.ColumnInt(0),
			SavedUTC:    st.ColumnText(1),
			NextIndex:   st.ColumnInt(2),
			HashState:   st.ColumnBlob(3),
			BatchState:  st.ColumnBlob(4),
			BatchBytes:  st.ColumnInt(5),
			BatchStart:  st.ColumnInt(6),
			BatchRawOff: st.ColumnInt(7),
			OutBytes:    st.ColumnInt(8),
			Processed:   st.ColumnInt(9),
			Degraded:    st.ColumnInt(10),
		})
	}
}

// Batch is the evidence row for one processed batch of records.
type Batch struct {
	JobID      int64
	StartIndex int64
	EndIndex   int64
	OutSHA256  string
	OutBytes   int64
	RawOffset  int64 // raw offset into the original material
	TsUTC      string
}

// SaveBatch inserts a batch evidence row.
func (s *Store) SaveBatch(b Batch) error {
	st, err := s.db.Prepare(`INSERT INTO batches
		(job_id,start_index,end_index,out_sha256,out_bytes,raw_offset,ts_utc)
		VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindInt(1, b.JobID); err != nil {
		return err
	}
	if err := st.BindInt(2, b.StartIndex); err != nil {
		return err
	}
	if err := st.BindInt(3, b.EndIndex); err != nil {
		return err
	}
	if err := st.BindText(4, b.OutSHA256); err != nil {
		return err
	}
	if err := st.BindInt(5, b.OutBytes); err != nil {
		return err
	}
	if err := st.BindInt(6, b.RawOffset); err != nil {
		return err
	}
	if err := st.BindText(7, b.TsUTC); err != nil {
		return err
	}
	_, err = st.Step()
	return err
}

// Batches lists all batch rows of a job ordered by start_index.
func (s *Store) Batches(jobID int64) ([]Batch, error) {
	st, err := s.db.Prepare(`SELECT start_index,end_index,out_sha256,out_bytes,raw_offset,ts_utc
		FROM batches WHERE job_id=? ORDER BY start_index`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return nil, err
	}
	var out []Batch
	for {
		row, err := st.Step()
		if err != nil || !row {
			return out, err
		}
		out = append(out, Batch{
			JobID:      jobID,
			StartIndex: st.ColumnInt(0),
			EndIndex:   st.ColumnInt(1),
			OutSHA256:  st.ColumnText(2),
			OutBytes:   st.ColumnInt(3),
			RawOffset:  st.ColumnInt(4),
			TsUTC:      st.ColumnText(5),
		})
	}
}
