package store

import "fmt"

// Schema for the pausable pipeline. All timestamps are UTC RFC3339Nano.
const schema = `
CREATE TABLE IF NOT EXISTS jobs (
    id            INTEGER PRIMARY KEY,
    created_utc   TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    material_sha  TEXT NOT NULL,
    status        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    job_id     INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    saved_utc  TEXT NOT NULL,
    next_index INTEGER NOT NULL,
    hash_state BLOB NOT NULL,
    batch_state BLOB NOT NULL,
    batch_bytes INTEGER NOT NULL,
    batch_start INTEGER NOT NULL,
    batch_raw_off INTEGER NOT NULL,
    out_bytes  INTEGER NOT NULL,
    processed  INTEGER NOT NULL,
    degraded   INTEGER NOT NULL,
    PRIMARY KEY (job_id, seq)
);
CREATE TABLE IF NOT EXISTS batches (
    job_id      INTEGER NOT NULL,
    start_index INTEGER NOT NULL,
    end_index   INTEGER NOT NULL,
    out_sha256  TEXT NOT NULL,
    out_bytes   INTEGER NOT NULL,
    raw_offset  INTEGER NOT NULL,
    ts_utc      TEXT NOT NULL,
    PRIMARY KEY (job_id, start_index)
);
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    job_id       INTEGER NOT NULL,
    ts_utc       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    raw_offset   INTEGER NOT NULL,
    detail       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS material (
    job_id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL,
    bytes  BLOB NOT NULL
);
`

// Store is the typed persistence layer over DB.
type Store struct{ db *DB }

// OpenStore opens the database and ensures the schema exists.
func OpenStore(path string) (*Store, error) {
	db, err := Open(path)
	if err != nil {
		return nil, err
	}
	if err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// CreateJob inserts a job row and returns its id.
func (s *Store) CreateJob(createdUTC, paramsJSON, materialSHA, status string) (int64, error) {
	st, err := s.db.Prepare(`INSERT INTO jobs(created_utc,params_json,material_sha,status) VALUES(?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := st.BindText(1, createdUTC); err != nil {
		return 0, err
	}
	if err := st.BindText(2, paramsJSON); err != nil {
		return 0, err
	}
	if err := st.BindText(3, materialSHA); err != nil {
		return 0, err
	}
	if err := st.BindText(4, status); err != nil {
		return 0, err
	}
	if _, err := st.Step(); err != nil {
		return 0, err
	}
	return s.db.LastInsertRowID(), nil
}

// SetJobStatus updates the status column of a job.
func (s *Store) SetJobStatus(jobID int64, status string) error {
	st, err := s.db.Prepare(`UPDATE jobs SET status=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindText(1, status); err != nil {
		return err
	}
	if err := st.BindInt(2, jobID); err != nil {
		return err
	}
	_, err = st.Step()
	return err
}

// Job is a row of the jobs table.
type Job struct {
	ID          int64
	CreatedUTC  string
	ParamsJSON  string
	MaterialSHA string
	Status      string
}

// GetJob loads a job row.
func (s *Store) GetJob(jobID int64) (Job, error) {
	st, err := s.db.Prepare(`SELECT id,created_utc,params_json,material_sha,status FROM jobs WHERE id=?`)
	if err != nil {
		return Job{}, err
	}
	defer st.Close()
	if err := st.BindInt(1, jobID); err != nil {
		return Job{}, err
	}
	row, err := st.Step()
	if err != nil {
		return Job{}, err
	}
	if !row {
		return Job{}, fmt.Errorf("job %d not found", jobID)
	}
	return Job{
		ID:          st.ColumnInt(0),
		CreatedUTC:  st.ColumnText(1),
		ParamsJSON:  st.ColumnText(2),
		MaterialSHA: st.ColumnText(3),
		Status:      st.ColumnText(4),
	}, nil
}
