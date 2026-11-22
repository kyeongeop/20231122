package store

import (
	"fmt"
	"time"

	"ckaudit/internal/sqlite"
)

type Store struct {
	db *sqlite.DB
}

func Open(path string) (*Store, error) {
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := db.ExecScript(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func nowTS() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) CreateRun(r *Run) (int64, error) {
	ts := nowTS()
	err := s.db.Exec(
		`INSERT INTO runs(name,status,mode,max_runs,max_len,seed,jobs,created_at,updated_at,pid)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.Name, r.Status, r.Mode, r.MaxRuns, r.MaxLen, r.Seed, r.Jobs, ts, ts, r.PID)
	if err != nil {
		return 0, err
	}
	r.ID = s.db.LastInsertRowID()
	r.CreatedAt, r.UpdatedAt = ts, ts
	return r.ID, nil
}

func (s *Store) TouchRun(id int64, status string, exitCode *int, note string) error {
	var code any
	if exitCode != nil {
		code = int64(*exitCode)
	}
	return s.db.Exec(
		`UPDATE runs SET status=?, exit_code=COALESCE(?, exit_code),
		 exec_note=?, updated_at=? WHERE id=?`,
		status, code, note, nowTS(), id)
}

func (s *Store) Heartbeat(id int64) error {
	return s.db.Exec(`UPDATE runs SET updated_at=? WHERE id=?`, nowTS(), id)
}

func (s *Store) GetRun(id int64) (*Run, error) {
	rows, err := s.db.Query(
		`SELECT id,name,status,mode,max_runs,max_len,seed,jobs,created_at,updated_at,
		        pid,exit_code,COALESCE(exec_note,'') FROM runs WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("run %d not found", id)
	}
	r := &Run{
		ID: rows.ColumnInt64(0), Name: rows.ColumnText(1), Status: rows.ColumnText(2),
		Mode: rows.ColumnText(3), MaxRuns: rows.ColumnInt64(4), MaxLen: int(rows.ColumnInt64(5)),
		Seed: rows.ColumnInt64(6), Jobs: int(rows.ColumnInt64(7)),
		CreatedAt: rows.ColumnText(8), UpdatedAt: rows.ColumnText(9),
		PID: rows.ColumnInt64(10), ExecNote: rows.ColumnText(12),
	}
	if !rows.ColumnIsNull(11) {
		v := int(rows.ColumnInt64(11))
		r.ExitCode = &v
	}
	return r, nil
}

func (s *Store) LatestRun() (*Run, error) {
	id, err := s.db.QueryString(`SELECT id FROM runs ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return nil, fmt.Errorf("no runs yet")
	}
	var rid int64
	if _, err := fmt.Sscanf(id, "%d", &rid); err != nil {
		return nil, err
	}
	return s.GetRun(rid)
}

func (s *Store) AddSample(smp *Sample) error {
	side := any(smp.Side)
	if smp.Side == "" {
		side = nil
	}
	boundary := any(smp.Boundary)
	if smp.Boundary == "" {
		boundary = nil
	}
	param := any(smp.ParamValue)
	if smp.ParamValue == "" {
		param = nil
	}
	err := s.db.Exec(
		`INSERT INTO samples(run_id,sample_key,scenario,boundary,side,param_value,input)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(run_id,sample_key) DO NOTHING`,
		smp.RunID, smp.SampleKey, smp.Scenario, boundary, side, param, smp.Input)
	if err != nil {
		return err
	}
	id, qerr := s.db.QueryString(
		`SELECT id FROM samples WHERE run_id=? AND sample_key=?`, smp.RunID, smp.SampleKey)
	if qerr != nil {
		return qerr
	}
	_, err = fmt.Sscanf(id, "%d", &smp.ID)
	return err
}

func (s *Store) SetSampleStatus(id int64, status string) error {
	return s.db.Exec(
		`UPDATE samples SET status=?, attempts=attempts+1 WHERE id=?`, status, id)
}

func (s *Store) RequeueRunning(runID int64) (int64, error) {
	if err := s.db.Exec(
		`UPDATE samples SET status='pending' WHERE run_id=? AND status='running'`,
		runID); err != nil {
		return 0, err
	}
	return int64(s.db.Changes()), nil
}

func (s *Store) PendingSamples(runID int64) ([]Sample, error) {
	rows, err := s.db.Query(
		`SELECT id,run_id,sample_key,scenario,COALESCE(boundary,''),
		        COALESCE(side,''),COALESCE(param_value,''),input,status,attempts
		 FROM samples WHERE run_id=? AND status IN ('pending','running')
		 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSamples(rows)
}

func (s *Store) AllSamples(runID int64) ([]Sample, error) {
	rows, err := s.db.Query(
		`SELECT id,run_id,sample_key,scenario,COALESCE(boundary,''),
		        COALESCE(side,''),COALESCE(param_value,''),input,status,attempts
		 FROM samples WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSamples(rows)
}
