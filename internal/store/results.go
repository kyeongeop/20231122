package store

import (
	"fmt"

	"ckaudit/internal/sqlite"
)

func scanSamples(rows *sqlite.Rows) ([]Sample, error) {
	var out []Sample
	for rows.Next() {
		out = append(out, Sample{
			ID: rows.ColumnInt64(0), RunID: rows.ColumnInt64(1),
			SampleKey: rows.ColumnText(2), Scenario: rows.ColumnText(3),
			Boundary: rows.ColumnText(4), Side: rows.ColumnText(5),
			ParamValue: rows.ColumnText(6), Input: rows.ColumnText(7),
			Status: rows.ColumnText(8), Attempts: int(rows.ColumnInt64(9)),
		})
	}
	return out, nil
}

func (s *Store) AddFindings(sampleID int64, findings []Finding) error {
	for _, f := range findings {
		if err := s.db.Exec(
			`INSERT INTO findings(sample_id,severity,code,message) VALUES(?,?,?,?)`,
			sampleID, f.Severity, f.Code, f.Message); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ClearFindings(sampleID int64) error {
	return s.db.Exec(`DELETE FROM findings WHERE sample_id=?`, sampleID)
}

func (s *Store) Findings(sampleID int64) ([]Finding, error) {
	rows, err := s.db.Query(
		`SELECT severity,code,message FROM findings WHERE sample_id=? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		out = append(out, Finding{
			Severity: rows.ColumnText(0), Code: rows.ColumnText(1),
			Message: rows.ColumnText(2),
		})
	}
	return out, nil
}

func (s *Store) AddEvidence(sampleID int64, ev Evidence) error {
	return s.db.Exec(
		`INSERT INTO evidence(sample_id,kind,path,sha256,bytes,created_at)
		 VALUES(?,?,?,?,?,?)`,
		sampleID, ev.Kind, ev.Path, ev.SHA256, ev.Bytes, ev.CreatedAt)
}

func (s *Store) Evidence(sampleID int64) ([]Evidence, error) {
	rows, err := s.db.Query(
		`SELECT kind,path,sha256,bytes,created_at FROM evidence
		 WHERE sample_id=? ORDER BY id`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		out = append(out, Evidence{
			Kind: rows.ColumnText(0), Path: rows.ColumnText(1),
			SHA256: rows.ColumnText(2), Bytes: rows.ColumnInt64(3),
			CreatedAt: rows.ColumnText(4),
		})
	}
	return out, nil
}

type RunSummary struct {
	Run
	Total, OK, Crash, Error, Pending int
}

func (s *Store) ListRuns() ([]RunSummary, error) {
	rows, err := s.db.Query(
		`SELECT r.id,r.name,r.status,r.mode,r.max_runs,r.max_len,r.seed,r.jobs,
		        r.created_at,r.updated_at,r.pid,r.exit_code,COALESCE(r.exec_note,''),
		        COUNT(s.id),
		        SUM(CASE WHEN s.status='ok' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN s.status='crash' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN s.status='error' THEN 1 ELSE 0 END),
		        SUM(CASE WHEN s.status IN ('pending','running') THEN 1 ELSE 0 END)
		 FROM runs r LEFT JOIN samples s ON s.run_id=r.id
		 GROUP BY r.id ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		rs := RunSummary{
			Run: Run{
				ID: rows.ColumnInt64(0), Name: rows.ColumnText(1),
				Status: rows.ColumnText(2), Mode: rows.ColumnText(3),
				MaxRuns: rows.ColumnInt64(4), MaxLen: int(rows.ColumnInt64(5)),
				Seed: rows.ColumnInt64(6), Jobs: int(rows.ColumnInt64(7)),
				CreatedAt: rows.ColumnText(8), UpdatedAt: rows.ColumnText(9),
				PID: rows.ColumnInt64(10), ExecNote: rows.ColumnText(12),
			},
			Total: int(rows.ColumnInt64(13)), OK: int(rows.ColumnInt64(14)),
			Crash: int(rows.ColumnInt64(15)), Error: int(rows.ColumnInt64(16)),
			Pending: int(rows.ColumnInt64(17)),
		}
		if !rows.ColumnIsNull(11) {
			v := int(rows.ColumnInt64(11))
			rs.ExitCode = &v
		}
		out = append(out, rs)
	}
	return out, nil
}

func (s *Store) SampleByKey(runID int64, key string) (*Sample, error) {
	rows, err := s.db.Query(
		`SELECT id,run_id,sample_key,scenario,COALESCE(boundary,''),
		        COALESCE(side,''),COALESCE(param_value,''),input,status,attempts
		 FROM samples WHERE run_id=? AND sample_key=?`, runID, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got, err := scanSamples(rows)
	if err != nil || len(got) == 0 {
		return nil, fmt.Errorf("sample %q not found in run %d", key, runID)
	}
	return &got[0], nil
}
