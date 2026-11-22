// Package journal persists every experiment step (input, state, result) into
// SQLite so the whole run can be replayed and audited.
package journal

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Journal struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
  run_id      TEXT PRIMARY KEY,
  started_at  TEXT NOT NULL,
  seed        INTEGER NOT NULL,
  corpus_size INTEGER NOT NULL,
  note        TEXT
);
CREATE TABLE IF NOT EXISTS steps (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id       TEXT NOT NULL,
  seq          INTEGER NOT NULL,
  phase        TEXT NOT NULL,
  record_id    TEXT NOT NULL,
  version      TEXT NOT NULL,
  input_sha256 TEXT NOT NULL,
  input_json   TEXT NOT NULL,
  status       TEXT NOT NULL,
  result       TEXT NOT NULL,
  error        TEXT NOT NULL DEFAULT '',
  elapsed_ns   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS comparisons (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id    TEXT NOT NULL,
  phase     TEXT NOT NULL,
  record_id TEXT NOT NULL,
  v1_result TEXT NOT NULL,
  v2_result TEXT NOT NULL,
  divergent INTEGER NOT NULL,
  detail    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_steps_run ON steps(run_id, seq);
`

func Open(path string) (*Journal, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Journal{db: db}, nil
}

func (j *Journal) Close() error { return j.db.Close() }

func (j *Journal) StartRun(runID string, seed int64, corpusSize int, note string) error {
	_, err := j.db.Exec(
		`INSERT INTO runs(run_id, started_at, seed, corpus_size, note) VALUES(?,?,?,?,?)`,
		runID, time.Now().UTC().Format(time.RFC3339Nano), seed, corpusSize, note)
	return err
}

type Step struct {
	Seq       int
	Phase     string
	RecordID  string
	Version   string
	InputHash string
	InputJSON string
	Status    string
	Result    string
	Err       string
	Elapsed   time.Duration
}

func (j *Journal) LogStep(runID string, s Step) error {
	_, err := j.db.Exec(
		`INSERT INTO steps(run_id,seq,phase,record_id,version,input_sha256,input_json,status,result,error,elapsed_ns)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		runID, s.Seq, s.Phase, s.RecordID, s.Version, s.InputHash, s.InputJSON,
		s.Status, s.Result, s.Err, s.Elapsed.Nanoseconds())
	return err
}

func (j *Journal) LogComparison(runID, phase, recordID, v1, v2 string, divergent bool, detail string) error {
	d := 0
	if divergent {
		d = 1
	}
	_, err := j.db.Exec(
		`INSERT INTO comparisons(run_id,phase,record_id,v1_result,v2_result,divergent,detail)
		 VALUES(?,?,?,?,?,?,?)`,
		runID, phase, recordID, v1, v2, d, detail)
	return err
}

// LoadSteps returns all steps of a run ordered by seq, for replay.
func (j *Journal) LoadSteps(runID string) ([]Step, error) {
	rows, err := j.db.Query(
		`SELECT seq,phase,record_id,version,input_sha256,input_json,status,result,error,elapsed_ns
		 FROM steps WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var s Step
		var ns int64
		if err := rows.Scan(&s.Seq, &s.Phase, &s.RecordID, &s.Version, &s.InputHash,
			&s.InputJSON, &s.Status, &s.Result, &s.Err, &ns); err != nil {
			return nil, err
		}
		s.Elapsed = time.Duration(ns)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Counts summarises a table for the report.
func (j *Journal) Counts(runID string) (map[string]int, error) {
	m := map[string]int{}
	rows, err := j.db.Query(`SELECT phase, status, COUNT(*) FROM steps WHERE run_id=? GROUP BY phase, status`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var phase, status string
		var n int
		if err := rows.Scan(&phase, &status, &n); err != nil {
			return nil, err
		}
		m[fmt.Sprintf("%s/%s", phase, status)] = n
	}
	var div int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM comparisons WHERE run_id=? AND divergent=1`, runID).Scan(&div); err != nil {
		return nil, err
	}
	m["divergent"] = div
	return m, rows.Err()
}

// Comparison is one row of the comparisons table.
type Comparison struct {
	Phase     string
	RecordID  string
	V1        string
	V2        string
	Divergent bool
	Detail    string
}

// QueryComparisons returns all comparison rows of a run.
func (j *Journal) QueryComparisons(runID string) ([]Comparison, error) {
	rows, err := j.db.Query(
		`SELECT phase,record_id,v1_result,v2_result,divergent,detail
		 FROM comparisons WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Comparison
	for rows.Next() {
		var c Comparison
		var d int
		if err := rows.Scan(&c.Phase, &c.RecordID, &c.V1, &c.V2, &d, &c.Detail); err != nil {
			return nil, err
		}
		c.Divergent = d == 1
		out = append(out, c)
	}
	return out, rows.Err()
}
