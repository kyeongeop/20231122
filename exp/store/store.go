package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed evidence log for the experiment.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    meta TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    object_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    input_hex TEXT NOT NULL,
    state_before TEXT NOT NULL,
    state_after TEXT NOT NULL,
    result TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) BeginRun(meta string) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO runs(started_at, meta) VALUES(?, ?)",
		time.Now().UTC().Format(time.RFC3339), meta)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) LogStep(runID int64, objectID string, version, seq int,
	inputHex, stateBefore, stateAfter, result string) error {
	_, err := s.db.Exec(
		`INSERT INTO steps(run_id, object_id, version, seq, input_hex,
		 state_before, state_after, result) VALUES(?,?,?,?,?,?,?,?)`,
		runID, objectID, version, seq, inputHex, stateBefore, stateAfter, result)
	return err
}

func (s *Store) LogVerification(runID int64, kind, objectID, outcome, detail string) error {
	_, err := s.db.Exec(
		"INSERT INTO verifications(run_id, kind, object_id, outcome, detail) VALUES(?,?,?,?,?)",
		runID, kind, objectID, outcome, detail)
	return err
}

// Steps returns all recorded steps for an object/version, ordered by seq.
func (s *Store) Steps(runID int64, objectID string, version int) ([]StepRow, error) {
	rows, err := s.db.Query(
		`SELECT seq, input_hex, state_before, state_after, result FROM steps
		 WHERE run_id=? AND object_id=? AND version=? ORDER BY seq`,
		runID, objectID, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StepRow
	for rows.Next() {
		var r StepRow
		if err := rows.Scan(&r.Seq, &r.InputHex, &r.StateBefore, &r.StateAfter, &r.Result); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type StepRow struct {
	Seq         int
	InputHex    string
	StateBefore string
	StateAfter  string
	Result      string
}

// Divergences returns [object_id, v1_final, v2_final] for objects whose
// final step result/state differs between versions.
func (s *Store) Divergences(runID int64) ([][3]string, error) {
	rows, err := s.db.Query(
		`SELECT object_id, version, state_after || '|' || result FROM steps a
		 WHERE run_id=? AND seq = (
		     SELECT MAX(seq) FROM steps b
		     WHERE b.run_id=a.run_id AND b.object_id=a.object_id AND b.version=a.version)
		 ORDER BY object_id, version`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	last := map[string]map[int]string{}
	var order []string
	for rows.Next() {
		var obj string
		var ver int
		var fin string
		if err := rows.Scan(&obj, &ver, &fin); err != nil {
			return nil, err
		}
		if last[obj] == nil {
			last[obj] = map[int]string{}
			order = append(order, obj)
		}
		last[obj][ver] = fin
	}
	var out [][3]string
	for _, obj := range order {
		if last[obj][1] != last[obj][2] {
			out = append(out, [3]string{obj, last[obj][1], last[obj][2]})
		}
	}
	return out, rows.Err()
}

// Verifications returns [kind, object_id, outcome, detail] rows.
func (s *Store) Verifications(runID int64) ([][4]string, error) {
	rows, err := s.db.Query(
		`SELECT kind, object_id, outcome, detail FROM verifications
		 WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][4]string
	for rows.Next() {
		var r [4]string
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
