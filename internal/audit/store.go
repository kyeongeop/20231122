package audit

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store is the provenance backbone: every conclusion can be traced back to
// the raw input object and the ordered processing steps that produced it.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    tool_version TEXT NOT NULL,
    rules_version TEXT NOT NULL,
    cleanup_ok INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    raw_input TEXT NOT NULL,
    sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conclusions (
    id INTEGER PRIMARY KEY,
    object_id INTEGER NOT NULL REFERENCES objects(id),
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY,
    conclusion_id INTEGER NOT NULL REFERENCES conclusions(id),
    seq INTEGER NOT NULL,
    name TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    conclusion_id INTEGER NOT NULL REFERENCES conclusions(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL
);
`

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) BeginRun(startedAt, toolVersion, rulesVersion string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO runs(started_at, tool_version, rules_version) VALUES(?,?,?)`,
		startedAt, toolVersion, rulesVersion)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinishRun(runID int64, finishedAt string, cleanupOK bool) error {
	flag := 0
	if cleanupOK {
		flag = 1
	}
	_, err := s.db.Exec(
		`UPDATE runs SET finished_at=?, cleanup_ok=? WHERE id=?`, finishedAt, flag, runID)
	return err
}

func (s *Store) InsertObject(runID int64, label, kind, raw, sha256 string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO objects(run_id, label, kind, raw_input, sha256) VALUES(?,?,?,?,?)`,
		runID, label, kind, raw, sha256)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
