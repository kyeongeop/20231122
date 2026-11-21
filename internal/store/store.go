package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store persists run state, checkpoints, findings and evidence events.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	run_id      TEXT PRIMARY KEY,
	image_path  TEXT NOT NULL,
	image_sha256 TEXT NOT NULL,
	params_json TEXT NOT NULL,
	status      TEXT NOT NULL,
	started_ts  TEXT NOT NULL,
	finished_ts TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS checkpoints (
	run_id       TEXT NOT NULL,
	seq          INTEGER NOT NULL,
	next_offset  INTEGER NOT NULL,
	entries_done INTEGER NOT NULL,
	findings_done INTEGER NOT NULL,
	degraded     INTEGER NOT NULL,
	state_hash   TEXT NOT NULL,
	ts_utc       TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS findings (
	run_id        TEXT NOT NULL,
	seq           INTEGER NOT NULL,
	path          TEXT NOT NULL,
	mode          INTEGER NOT NULL,
	uid           INTEGER NOT NULL,
	gid           INTEGER NOT NULL,
	size          INTEGER NOT NULL,
	header_offset INTEGER NOT NULL,
	rule          TEXT NOT NULL,
	severity      TEXT NOT NULL,
	degraded      INTEGER NOT NULL,
	ts_utc        TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS events (
	run_id TEXT NOT NULL,
	seq    INTEGER NOT NULL,
	kind   TEXT NOT NULL,
	detail TEXT NOT NULL,
	offset INTEGER NOT NULL,
	ts_utc TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
`

// Open creates or opens the SQLite database at path.
func Open(path string) (*Store, error) {
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

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// CreateRun registers a new audit run.
func (s *Store) CreateRun(runID, imagePath, imageSHA, paramsJSON, startedTS string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO runs (run_id, image_path, image_sha256, params_json, status, started_ts)
		 VALUES (?,?,?,?, 'running', ?)`, runID, imagePath, imageSHA, paramsJSON, startedTS)
	return err
}

// SetRunStatus updates run status and finish timestamp.
func (s *Store) SetRunStatus(runID, status, finishedTS string) error {
	_, err := s.db.Exec(`UPDATE runs SET status=?, finished_ts=? WHERE run_id=?`, status, finishedTS, runID)
	return err
}

// Checkpoint is a resumable snapshot of scanner progress.
type Checkpoint struct {
	Seq          int64
	NextOffset   int64
	EntriesDone  int64
	FindingsDone int64
	Degraded     bool
	StateHash    string
	TS           string
}

// SaveCheckpoint persists a checkpoint row.
func (s *Store) SaveCheckpoint(runID string, c Checkpoint) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO checkpoints
		 (run_id, seq, next_offset, entries_done, findings_done, degraded, state_hash, ts_utc)
		 VALUES (?,?,?,?,?,?,?,?)`,
		runID, c.Seq, c.NextOffset, c.EntriesDone, c.FindingsDone, boolInt(c.Degraded), c.StateHash, c.TS)
	return err
}

// LatestCheckpoint returns the newest checkpoint for a run, or nil.
func (s *Store) LatestCheckpoint(runID string) (*Checkpoint, error) {
	row := s.db.QueryRow(
		`SELECT seq, next_offset, entries_done, findings_done, degraded, state_hash, ts_utc
		 FROM checkpoints WHERE run_id=? ORDER BY seq DESC LIMIT 1`, runID)
	var c Checkpoint
	var degraded int
	if err := row.Scan(&c.Seq, &c.NextOffset, &c.EntriesDone, &c.FindingsDone, &degraded, &c.StateHash, &c.TS); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	c.Degraded = degraded != 0
	return &c, nil
}

// FindingRow is one persisted audit finding.
type FindingRow struct {
	Seq          int64
	Path         string
	Mode         int64
	UID          int64
	GID          int64
	Size         int64
	HeaderOffset int64
	Rule         string
	Severity     string
	Degraded     bool
	TS           string
}

// InsertFinding appends a finding row.
func (s *Store) InsertFinding(runID string, f FindingRow) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO findings
		 (run_id, seq, path, mode, uid, gid, size, header_offset, rule, severity, degraded, ts_utc)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		runID, f.Seq, f.Path, f.Mode, f.UID, f.GID, f.Size, f.HeaderOffset,
		f.Rule, f.Severity, boolInt(f.Degraded), f.TS)
	return err
}

// Findings returns all findings of a run ordered by seq.
func (s *Store) Findings(runID string) ([]FindingRow, error) {
	rows, err := s.db.Query(
		`SELECT seq, path, mode, uid, gid, size, header_offset, rule, severity, degraded, ts_utc
		 FROM findings WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		var degraded int
		if err := rows.Scan(&f.Seq, &f.Path, &f.Mode, &f.UID, &f.GID, &f.Size,
			&f.HeaderOffset, &f.Rule, &f.Severity, &degraded, &f.TS); err != nil {
			return nil, err
		}
		f.Degraded = degraded != 0
		out = append(out, f)
	}
	return out, rows.Err()
}

// LogEvent appends an evidence event (pause/resume/degrade/verify...).
func (s *Store) LogEvent(runID string, seq int64, kind, detail string, offset int64, ts string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO events (run_id, seq, kind, detail, offset, ts_utc) VALUES (?,?,?,?,?,?)`,
		runID, seq, kind, detail, offset, ts)
	return err
}

// EventRow is one persisted evidence event.
type EventRow struct {
	Seq    int64
	Kind   string
	Detail string
	Offset int64
	TS     string
}

// Events returns all events of a run ordered by seq.
func (s *Store) Events(runID string) ([]EventRow, error) {
	rows, err := s.db.Query(
		`SELECT seq, kind, detail, offset, ts_utc FROM events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Detail, &e.Offset, &e.TS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// NextEventSeq returns the next free event sequence for a run.
func (s *Store) NextEventSeq(runID string) (int64, error) {
	var n sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(seq) FROM events WHERE run_id=?`, runID).Scan(&n); err != nil {
		return 0, err
	}
	if !n.Valid {
		return 0, nil
	}
	return n.Int64 + 1, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
