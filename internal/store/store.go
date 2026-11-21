// Package store persists pauses, checkpoints, ordered results, and evidence.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"corpusd/internal/corpus"
	"corpusd/internal/model"

	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	run_id             TEXT PRIMARY KEY,
	corpus_dir         TEXT NOT NULL,
	corpus_fingerprint TEXT NOT NULL,
	config_json        TEXT NOT NULL,
	status             TEXT NOT NULL,
	total_entries      INTEGER NOT NULL,
	cursor             INTEGER NOT NULL DEFAULT 0,
	degraded           INTEGER NOT NULL DEFAULT 0,
	result_digest      TEXT NOT NULL DEFAULT '',
	started_ts         TEXT NOT NULL,
	updated_ts         TEXT NOT NULL,
	finished_ts        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS corpus_entries (
	run_id   TEXT NOT NULL,
	seq      INTEGER NOT NULL,
	name     TEXT NOT NULL,
	sha256   TEXT NOT NULL,
	bytes    INTEGER NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS checkpoints (
	run_id         TEXT NOT NULL,
	seq            INTEGER NOT NULL,
	cursor         INTEGER NOT NULL,
	completed_count INTEGER NOT NULL,
	degraded       INTEGER NOT NULL,
	mode           TEXT NOT NULL,
	result_digest  TEXT NOT NULL,
	reason         TEXT NOT NULL,
	ts_utc         TEXT NOT NULL,
	state_digest   TEXT NOT NULL,
	block_json     TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS results (
	run_id        TEXT NOT NULL,
	seq           INTEGER NOT NULL,
	record_json   TEXT NOT NULL,
	record_digest TEXT NOT NULL,
	ts_utc        TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS events (
	run_id    TEXT NOT NULL,
	seq       INTEGER NOT NULL,
	event_json TEXT NOT NULL,
	ts_utc    TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS comparisons (
	run_id          TEXT NOT NULL,
	seq             INTEGER NOT NULL,
	comparison_json TEXT NOT NULL,
	ts_utc          TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_results_run_seq ON results(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);
`

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(0)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite pragma: %w", err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

type RunState struct {
	RunID             string
	CorpusDir         string
	CorpusFingerprint string
	Config            model.Config
	Status            string
	TotalEntries      int64
	Cursor            int64
	Degraded          bool
	ResultDigest      string
	StartedTS         string
	UpdatedTS         string
	FinishedTS        string
}

func (s *Store) CreateRun(runID, corpusDir, fingerprint string, cfg model.Config, entries []corpus.Entry, ts string) (bool, error) {
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE run_id=?`, runID).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists != 0 {
		return false, nil
	}
	_, err = tx.Exec(`INSERT INTO runs
		(run_id, corpus_dir, corpus_fingerprint, config_json, status, total_entries,
		 cursor, degraded, result_digest, started_ts, updated_ts)
		VALUES (?,?,?,?, 'running', ?, 0, 0, '', ?, ?)`,
		runID, corpusDir, fingerprint, string(cfgJSON), len(entries), ts, ts)
	if err != nil {
		return false, err
	}
	stmt, err := tx.Prepare(`INSERT INTO corpus_entries(run_id, seq, name, sha256, bytes) VALUES (?,?,?,?,?)`)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if _, err := stmt.Exec(runID, e.Seq, e.Name, e.SHA256, e.Bytes); err != nil {
			stmt.Close()
			return false, err
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) Run(runID string) (RunState, bool, error) {
	var run RunState
	var cfgJSON string
	var degraded int
	err := s.db.QueryRow(`SELECT run_id, corpus_dir, corpus_fingerprint, config_json,
		status, total_entries, cursor, degraded, result_digest, started_ts,
		updated_ts, finished_ts FROM runs WHERE run_id=?`, runID).Scan(
		&run.RunID, &run.CorpusDir, &run.CorpusFingerprint, &cfgJSON,
		&run.Status, &run.TotalEntries, &run.Cursor, &degraded,
		&run.ResultDigest, &run.StartedTS, &run.UpdatedTS, &run.FinishedTS)
	if errors.Is(err, sql.ErrNoRows) {
		return RunState{}, false, nil
	}
	if err != nil {
		return RunState{}, false, err
	}
	if err := json.Unmarshal([]byte(cfgJSON), &run.Config); err != nil {
		return RunState{}, false, fmt.Errorf("decode run config: %w", err)
	}
	run.Degraded = degraded != 0
	return run, true, nil
}

func (s *Store) Entries(runID string) ([]corpus.Entry, error) {
	rows, err := s.db.Query(`SELECT seq, name, sha256, bytes FROM corpus_entries
		WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []corpus.Entry
	for rows.Next() {
		var e corpus.Entry
		if err := rows.Scan(&e.Seq, &e.Name, &e.SHA256, &e.Bytes); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) UpdateProgress(runID, status string, cursor int64, degraded bool, digest, ts string) error {
	finished := ""
	if status == "completed" || status == "completed_degraded" || status == "failed" {
		finished = ts
	}
	_, err := s.db.Exec(`UPDATE runs SET status=?, cursor=?, degraded=?, result_digest=?,
		updated_ts=?, finished_ts=CASE WHEN ?='' THEN finished_ts ELSE ? END
		WHERE run_id=?`, status, cursor, boolInt(degraded), digest, ts, finished, finished, runID)
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// RetryBusy retries SQLite lock contention, which is common when another
// exporter is reading the WAL database.
func (s *Store) RetryBusy(fn func() error) error {
	var err error
	delay := 20 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "database is locked") && !strings.Contains(msg, "database table is locked") {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return err
}
