package store

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// Schema is the full database layout. Every acceptance-grade fact is kept in
// SQLite: raw offsets live in anchors/samples, absolute time points in the
// *_at_utc columns (RFC3339 with nanosecond precision).
const Schema = `
CREATE TABLE IF NOT EXISTS run_meta (
    key              TEXT PRIMARY KEY,
    value            TEXT NOT NULL,
    updated_at_utc   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anchors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    anchor_index    INTEGER NOT NULL CHECK (anchor_index BETWEEN 1 AND 3),
    magic           TEXT NOT NULL,
    name            TEXT NOT NULL,
    raw_offset      INTEGER NOT NULL,
    length          INTEGER NOT NULL,
    located_at_utc  TEXT NOT NULL,
    UNIQUE(anchor_index)
);

CREATE TABLE IF NOT EXISTS samples (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    kind             TEXT NOT NULL CHECK (kind IN ('attack','benign')),
    raw_path         TEXT NOT NULL,
    sha256           TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    anchor1_offset   INTEGER,
    anchor2_offset   INTEGER,
    anchor3_offset   INTEGER,
    client_epoch     INTEGER,
    server_epoch     INTEGER,
    attest_epoch     INTEGER,
    imported_at_utc  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id         INTEGER NOT NULL REFERENCES samples(id),
    phase             TEXT NOT NULL CHECK (phase IN ('vuln','fixed')),
    state             TEXT NOT NULL
        CHECK (state IN ('pending','running','done','interrupted','error')),
    attempts          INTEGER NOT NULL DEFAULT 0,
    created_at_utc    TEXT NOT NULL,
    started_at_utc    TEXT,
    finished_at_utc   TEXT,
    UNIQUE(sample_id, phase)
);

CREATE TABLE IF NOT EXISTS runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id           INTEGER NOT NULL REFERENCES jobs(id),
    attempt          INTEGER NOT NULL,
    verdict_code     INTEGER,
    verdict_label    TEXT,
    exit_code        INTEGER,
    duration_ns      INTEGER,
    started_at_utc   TEXT NOT NULL,
    finished_at_utc  TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id         INTEGER NOT NULL REFERENCES samples(id),
    run_id            INTEGER REFERENCES runs(id),
    kind              TEXT NOT NULL,
    path              TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    note              TEXT,
    captured_at_utc   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_runs_job ON runs(job_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sample ON evidence(sample_id);
`

// Open opens (creating if needed) the SQLite database with a WAL and busy
// timeout suitable for stop/resume access from one controller process.
func Open(path string) (*sql.DB, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
