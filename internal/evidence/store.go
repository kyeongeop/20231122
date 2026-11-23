package evidence

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store 把每个用例的原始输入、事件链、自动结论持久化到 SQLite。
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS cases (
    case_id      TEXT PRIMARY KEY,
    format       TEXT NOT NULL,
    input_hash   TEXT NOT NULL,
    content_type TEXT NOT NULL,
    raw_input    BLOB NOT NULL,
    source       TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    stage       TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    verdict     TEXT NOT NULL,
    reason_code TEXT,
    detail      TEXT,
    evidence    TEXT,
    at          TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    case_id        TEXT PRIMARY KEY,
    verdict        TEXT NOT NULL,
    trigger_point  TEXT NOT NULL,
    reason_code    TEXT NOT NULL,
    reason_human   TEXT NOT NULL,
    permission_log TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id)
);
CREATE TABLE IF NOT EXISTS reviews (
    case_id      TEXT PRIMARY KEY,
    reviewer     TEXT NOT NULL,
    confirmed    INTEGER NOT NULL,
    notes        TEXT,
    reviewed_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
`

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

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }
