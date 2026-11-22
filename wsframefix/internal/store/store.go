// Package store 用 SQLite 持久化攻击样本、重跑记录与锚点证据,
// 使工具支持中途退出后重新进入并继续工作。
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS samples(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  source TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  data BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_samples_sha ON samples(sha256);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sample_id INTEGER NOT NULL REFERENCES samples(id),
  run_at TEXT NOT NULL,
  parser TEXT NOT NULL,
  outcome TEXT NOT NULL,
  anchor TEXT,
  raw_offset INTEGER,
  detail TEXT,
  duration_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_sample ON runs(sample_id);
`

type Store struct{ db *sql.DB }

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

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	return v, err
}

// AddSample 写入一个攻击样本;同 sha256 去重,返回样本 ID 与是否新建。
func (s *Store) AddSample(source, sha256 string, data []byte) (int64, bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO samples(created_at,source,sha256,data) VALUES(?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), source, sha256, data)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var id int64
		if err := s.db.QueryRow(`SELECT id FROM samples WHERE sha256=?`, sha256).Scan(&id); err != nil {
			return 0, false, err
		}
		return id, false, nil
	}
	id, _ := res.LastInsertId()
	return id, true, nil
}

type Sample struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Data      []byte `json:"data"`
}

func (s *Store) GetSample(id int64) (*Sample, error) {
	var sm Sample
	err := s.db.QueryRow(`SELECT id,created_at,source,sha256,data FROM samples WHERE id=?`, id).
		Scan(&sm.ID, &sm.CreatedAt, &sm.Source, &sm.SHA256, &sm.Data)
	if err != nil {
		return nil, err
	}
	return &sm, nil
}

func (s *Store) ListSamples() ([]Sample, error) {
	rows, err := s.db.Query(`SELECT id,created_at,source,sha256,data FROM samples ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var sm Sample
		if err := rows.Scan(&sm.ID, &sm.CreatedAt, &sm.Source, &sm.SHA256, &sm.Data); err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

type Run struct {
	ID         int64          `json:"id"`
	SampleID   int64          `json:"sample_id"`
	RunAt      string         `json:"run_at"`
	Parser     string         `json:"parser"`
	Outcome    string         `json:"outcome"`
	Anchor     sql.NullString `json:"anchor"`
	RawOffset  sql.NullInt64  `json:"raw_offset"`
	Detail     string         `json:"detail"`
	DurationNs int64          `json:"duration_ns"`
}

func (s *Store) AddRun(r *Run) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO runs(sample_id,run_at,parser,outcome,anchor,raw_offset,detail,duration_ns)
		 VALUES(?,?,?,?,?,?,?,?)`,
		r.SampleID, r.RunAt, r.Parser, r.Outcome, r.Anchor, r.RawOffset, r.Detail, r.DurationNs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListRuns(sampleID int64) ([]Run, error) {
	q := `SELECT id,sample_id,run_at,parser,outcome,anchor,raw_offset,detail,duration_ns FROM runs`
	args := []any{}
	if sampleID > 0 {
		q += ` WHERE sample_id=?`
		args = append(args, sampleID)
	}
	q += ` ORDER BY id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.SampleID, &r.RunAt, &r.Parser, &r.Outcome,
			&r.Anchor, &r.RawOffset, &r.Detail, &r.DurationNs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
