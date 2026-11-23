package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"idorfix/internal/domain"
)

// Store is the SQLite-backed workspace. All writes use WAL and foreign keys
// so an interrupted process never leaves half-written sample/run rows.
type Store struct {
	db *sql.DB
}

const schemaSQL = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
	sample_id    TEXT PRIMARY KEY,
	title        TEXT NOT NULL,
	attack_class TEXT NOT NULL,
	note         TEXT NOT NULL,
	input_sha256 TEXT NOT NULL,
	payload_json TEXT NOT NULL,
	seq          INTEGER NOT NULL,
	created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
	run_id         TEXT PRIMARY KEY,
	sample_id      TEXT NOT NULL REFERENCES samples(sample_id),
	attempt        INTEGER NOT NULL,
	status         TEXT NOT NULL,
	started_at     TEXT NOT NULL,
	finished_at    TEXT,
	pid            INTEGER NOT NULL,
	input_sha256   TEXT NOT NULL,
	rule_version   TEXT NOT NULL,
	outcome        TEXT NOT NULL,
	findings_json  TEXT NOT NULL,
	fragments_json TEXT NOT NULL,
	error_text     TEXT NOT NULL,
	seq            INTEGER NOT NULL,
	UNIQUE(sample_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_runs_sample ON runs(sample_id, seq);
`

// Open opens (creating if needed) the workspace database at dbPath.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	if parent := filepath.Dir(dbPath); parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Meta returns a workspace meta value.
func (s *Store) Meta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetMeta upserts a workspace meta value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// NextSampleSeq returns the insertion order counter for a new sample.
func (s *Store) NextSampleSeq(ctx context.Context) (int, error) {
	var maxSeq sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(seq) FROM samples`).Scan(&maxSeq); err != nil {
		return 0, err
	}
	return int(maxSeq.Int64) + 1, nil
}

// InsertSample stores a sample together with its canonical JSON payload.
func (s *Store) InsertSample(ctx context.Context, sample *domain.Sample, payloadJSON string, seq int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO samples(sample_id, title, attack_class, note, input_sha256, payload_json, seq, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.SampleID, sample.Title, sample.AttackClass, sample.Note,
		sample.InputSHA256, payloadJSON, seq, sample.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))
	return err
}

// SampleExists reports whether sampleID is already stored.
func (s *Store) SampleExists(ctx context.Context, sampleID string) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE sample_id = ?`, sampleID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// SamplePayload returns the canonical JSON payload of one sample.
func (s *Store) SamplePayload(ctx context.Context, sampleID string) (string, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM samples WHERE sample_id = ?`, sampleID).Scan(&payload)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("sample %q not found", sampleID)
	}
	return payload, err
}

// SampleRow is the list-view projection, preserving insertion order.
type SampleRow struct {
	SampleID    string
	Title       string
	AttackClass string
	InputSHA256 string
	Seq         int
}

// ListSamples returns samples in stable insertion order.
func (s *Store) ListSamples(ctx context.Context) ([]SampleRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sample_id, title, attack_class, input_sha256, seq FROM samples ORDER BY seq, sample_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SampleRow
	for rows.Next() {
		var row SampleRow
		if err := rows.Scan(&row.SampleID, &row.Title, &row.AttackClass, &row.InputSHA256, &row.Seq); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
