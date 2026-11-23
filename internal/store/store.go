// Package store persists audit records in SQLite and implements crash
// recovery: a truncated tail record is detected, quarantined into the
// evidence table (raw bytes + sha256 preserved), and the recovery point
// is itself logged so the first corrupt state stays pinpointable.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	_ "modernc.org/sqlite"

	"trustaudit/internal/record"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    format  INTEGER NOT NULL,
    raw     BLOB    NOT NULL,
    sha256  TEXT    NOT NULL,
    status  TEXT    NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS evidence (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id     INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    raw        BLOB    NOT NULL,
    sha256     TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    at               INTEGER NOT NULL,
    first_bad_log_id INTEGER NOT NULL,
    salvaged         INTEGER NOT NULL,
    note             TEXT    NOT NULL
);
`

// Status values for audit_log rows.
const (
	StatusPending    = "pending"
	StatusValid      = "valid"
	StatusQuarantine = "quarantined"
)

// Entry is one audit_log row.
type Entry struct {
	ID     int64
	Format int
	Raw    []byte
	SHA256 string
	Status string
}

// Store wraps the SQLite handle.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Append inserts one record in pending status and returns its row id.
func (s *Store) Append(raw []byte) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO audit_log(format, raw, sha256, status) VALUES(?,?,?,?)`,
		record.Detect(raw), raw, digest(raw), StatusPending)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Entries returns all audit_log rows in insertion order.
func (s *Store) Entries() ([]Entry, error) {
	rows, err := s.db.Query(`SELECT id, format, raw, sha256, status FROM audit_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Format, &e.Raw, &e.SHA256, &e.Status); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Evidence is one quarantined artifact.
type Evidence struct {
	ID       int64  `json:"id"`
	LogID    int64  `json:"log_id"`
	Kind     string `json:"kind"`
	Raw      []byte `json:"raw"` // base64 in JSON; exact torn bytes preserved
	SHA256   string `json:"sha256"`
	Detail   string `json:"detail"`
	StoredAt int64  `json:"stored_at"`
}

// EvidenceRows returns everything preserved in the evidence table.
func (s *Store) EvidenceRows() ([]Evidence, error) {
	rows, err := s.db.Query(
		`SELECT id, log_id, kind, raw, sha256, detail, created_at FROM evidence ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var ev Evidence
		if err := rows.Scan(&ev.ID, &ev.LogID, &ev.Kind, &ev.Raw, &ev.SHA256, &ev.Detail, &ev.StoredAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
