// Package evidence persists verification records to SQLite and exports them
// as JSONL with a fixed field order so a colleague can independently reload
// and re-verify every artifact.
package evidence

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"
)

// FieldOrder is the canonical column order. Export and reload both enforce
// it; the meta table stores a copy so a reloaded database can prove the
// producer and consumer agree on the schema.
var FieldOrder = []string{
	"record_id",
	"ts",
	"scenario",
	"input_sha256",
	"input_len",
	"attack_vector",
	"trigger_func",
	"trigger_file",
	"trigger_line",
	"perm_subject",
	"perm_action",
	"perm_decision",
	"perm_reason",
	"expanded_bytes",
	"expansion_count",
	"quota_max_output_bytes",
	"quota_max_expansion_ratio",
	"log_file",
	"log_digest",
	"notes",
}

const schemaVersion = 1

// Record is one verification event. The JSON field order matches FieldOrder
// because encoding/json emits struct fields in declaration order.
type Record struct {
	RecordID               string  `json:"record_id"`
	TS                     string  `json:"ts"`
	Scenario               string  `json:"scenario"`
	InputSHA256            string  `json:"input_sha256"`
	InputLen               int64   `json:"input_len"`
	AttackVector           string  `json:"attack_vector"`
	TriggerFunc            string  `json:"trigger_func"`
	TriggerFile            string  `json:"trigger_file"`
	TriggerLine            int64   `json:"trigger_line"`
	PermSubject            string  `json:"perm_subject"`
	PermAction             string  `json:"perm_action"`
	PermDecision           string  `json:"perm_decision"`
	PermReason             string  `json:"perm_reason"`
	ExpandedBytes          int64   `json:"expanded_bytes"`
	ExpansionCount         int64   `json:"expansion_count"`
	QuotaMaxOutputBytes    int64   `json:"quota_max_output_bytes"`
	QuotaMaxExpansionRatio float64 `json:"quota_max_expansion_ratio"`
	LogFile                string  `json:"log_file"`
	LogDigest              string  `json:"log_digest"`
	Notes                  string  `json:"notes"`
}

// Digest returns the canonical sha256 of the record's JSON encoding.
func (r Record) Digest() string {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Store is a SQLite-backed evidence repository.
type Store struct {
	db *sql.DB
}

// Open creates or opens the evidence database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	cols := "record_id TEXT PRIMARY KEY, ts TEXT, scenario TEXT, " +
		"input_sha256 TEXT, input_len INTEGER, attack_vector TEXT, " +
		"trigger_func TEXT, trigger_file TEXT, trigger_line INTEGER, " +
		"perm_subject TEXT, perm_action TEXT, perm_decision TEXT, perm_reason TEXT, " +
		"expanded_bytes INTEGER, expansion_count INTEGER, " +
		"quota_max_output_bytes INTEGER, quota_max_expansion_ratio REAL, " +
		"log_file TEXT, log_digest TEXT, notes TEXT"
	stmts := []string{
		"CREATE TABLE IF NOT EXISTS evidence (" + cols + ")",
		"CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)",
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	order, err := json.Marshal(FieldOrder)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO meta(k,v) VALUES ('schema_version',?), ('field_order',?)",
		fmt.Sprint(schemaVersion), string(order))
	return err
}
