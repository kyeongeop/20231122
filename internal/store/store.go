package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"serrfix/internal/model"
)

var ErrNotFound = errors.New("not found")

type DB struct {
	sql *sql.DB
}

type Material struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	SourcePath    string `json:"source_path"`
	SnapshotPath  string `json:"snapshot_path"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	OriginalMTime string `json:"original_mtime"`
	CapturedAt    string `json:"captured_at"`
	Immutable     bool   `json:"immutable"`
}

type Event struct {
	ID         int64
	At         string
	Kind       string
	SampleID   string
	RunID      string
	DetailJSON string
}

type Comparison struct {
	ID          string `json:"id"`
	SampleID    string `json:"sample_id"`
	RunA        string `json:"run_a"`
	RunB        string `json:"run_b"`
	ComparedAt  string `json:"compared_at"`
	Equal       bool   `json:"equal"`
	SummaryJSON string `json:"summary_json"`
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{sql: sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error { return db.sql.Close() }

func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS materials (
			id TEXT PRIMARY KEY,
			role TEXT NOT NULL,
			source_path TEXT NOT NULL,
			snapshot_path TEXT NOT NULL UNIQUE,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			original_mtime TEXT NOT NULL,
			captured_at TEXT NOT NULL,
			immutable INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS samples (
			id TEXT PRIMARY KEY,
			ordinal INTEGER NOT NULL UNIQUE,
			label TEXT NOT NULL,
			origin TEXT NOT NULL,
			material_id TEXT NOT NULL REFERENCES materials(id),
			source_offset INTEGER NOT NULL CHECK(source_offset >= 0),
			source_length INTEGER NOT NULL CHECK(source_length > 0),
			source_sha256 TEXT NOT NULL,
			params_json TEXT NOT NULL,
			case_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(material_id, source_offset, source_length, source_sha256)
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			id TEXT NOT NULL UNIQUE,
			sample_id TEXT NOT NULL REFERENCES samples(id),
			attempt INTEGER NOT NULL,
			repetition INTEGER NOT NULL,
			state TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			duration_ns INTEGER NOT NULL,
			before_leaks INTEGER NOT NULL,
			after_leaks INTEGER NOT NULL,
			redacted_sha256 TEXT NOT NULL,
			evidence_path TEXT NOT NULL,
			evidence_sha256 TEXT NOT NULL,
			error TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(sample_id, attempt, repetition)
		)`,
		`CREATE TABLE IF NOT EXISTS spans (
			run_id TEXT NOT NULL REFERENCES runs(id),
			ordinal INTEGER NOT NULL,
			source_offset INTEGER NOT NULL,
			source_length INTEGER NOT NULL,
			line INTEGER NOT NULL,
			column INTEGER NOT NULL,
			rule TEXT NOT NULL,
			kind TEXT NOT NULL,
			replacement TEXT NOT NULL,
			replacement_offset INTEGER NOT NULL,
			original_sha256 TEXT NOT NULL,
			PRIMARY KEY(run_id, ordinal)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			kind TEXT NOT NULL,
			sample_id TEXT NOT NULL,
			run_id TEXT NOT NULL,
			detail_json TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS comparisons (
			id TEXT PRIMARY KEY,
			sample_id TEXT NOT NULL REFERENCES samples(id),
			run_a TEXT NOT NULL REFERENCES runs(id),
			run_b TEXT NOT NULL REFERENCES runs(id),
			compared_at TEXT NOT NULL,
			equal INTEGER NOT NULL,
			summary_json TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_runs_sample_seq ON runs(sample_id, seq)`,
		`CREATE INDEX IF NOT EXISTS idx_events_at ON events(at)`,
	}
	for _, stmt := range stmts {
		if _, err := db.sql.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func (db *DB) SetMeta(key, value, at string) error {
	_, err := db.sql.Exec(`INSERT INTO meta(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, at)
	return err
}

func (db *DB) GetMeta(key string) (string, error) {
	var value string
	err := db.sql.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

func (db *DB) AddMaterial(m Material) error {
	_, err := db.sql.Exec(`INSERT INTO materials
		(id,role,source_path,snapshot_path,sha256,size,original_mtime,captured_at,immutable)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		m.ID, m.Role, m.SourcePath, m.SnapshotPath, m.SHA256, m.Size,
		m.OriginalMTime, m.CapturedAt, boolInt(m.Immutable))
	return err
}

func (db *DB) GetMaterial(id string) (Material, error) {
	var m Material
	var immutable int
	err := db.sql.QueryRow(`SELECT id,role,source_path,snapshot_path,sha256,size,
		original_mtime,captured_at,immutable FROM materials WHERE id=?`, id).
		Scan(&m.ID, &m.Role, &m.SourcePath, &m.SnapshotPath, &m.SHA256,
			&m.Size, &m.OriginalMTime, &m.CapturedAt, &immutable)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	m.Immutable = immutable != 0
	return m, err
}

func (db *DB) ListMaterials() ([]Material, error) {
	rows, err := db.sql.Query(`SELECT id,role,source_path,snapshot_path,sha256,size,
		original_mtime,captured_at,immutable FROM materials ORDER BY captured_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Material
	for rows.Next() {
		var m Material
		var immutable int
		if err := rows.Scan(&m.ID, &m.Role, &m.SourcePath, &m.SnapshotPath, &m.SHA256,
			&m.Size, &m.OriginalMTime, &m.CapturedAt, &immutable); err != nil {
			return nil, err
		}
		m.Immutable = immutable != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func (db *DB) AddSample(s model.Sample) error {
	_, err := db.sql.Exec(`INSERT INTO samples
		(id,ordinal,label,origin,material_id,source_offset,source_length,source_sha256,
		params_json,case_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		s.ID, s.Ordinal, s.Label, s.Origin, s.MaterialID, s.Offset, s.Length,
		s.SHA256, s.ParamsJSON, s.CaseJSON, model.Timestamp(s.CreatedAt))
	return err
}

func (db *DB) GetSample(id string) (model.Sample, error) {
	var s model.Sample
	var created string
	err := db.sql.QueryRow(`SELECT id,ordinal,label,origin,material_id,source_offset,
		source_length,source_sha256,params_json,case_json,created_at
		FROM samples WHERE id=?`, id).
		Scan(&s.ID, &s.Ordinal, &s.Label, &s.Origin, &s.MaterialID, &s.Offset,
			&s.Length, &s.SHA256, &s.ParamsJSON, &s.CaseJSON, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err == nil {
		s.CreatedAt, err = model.ParseTimestamp(created)
	}
	return s, err
}

func (db *DB) CountSamples() (int, error) {
	var n int
	err := db.sql.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&n)
	return n, err
}

func (db *DB) MaxSampleOrdinal() (int, error) {
	var n sql.NullInt64
	if err := db.sql.QueryRow(`SELECT MAX(ordinal) FROM samples`).Scan(&n); err != nil {
		return 0, err
	}
	if !n.Valid {
		return 0, nil
	}
	return int(n.Int64), nil
}

func (db *DB) NextAttempt(sampleID string) (int, error) {
	var n sql.NullInt64
	if err := db.sql.QueryRow(`SELECT MAX(attempt) FROM runs WHERE sample_id=?`, sampleID).Scan(&n); err != nil {
		return 0, err
	}
	if !n.Valid {
		return 1, nil
	}
	return int(n.Int64) + 1, nil
}

func (db *DB) ListSamples() ([]model.Sample, error) {
	rows, err := db.sql.Query(`SELECT id,ordinal,label,origin,material_id,source_offset,
		source_length,source_sha256,params_json,case_json,created_at
		FROM samples ORDER BY ordinal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Sample
	for rows.Next() {
		var s model.Sample
		var created string
		if err := rows.Scan(&s.ID, &s.Ordinal, &s.Label, &s.Origin, &s.MaterialID,
			&s.Offset, &s.Length, &s.SHA256, &s.ParamsJSON, &s.CaseJSON, &created); err != nil {
			return nil, err
		}
		s.CreatedAt, err = model.ParseTimestamp(created)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) AddRun(r *model.Run) error {
	res, err := db.sql.Exec(`INSERT INTO runs
		(id,sample_id,attempt,repetition,state,started_at,finished_at,duration_ns,
		before_leaks,after_leaks,redacted_sha256,evidence_path,evidence_sha256,error,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.SampleID, r.Attempt, r.Repetition, r.State, model.Timestamp(r.StartedAt),
		model.Timestamp(r.FinishedAt), r.DurationNS, r.BeforeLeaks, r.AfterLeaks,
		r.RedactedSHA256, r.EvidencePath, r.EvidenceSHA256, r.Error,
		model.Timestamp(r.CreatedAt))
	if err != nil {
		return err
	}
	if r.Seq == 0 {
		r.Seq, err = res.LastInsertId()
	}
	return err
}

func (db *DB) FinishRun(r *model.Run, spans []model.Span) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE runs SET state=?,finished_at=?,duration_ns=?,
		before_leaks=?,after_leaks=?,redacted_sha256=?,evidence_sha256=?,error=?
		WHERE id=?`,
		r.State, model.Timestamp(r.FinishedAt), r.DurationNS, r.BeforeLeaks,
		r.AfterLeaks, r.RedactedSHA256, r.EvidenceSHA256, r.Error, r.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM spans WHERE run_id=?`, r.ID); err != nil {
		return err
	}
	for _, s := range spans {
		if _, err := tx.Exec(`INSERT INTO spans
			(run_id,ordinal,source_offset,source_length,line,column,rule,kind,replacement,
			replacement_offset,original_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, s.Ordinal, s.SourceOffset, s.SourceLength, s.Line, s.Column,
			s.Rule, s.Kind, s.Replacement, s.ReplacementOffset, s.OriginalSHA256); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO events(at,kind,sample_id,run_id,detail_json)
		VALUES(?,?,?,?,?)`, model.Timestamp(r.FinishedAt), "run_finished",
		r.SampleID, r.ID, fmt.Sprintf(`{"state":%q}`, r.State)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) GetRun(id string) (model.Run, error) {
	return scanRun(db.sql.QueryRow(runSelect+` WHERE id=?`, id))
}

func (db *DB) ListRuns(sampleID string) ([]model.Run, error) {
	query := runSelect
	args := []any{}
	if sampleID != "" {
		query += ` WHERE sample_id=?`
		args = append(args, sampleID)
	}
	query += ` ORDER BY seq`
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) ListSpans(runID string) ([]model.Span, error) {
	rows, err := db.sql.Query(`SELECT ordinal,source_offset,source_length,line,column,
		rule,kind,replacement,replacement_offset,original_sha256
		FROM spans WHERE run_id=? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Span
	for rows.Next() {
		var s model.Span
		if err := rows.Scan(&s.Ordinal, &s.SourceOffset, &s.SourceLength, &s.Line,
			&s.Column, &s.Rule, &s.Kind, &s.Replacement, &s.ReplacementOffset,
			&s.OriginalSHA256); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) AddEvent(at, kind, sampleID, runID, detail string) error {
	_, err := db.sql.Exec(`INSERT INTO events(at,kind,sample_id,run_id,detail_json)
		VALUES(?,?,?,?,?)`, at, kind, sampleID, runID, detail)
	return err
}

func (db *DB) ListEvents(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := db.sql.Query(`SELECT id,at,kind,sample_id,run_id,detail_json
		FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.SampleID, &e.RunID, &e.DetailJSON); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) AddComparison(c Comparison) error {
	_, err := db.sql.Exec(`INSERT INTO comparisons
		(id,sample_id,run_a,run_b,compared_at,equal,summary_json) VALUES(?,?,?,?,?,?,?)`,
		c.ID, c.SampleID, c.RunA, c.RunB, c.ComparedAt, boolInt(c.Equal), c.SummaryJSON)
	return err
}

func (db *DB) ListComparisons(sampleID string) ([]Comparison, error) {
	query := `SELECT id,sample_id,run_a,run_b,compared_at,equal,summary_json
		FROM comparisons`
	args := []any{}
	if sampleID != "" {
		query += ` WHERE sample_id=?`
		args = append(args, sampleID)
	}
	query += ` ORDER BY compared_at,id`
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Comparison
	for rows.Next() {
		var c Comparison
		var equal int
		if err := rows.Scan(&c.ID, &c.SampleID, &c.RunA, &c.RunB, &c.ComparedAt,
			&equal, &c.SummaryJSON); err != nil {
			return nil, err
		}
		c.Equal = equal != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) ListInterrupted() ([]model.Run, error) {
	runs, err := db.ListRuns("")
	if err != nil {
		return nil, err
	}
	var out []model.Run
	for _, r := range runs {
		if r.State == "running" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (db *DB) AbandonRun(id, at, note string) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE runs SET state='abandoned',finished_at=?,error=?
		WHERE id=? AND state='running'`, at, note, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil
	}
	if _, err := tx.Exec(`INSERT INTO events(at,kind,sample_id,run_id,detail_json)
		SELECT ?, 'run_abandoned', sample_id, id, ? FROM runs WHERE id=?`,
		at, fmt.Sprintf(`{"note":%q}`, note), id); err != nil {
		return err
	}
	return tx.Commit()
}

const runSelect = `SELECT id,seq,sample_id,attempt,repetition,state,started_at,
	finished_at,duration_ns,before_leaks,after_leaks,redacted_sha256,evidence_path,
	evidence_sha256,error,created_at FROM runs`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRun(row rowScanner) (model.Run, error) {
	var r model.Run
	var started, finished, created string
	err := row.Scan(&r.ID, &r.Seq, &r.SampleID, &r.Attempt, &r.Repetition, &r.State,
		&started, &finished, &r.DurationNS, &r.BeforeLeaks, &r.AfterLeaks,
		&r.RedactedSHA256, &r.EvidencePath, &r.EvidenceSHA256, &r.Error, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if r.StartedAt, err = model.ParseTimestamp(started); err != nil {
		return r, err
	}
	if r.FinishedAt, err = model.ParseTimestamp(finished); err != nil {
		return r, err
	}
	if r.CreatedAt, err = model.ParseTimestamp(created); err != nil {
		return r, err
	}
	return r, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ParseTime(s string) (time.Time, error) {
	return model.ParseTimestamp(s)
}
