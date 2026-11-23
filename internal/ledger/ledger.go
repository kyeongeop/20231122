package ledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schemaVersion = "1"

type Ledger struct {
	db       *sql.DB
	path     string
	readOnly bool
}

func Open(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := path + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('schema_version', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, schemaVersion); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db, path: path}, nil
}

func OpenReadOnly(path string) (*Ledger, error) {
	dsn := "file:" + path + "?mode=ro&_query_only=1&_busy_timeout=5000"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db, path: path, readOnly: true}, nil
}

func (l *Ledger) Close() error {
	if !l.readOnly {
		_, _ = l.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return l.db.Close()
}

func (l *Ledger) Path() string {
	return l.path
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
	run_id TEXT PRIMARY KEY,
	scenario TEXT NOT NULL,
	role TEXT NOT NULL,
	mode TEXT NOT NULL,
	seed INTEGER NOT NULL,
	expected TEXT NOT NULL,
	status TEXT NOT NULL,
	state_digest TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	completed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS steps (
	run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	phase TEXT NOT NULL,
	action TEXT NOT NULL,
	input_sha256 TEXT NOT NULL,
	input_json TEXT NOT NULL,
	input_hex TEXT NOT NULL,
	state_before TEXT NOT NULL,
	state_after TEXT NOT NULL,
	outcome TEXT NOT NULL,
	result_json TEXT NOT NULL,
	duration_us INTEGER NOT NULL,
	recorded_at TEXT NOT NULL,
	PRIMARY KEY(run_id, seq)
);
CREATE TABLE IF NOT EXISTS records (
	run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
	record_id INTEGER NOT NULL,
	payload TEXT NOT NULL,
	canonical_sha256 TEXT NOT NULL,
	source_seq INTEGER NOT NULL,
	PRIMARY KEY(run_id, record_id)
);
CREATE TABLE IF NOT EXISTS checks (
	check_id TEXT PRIMARY KEY,
	category TEXT NOT NULL,
	passed INTEGER NOT NULL,
	expected TEXT NOT NULL,
	observed TEXT NOT NULL,
	evidence TEXT NOT NULL,
	detail TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
	path TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	note TEXT NOT NULL,
	recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_run_action ON steps(run_id, action);
`

type Run struct {
	ID          string `json:"run_id"`
	Scenario    string `json:"scenario"`
	Role        string `json:"role"`
	Mode        string `json:"mode"`
	Seed        int64  `json:"seed"`
	Expected    string `json:"expected"`
	Status      string `json:"status"`
	StateDigest string `json:"state_digest"`
	CreatedAt   string `json:"created_at"`
	CompletedAt string `json:"completed_at"`
}

type Step struct {
	RunID       string `json:"run_id"`
	Seq         int    `json:"seq"`
	Phase       string `json:"phase"`
	Action      string `json:"action"`
	InputSHA256 string `json:"input_sha256"`
	InputJSON   string `json:"input_json"`
	InputHex    string `json:"input_hex"`
	StateBefore string `json:"state_before"`
	StateAfter  string `json:"state_after"`
	Outcome     string `json:"outcome"`
	ResultJSON  string `json:"result_json"`
	DurationUS  int64  `json:"duration_us"`
	RecordedAt  string `json:"recorded_at"`
}

type Record struct {
	RunID          string `json:"run_id"`
	ID             int    `json:"id"`
	Payload        string `json:"payload"`
	CanonicalSHA   string `json:"canonical_sha256"`
	SourceSequence int    `json:"source_seq"`
}

type Check struct {
	ID       string `json:"check_id"`
	Category string `json:"category"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
	At       string `json:"created_at"`
}

type Evidence struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Note     string `json:"note"`
	Recorded string `json:"recorded_at"`
}

func (l *Ledger) ResetRun(ctx context.Context, runID string) error {
	_, err := l.db.ExecContext(ctx, `DELETE FROM runs WHERE run_id = ?`, runID)
	return err
}

func (l *Ledger) StartRun(ctx context.Context, run Run) error {
	now := nowUTC()
	if run.CreatedAt == "" {
		run.CreatedAt = now
	}
	_, err := l.db.ExecContext(ctx, `INSERT INTO runs
		(run_id, scenario, role, mode, seed, expected, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.Scenario, run.Role, run.Mode, run.Seed, run.Expected, run.Status, run.CreatedAt)
	return err
}

func (l *Ledger) CompleteRun(ctx context.Context, runID, status, digest string) error {
	res, err := l.db.ExecContext(ctx, `UPDATE runs
		SET status = ?, state_digest = ?, completed_at = ?
		WHERE run_id = ?`, status, digest, nowUTC(), runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("complete run %q: affected %d rows", runID, n)
	}
	return nil
}

func (l *Ledger) AppendStep(ctx context.Context, step Step) error {
	if step.RecordedAt == "" {
		step.RecordedAt = nowUTC()
	}
	_, err := l.db.ExecContext(ctx, `INSERT INTO steps
		(run_id, seq, phase, action, input_sha256, input_json, input_hex,
		 state_before, state_after, outcome, result_json, duration_us, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		step.RunID, step.Seq, step.Phase, step.Action, step.InputSHA256,
		step.InputJSON, step.InputHex, step.StateBefore, step.StateAfter,
		step.Outcome, step.ResultJSON, step.DurationUS, step.RecordedAt)
	return err
}

func (l *Ledger) CommitRecords(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO records
		(run_id, record_id, payload, canonical_sha256, source_seq)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, rec := range records {
		if _, err := stmt.ExecContext(ctx, rec.RunID, rec.ID, rec.Payload, rec.CanonicalSHA, rec.SourceSequence); err != nil {
			return fmt.Errorf("insert record %d: %w", rec.ID, err)
		}
	}
	return tx.Commit()
}

func (l *Ledger) Records(ctx context.Context, runID string) ([]Record, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT run_id, record_id, payload, canonical_sha256, source_seq
		FROM records WHERE run_id = ? ORDER BY record_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var rec Record
		if err := rows.Scan(&rec.RunID, &rec.ID, &rec.Payload, &rec.CanonicalSHA, &rec.SourceSequence); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (l *Ledger) Run(ctx context.Context, runID string) (Run, error) {
	var run Run
	err := l.db.QueryRowContext(ctx, `SELECT run_id, scenario, role, mode, seed, expected,
		status, state_digest, created_at, completed_at FROM runs WHERE run_id = ?`, runID).
		Scan(&run.ID, &run.Scenario, &run.Role, &run.Mode, &run.Seed, &run.Expected,
			&run.Status, &run.StateDigest, &run.CreatedAt, &run.CompletedAt)
	return run, err
}

func (l *Ledger) Runs(ctx context.Context) ([]Run, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT run_id, scenario, role, mode, seed, expected,
		status, state_digest, created_at, completed_at FROM runs ORDER BY created_at, run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var run Run
		if err := rows.Scan(&run.ID, &run.Scenario, &run.Role, &run.Mode, &run.Seed,
			&run.Expected, &run.Status, &run.StateDigest, &run.CreatedAt, &run.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (l *Ledger) Steps(ctx context.Context, runID string) ([]Step, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT run_id, seq, phase, action, input_sha256,
		input_json, input_hex, state_before, state_after, outcome, result_json,
		duration_us, recorded_at FROM steps WHERE run_id = ? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var step Step
		if err := rows.Scan(&step.RunID, &step.Seq, &step.Phase, &step.Action,
			&step.InputSHA256, &step.InputJSON, &step.InputHex, &step.StateBefore,
			&step.StateAfter, &step.Outcome, &step.ResultJSON, &step.DurationUS,
			&step.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, step)
	}
	return out, rows.Err()
}

func (l *Ledger) PutCheck(ctx context.Context, check Check) error {
	if check.At == "" {
		check.At = nowUTC()
	}
	_, err := l.db.ExecContext(ctx, `INSERT INTO checks
		(check_id, category, passed, expected, observed, evidence, detail, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(check_id) DO UPDATE SET
			category=excluded.category, passed=excluded.passed,
			expected=excluded.expected, observed=excluded.observed,
			evidence=excluded.evidence, detail=excluded.detail,
			created_at=excluded.created_at`,
		check.ID, check.Category, boolInt(check.Passed), check.Expected,
		check.Observed, check.Evidence, check.Detail, check.At)
	return err
}

func (l *Ledger) Checks(ctx context.Context) ([]Check, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT check_id, category, passed, expected,
		observed, evidence, detail, created_at FROM checks ORDER BY check_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var check Check
		var passed int
		if err := rows.Scan(&check.ID, &check.Category, &passed, &check.Expected,
			&check.Observed, &check.Evidence, &check.Detail, &check.At); err != nil {
			return nil, err
		}
		check.Passed = passed != 0
		out = append(out, check)
	}
	return out, rows.Err()
}

func (l *Ledger) PutEvidence(ctx context.Context, evidence Evidence) error {
	if evidence.Recorded == "" {
		evidence.Recorded = nowUTC()
	}
	_, err := l.db.ExecContext(ctx, `INSERT INTO evidence
		(path, kind, sha256, bytes, note, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			kind=excluded.kind, sha256=excluded.sha256, bytes=excluded.bytes,
			note=excluded.note, recorded_at=excluded.recorded_at`,
		evidence.Path, evidence.Kind, evidence.SHA256, evidence.Bytes,
		evidence.Note, evidence.Recorded)
	return err
}

func (l *Ledger) Evidence(ctx context.Context) ([]Evidence, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT path, kind, sha256, bytes, note, recorded_at
		FROM evidence ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var evidence Evidence
		if err := rows.Scan(&evidence.Path, &evidence.Kind, &evidence.SHA256,
			&evidence.Bytes, &evidence.Note, &evidence.Recorded); err != nil {
			return nil, err
		}
		out = append(out, evidence)
	}
	return out, rows.Err()
}

func (l *Ledger) ExportJSONL(ctx context.Context, runID string) ([]byte, error) {
	steps, err := l.Steps(ctx, runID)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, step := range steps {
		line, err := json.Marshal(step)
		if err != nil {
			return nil, err
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out, nil
}

func (l *Ledger) ScalarInt(ctx context.Context, query string, args ...any) (int64, error) {
	var value int64
	err := l.db.QueryRowContext(ctx, query, args...).Scan(&value)
	return value, err
}

func (l *Ledger) ScalarString(ctx context.Context, query string, args ...any) (string, error) {
	var value sql.NullString
	err := l.db.QueryRowContext(ctx, query, args...).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value.String, err
}

func (l *Ledger) Query(ctx context.Context, query string, args ...any) ([]string, [][]string, error) {
	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var values [][]string
	for rows.Next() {
		raw := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		row := make([]string, len(columns))
		for i, value := range raw {
			switch typed := value.(type) {
			case nil:
				row[i] = "NULL"
			case []byte:
				row[i] = string(typed)
			default:
				row[i] = fmt.Sprint(typed)
			}
		}
		values = append(values, row)
	}
	return columns, values, rows.Err()
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
