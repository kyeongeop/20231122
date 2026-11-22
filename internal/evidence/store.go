package evidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"example.com/migration-review/internal/model"
	_ "modernc.org/sqlite"
)

type Artifact struct {
	Kind    string
	Name    string
	Content []byte
}

type LogEntry struct {
	Seq      int64  `json:"seq"`
	RunID    string `json:"run_id"`
	Time     string `json:"ts"`
	Level    string `json:"level"`
	Event    string `json:"event"`
	Detail   string `json:"detail"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"entry_hash"`
}

type EvidenceRecord struct {
	Kind    string
	Name    string
	SHA256  string
	Content []byte
}

type Store struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("evidence database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open evidence database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, path: abs}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (
			version INTEGER NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			run_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			completed_at TEXT,
			status TEXT NOT NULL,
			format TEXT NOT NULL,
			manifest_id TEXT NOT NULL,
			actor TEXT NOT NULL,
			input_path TEXT NOT NULL,
			input_sha256 TEXT NOT NULL,
			input_bytes BLOB NOT NULL,
			decision_json TEXT NOT NULL,
			trigger_file TEXT NOT NULL,
			trigger_line INTEGER NOT NULL,
			trigger_column INTEGER NOT NULL,
			trigger_token TEXT NOT NULL,
			reason TEXT NOT NULL,
			rollback_ok INTEGER NOT NULL,
			schema_before TEXT NOT NULL,
			schema_after TEXT NOT NULL,
			log_head_hash TEXT NOT NULL,
			evidence_bytes INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL REFERENCES runs(run_id),
			ts TEXT NOT NULL,
			level TEXT NOT NULL,
			event TEXT NOT NULL,
			detail TEXT NOT NULL,
			prev_hash TEXT NOT NULL,
			entry_hash TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_run ON logs(run_id, seq)`,
		`CREATE TABLE IF NOT EXISTS evidence (
			run_id TEXT NOT NULL REFERENCES runs(run_id),
			kind TEXT NOT NULL,
			name TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			content BLOB NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY (run_id, kind, name)
		)`,
	}
	for _, stmt := range schema {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize evidence schema: %w", err)
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_meta").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_meta(version, created_at) VALUES (1, ?)", now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) BeginRun(ctx context.Context, record model.RunRecord, artifacts ...Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	decisionJSON, err := json.Marshal(record.Decision)
	if err != nil {
		return fmt.Errorf("encode decision evidence: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO runs (
		run_id, created_at, status, format, manifest_id, actor, input_path,
		input_sha256, input_bytes, decision_json, trigger_file, trigger_line,
		trigger_column, trigger_token, reason, rollback_ok, schema_before,
		schema_after, log_head_hash, evidence_bytes
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		record.RunID, record.CreatedAt.UTC().Format(time.RFC3339Nano), record.Status,
		record.Format, record.ManifestID, record.Actor, record.InputPath,
		record.InputSHA256, record.InputBytes, string(decisionJSON),
		record.Trigger.File, record.Trigger.Line, record.Trigger.Column, record.Trigger.Token,
		record.Reason, boolInt(record.RollbackOK), record.SchemaBefore,
		record.SchemaAfter, "", 0)
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	var total int64
	for _, artifact := range artifacts {
		if artifact.Kind == "" || artifact.Name == "" {
			return fmt.Errorf("evidence artifact kind and name are required")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO evidence(
			run_id, kind, name, sha256, content, created_at
		) VALUES (?,?,?,?,?,?)`,
			record.RunID, artifact.Kind, artifact.Name, model.SHA256Hex(artifact.Content),
			artifact.Content, now())
		if err != nil {
			return fmt.Errorf("insert evidence %s/%s: %w", artifact.Kind, artifact.Name, err)
		}
		total += int64(len(artifact.Content))
	}
	if _, err := tx.ExecContext(ctx, "UPDATE runs SET evidence_bytes = ? WHERE run_id = ?", total, record.RunID); err != nil {
		return err
	}
	return tx.Commit()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (s *Store) Log(ctx context.Context, runID, level, event, detail string) (LogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LogEntry{}, err
	}
	defer tx.Rollback()
	var prev string
	err = tx.QueryRowContext(ctx,
		"SELECT entry_hash FROM logs WHERE run_id = ? ORDER BY seq DESC LIMIT 1", runID).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return LogEntry{}, err
	}
	entry := LogEntry{
		RunID:    runID,
		Time:     now(),
		Level:    level,
		Event:    event,
		Detail:   detail,
		PrevHash: prev,
	}
	entry.Hash = hashLog(entry)
	res, err := tx.ExecContext(ctx, `INSERT INTO logs(
		run_id, ts, level, event, detail, prev_hash, entry_hash
	) VALUES (?,?,?,?,?,?,?)`,
		entry.RunID, entry.Time, entry.Level, entry.Event, entry.Detail, entry.PrevHash, entry.Hash)
	if err != nil {
		return LogEntry{}, fmt.Errorf("append evidence log: %w", err)
	}
	entry.Seq, err = res.LastInsertId()
	if err != nil {
		return LogEntry{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE runs SET log_head_hash = ? WHERE run_id = ?", entry.Hash, runID); err != nil {
		return LogEntry{}, err
	}
	return entry, tx.Commit()
}

func hashLog(entry LogEntry) string {
	payload, _ := json.Marshal(struct {
		RunID    string `json:"run_id"`
		Time     string `json:"ts"`
		Level    string `json:"level"`
		Event    string `json:"event"`
		Detail   string `json:"detail"`
		PrevHash string `json:"prev_hash"`
	}{
		RunID: entry.RunID, Time: entry.Time, Level: entry.Level,
		Event: entry.Event, Detail: entry.Detail, PrevHash: entry.PrevHash,
	})
	return model.SHA256Hex(payload)
}

func (s *Store) AddArtifact(ctx context.Context, runID string, artifact Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if artifact.Kind == "" || artifact.Name == "" {
		return fmt.Errorf("evidence artifact kind and name are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO evidence(
		run_id, kind, name, sha256, content, created_at
	) VALUES (?,?,?,?,?,?)`,
		runID, artifact.Kind, artifact.Name, model.SHA256Hex(artifact.Content), artifact.Content, now())
	if err != nil {
		return fmt.Errorf("insert evidence %s/%s: %w", artifact.Kind, artifact.Name, err)
	}
	_, err = tx.ExecContext(ctx,
		"UPDATE runs SET evidence_bytes = evidence_bytes + ? WHERE run_id = ?",
		len(artifact.Content), runID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteRun(ctx context.Context, record model.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var completed any
	if record.CompletedAt != nil {
		completed = record.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE runs SET
		completed_at = ?, status = ?, reason = ?, rollback_ok = ?,
		schema_before = ?, schema_after = ?, log_head_hash = ?
		WHERE run_id = ?`,
		completed, record.Status, record.Reason, boolInt(record.RollbackOK),
		record.SchemaBefore, record.SchemaAfter, record.LogHeadHash, record.RunID)
	if err != nil {
		return fmt.Errorf("complete run evidence: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("run %q does not exist", record.RunID)
	}
	return nil
}

func (s *Store) GetRun(ctx context.Context, runID string) (model.RunRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT
		run_id, created_at, completed_at, status, format, manifest_id, actor,
		input_path, input_sha256, input_bytes, decision_json, trigger_file,
		trigger_line, trigger_column, trigger_token, reason, rollback_ok,
		schema_before, schema_after, log_head_hash, evidence_bytes
		FROM runs WHERE run_id = ?`, runID)
	return scanRun(row)
}

func (s *Store) ListRuns(ctx context.Context) ([]model.RunRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		run_id, created_at, completed_at, status, format, manifest_id, actor,
		input_path, input_sha256, input_bytes, decision_json, trigger_file,
		trigger_line, trigger_column, trigger_token, reason, rollback_ok,
		schema_before, schema_after, log_head_hash, evidence_bytes
		FROM runs ORDER BY created_at, run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []model.RunRecord
	for rows.Next() {
		record, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, record)
	}
	return runs, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRun(row scanner) (model.RunRecord, error) {
	var record model.RunRecord
	var created, completed, status, format, decisionJSON sql.NullString
	var rollback int
	err := row.Scan(
		&record.RunID, &created, &completed, &status, &format, &record.ManifestID,
		&record.Actor, &record.InputPath, &record.InputSHA256, &record.InputBytes,
		&decisionJSON, &record.Trigger.File, &record.Trigger.Line,
		&record.Trigger.Column, &record.Trigger.Token, &record.Reason,
		&rollback, &record.SchemaBefore, &record.SchemaAfter,
		&record.LogHeadHash, &record.EvidenceBytes)
	if err != nil {
		return model.RunRecord{}, err
	}
	record.CreatedAt, _ = time.Parse(time.RFC3339Nano, created.String)
	if completed.Valid {
		value, _ := time.Parse(time.RFC3339Nano, completed.String)
		record.CompletedAt = &value
	}
	record.Status = model.RunStatus(status.String)
	record.Format = model.Format(format.String)
	record.RollbackOK = rollback == 1
	if decisionJSON.Valid {
		if err := json.Unmarshal([]byte(decisionJSON.String), &record.Decision); err != nil {
			return model.RunRecord{}, fmt.Errorf("decode decision evidence: %w", err)
		}
	}
	return record, nil
}

func (s *Store) Logs(ctx context.Context, runID string) ([]LogEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		seq, run_id, ts, level, event, detail, prev_hash, entry_hash
		FROM logs WHERE run_id = ? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []LogEntry
	for rows.Next() {
		var entry LogEntry
		if err := rows.Scan(&entry.Seq, &entry.RunID, &entry.Time, &entry.Level,
			&entry.Event, &entry.Detail, &entry.PrevHash, &entry.Hash); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) Artifacts(ctx context.Context, runID string) ([]EvidenceRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		kind, name, sha256, content FROM evidence
		WHERE run_id = ? ORDER BY kind, name`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []EvidenceRecord
	for rows.Next() {
		var record EvidenceRecord
		if err := rows.Scan(&record.Kind, &record.Name, &record.SHA256, &record.Content); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) VerifyChain(ctx context.Context, runID string) error {
	entries, err := s.ApplyLogChainCheck(ctx, runID)
	if err != nil {
		return err
	}
	record, err := s.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if record.LogHeadHash != entries {
		return fmt.Errorf("log head mismatch: run=%s chain=%s", record.LogHeadHash, entries)
	}
	return nil
}

func (s *Store) ApplyLogChainCheck(ctx context.Context, runID string) (string, error) {
	entries, err := s.Logs(ctx, runID)
	if err != nil {
		return "", err
	}
	prev := ""
	for _, entry := range entries {
		if entry.PrevHash != prev {
			return "", fmt.Errorf("log %d prev_hash mismatch", entry.Seq)
		}
		if hashLog(entry) != entry.Hash {
			return "", fmt.Errorf("log %d entry_hash mismatch", entry.Seq)
		}
		prev = entry.Hash
	}
	return prev, nil
}

func (s *Store) VerifyArtifacts(ctx context.Context, runID string) error {
	records, err := s.Artifacts(ctx, runID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if got := model.SHA256Hex(record.Content); got != record.SHA256 {
			return fmt.Errorf("artifact %s/%s hash mismatch: stored=%s actual=%s",
				record.Kind, record.Name, record.SHA256, got)
		}
	}
	return nil
}

func (s *Store) VerifyRun(ctx context.Context, runID string) error {
	record, err := s.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if err := s.VerifyChain(ctx, runID); err != nil {
		return err
	}
	if err := s.VerifyArtifacts(ctx, runID); err != nil {
		return err
	}
	records, err := s.Artifacts(ctx, runID)
	if err != nil {
		return err
	}
	var raw, policySnapshot, decisionSnapshot []byte
	for _, artifact := range records {
		switch {
		case artifact.Kind == "input" && artifact.Name == "raw":
			raw = artifact.Content
		case artifact.Kind == "policy" && artifact.Name == "snapshot.json":
			policySnapshot = artifact.Content
		case artifact.Kind == "permission" && artifact.Name == "decision.json":
			decisionSnapshot = artifact.Content
		}
	}
	if raw == nil {
		return fmt.Errorf("raw input evidence is missing")
	}
	if model.SHA256Hex(raw) != record.InputSHA256 {
		return fmt.Errorf("raw input hash does not match run input_sha256")
	}
	if !bytes.Equal(raw, record.InputBytes) {
		return fmt.Errorf("raw input evidence does not match run input_bytes")
	}
	if policySnapshot == nil || model.SHA256Hex(policySnapshot) != record.Decision.PolicySHA256 {
		return fmt.Errorf("policy snapshot does not match decision policy_sha256")
	}
	if decisionSnapshot == nil {
		return fmt.Errorf("permission decision evidence is missing")
	}
	var decision model.PermissionDecision
	if err := json.Unmarshal(decisionSnapshot, &decision); err != nil {
		return fmt.Errorf("decode permission evidence: %w", err)
	}
	if !reflect.DeepEqual(decision, record.Decision) {
		return fmt.Errorf("permission decision evidence does not match run decision")
	}
	if !triggerBelongsToDecision(record.Trigger, record.Decision) {
		return fmt.Errorf("run trigger does not match any permission statement")
	}
	logs, err := s.Logs(ctx, runID)
	if err != nil {
		return err
	}
	hasDecisionLog := false
	for _, entry := range logs {
		if entry.Event == "permission_decision" {
			hasDecisionLog = true
			break
		}
	}
	if !hasDecisionLog {
		return fmt.Errorf("permission_decision log evidence is missing")
	}
	return nil
}

func triggerBelongsToDecision(trigger model.Trigger, decision model.PermissionDecision) bool {
	for _, statement := range decision.Statements {
		if statement.Trigger.File == trigger.File &&
			statement.Trigger.Line == trigger.Line &&
			statement.Trigger.Column == trigger.Column &&
			statement.Trigger.Token == trigger.Token {
			return true
		}
	}
	return false
}
