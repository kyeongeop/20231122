package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"seedreview/internal/model"
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db *sql.DB
}

type RunWrite struct {
	Session          model.Recovery
	ManifestEvidence model.Evidence
	InputEvidence    model.Evidence
	StdoutEvidence   model.Evidence
	StderrEvidence   model.Evidence
	TraceEvidence    model.Evidence
	AllEvidence      []model.Evidence
	StartedAt        time.Time
	CompletedAt      time.Time
	Status           string
	ExitCode         int
	Signal           string
	TargetSHA256     string
	TargetEvidence   model.Evidence
	TargetPath       string
	ArtifactPath     string
	InputSHA256      string
	InputSize        int64
	EffectiveSeed    string
	FailureCode      string
	FailureMessage   string
	NextActions      []model.NextAction
	AutoConclusion   string
	Extensions       []model.ExtensionRecord
	Logs             []model.LogEvidence
	Findings         []model.Finding
	ManualChecks     []model.ManualCheck
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(abs) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	var targetPathColumns int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info('replay_runs') WHERE name='target_path'",
	).Scan(&targetPathColumns)
	if err != nil {
		return fmt.Errorf("inspect replay_runs schema: %w", err)
	}
	if targetPathColumns == 0 {
		if _, err := db.Exec(
			"ALTER TABLE replay_runs ADD COLUMN target_path TEXT NOT NULL DEFAULT ''",
		); err != nil {
			return fmt.Errorf("add target_path column: %w", err)
		}
		if _, err := db.Exec(`
UPDATE replay_runs
SET target_path = COALESCE(
    (SELECT target FROM recovery_sessions WHERE id = replay_runs.session_id), ''
)
WHERE target_path = ''`); err != nil {
			return fmt.Errorf("backfill target_path: %w", err)
		}
	}
	_, err = db.Exec(
		"INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)",
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	_, err = db.Exec(
		"INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)",
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("record schema version 2: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveRun(ctx context.Context, write RunWrite) (int64, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := saveEvidence(ctx, tx, write.AllEvidence); err != nil {
		return 0, 0, err
	}
	sessionID, err := saveSession(ctx, tx, write)
	if err != nil {
		return 0, 0, err
	}
	nextActions, err := json.Marshal(write.NextActions)
	if err != nil {
		return 0, 0, fmt.Errorf("encode next actions: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO replay_runs(
    session_id, started_at, completed_at, status, exit_code, signal,
    target_sha256, target_evidence, target_path, artifact_path, input_sha256, input_size,
    input_evidence, stdout_evidence, stderr_evidence, trace_evidence,
    seed, effective_seed, failure_code, failure_message, next_actions_json,
    auto_conclusion
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sessionID, formatTime(write.StartedAt), formatTime(write.CompletedAt),
		write.Status, write.ExitCode, write.Signal, write.TargetSHA256,
		write.TargetEvidence.SHA256, write.TargetPath, write.ArtifactPath,
		write.InputSHA256, write.InputSize,
		write.InputEvidence.SHA256, write.StdoutEvidence.SHA256,
		write.StderrEvidence.SHA256, write.TraceEvidence.SHA256,
		write.Session.Seed, write.EffectiveSeed, write.FailureCode,
		write.FailureMessage, string(nextActions), write.AutoConclusion,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("insert replay run: %w", err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return 0, 0, fmt.Errorf("read replay run id: %w", err)
	}
	if err := saveTrace(ctx, tx, runID, write); err != nil {
		return 0, 0, err
	}
	if err := saveManualChecks(ctx, tx, runID, write.ManualChecks); err != nil {
		return 0, 0, err
	}
	if err := saveAuditEvent(ctx, tx, runID, "replay.completed", map[string]any{
		"status": write.Status, "input_sha256": write.InputSHA256,
		"target_sha256": write.TargetSHA256, "target_path": write.TargetPath,
		"artifact_path":   write.ArtifactPath,
		"auto_conclusion": write.AutoConclusion,
	}); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit replay run: %w", err)
	}
	return runID, sessionID, nil
}

func saveEvidence(ctx context.Context, tx *sql.Tx, records []model.Evidence) error {
	seen := make(map[string]bool)
	for _, record := range records {
		if seen[record.SHA256] {
			continue
		}
		seen[record.SHA256] = true
		_, err := tx.ExecContext(ctx, `
INSERT INTO evidence(sha256, kind, relative_path, size, media_type, created_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(sha256) DO UPDATE SET
    kind=excluded.kind, relative_path=excluded.relative_path,
    size=excluded.size, media_type=excluded.media_type`,
			record.SHA256, record.Kind, record.RelativePath, record.Size,
			record.MediaType, formatTime(record.CreatedAt),
		)
		if err != nil {
			return fmt.Errorf("insert evidence %s: %w", record.SHA256, err)
		}
	}
	return nil
}

func saveSession(ctx context.Context, tx *sql.Tx, write RunWrite) (int64, error) {
	environment, err := json.Marshal(write.Session.Environment)
	if err != nil {
		return 0, fmt.Errorf("encode environment: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO recovery_sessions(
    recovery_key, source_format, recovery_id, captured_at, app_version,
    rng_algorithm, seed, recovered_seed, state_sha256, target, artifact_path,
    environment_json, notes, manifest_evidence, created_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(recovery_key) DO NOTHING`,
		write.Session.Key, write.Session.SourceFormat, write.Session.RecoveryID,
		write.Session.CapturedAt, write.Session.AppVersion,
		write.Session.RNGAlgorithm, write.Session.Seed,
		write.Session.RecoveredSeed, write.Session.StateSHA256,
		write.Session.Target, write.Session.Artifact,
		string(environment), write.Session.Notes,
		write.ManifestEvidence.SHA256, formatTime(write.StartedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("upsert recovery session: %w", err)
	}
	var id int64
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM recovery_sessions WHERE recovery_key = ?",
		write.Session.Key,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("read recovery session: %w", err)
	}
	return id, nil
}

func saveAuditEvent(ctx context.Context, tx *sql.Tx, runID int64, action string, detail any) error {
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events(run_id, at, actor, action, detail_json)
VALUES(?,?,?,?,?)`,
		runID, formatTime(time.Now()), "seedreview", action, string(payload),
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

var ErrNotFound = errors.New("not found")
