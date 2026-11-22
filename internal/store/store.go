package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cacheleak.local/experiment/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	st := &Store{db: db, path: path}
	if err := st.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS runs (
			id TEXT PRIMARY KEY,
			schema_version TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			db_path TEXT NOT NULL,
			evidence_dir TEXT NOT NULL,
			config_json TEXT NOT NULL,
			summary_json TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			run_id TEXT NOT NULL REFERENCES runs(id),
			id TEXT NOT NULL,
			label TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY (run_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS objects (
			run_id TEXT NOT NULL REFERENCES runs(id),
			key TEXT NOT NULL,
			snapshot_id TEXT NOT NULL,
			version TEXT NOT NULL,
			logical_path TEXT NOT NULL,
			file_name TEXT NOT NULL,
			extension TEXT NOT NULL,
			known_extension INTEGER NOT NULL,
			mime TEXT NOT NULL,
			size INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			captured_at TEXT NOT NULL,
			body BLOB NOT NULL,
			PRIMARY KEY (run_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS scenarios (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL REFERENCES runs(id),
			name TEXT NOT NULL,
			order_key TEXT NOT NULL,
			plan_json TEXT NOT NULL,
			status TEXT NOT NULL,
			step_count INTEGER NOT NULL DEFAULT 0,
			error_count INTEGER NOT NULL DEFAULT 0,
			leak_count INTEGER NOT NULL DEFAULT 0,
			temp_path TEXT NOT NULL,
			cleanup_ok INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			error_detail TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS steps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL REFERENCES runs(id),
			scenario_id TEXT NOT NULL REFERENCES scenarios(id),
			ordinal INTEGER NOT NULL,
			object_key TEXT NOT NULL,
			phase TEXT NOT NULL,
			input_json TEXT NOT NULL,
			state_before_json TEXT NOT NULL,
			state_after_json TEXT NOT NULL,
			result_json TEXT NOT NULL,
			status TEXT NOT NULL,
			error_text TEXT,
			object_sha256 TEXT,
			response_body_sha256 TEXT,
			cache_status TEXT NOT NULL,
			leaked INTEGER NOT NULL,
			evidence_id TEXT,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			UNIQUE (scenario_id, ordinal)
		)`,
		`CREATE TABLE IF NOT EXISTS evidence (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL REFERENCES runs(id),
			kind TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			immutable INTEGER NOT NULL,
			description TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS verifications (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL REFERENCES runs(id),
			kind TEXT NOT NULL,
			subject TEXT NOT NULL,
			expected_json TEXT NOT NULL,
			actual_json TEXT NOT NULL,
			passed INTEGER NOT NULL,
			evidence_id TEXT,
			created_at TEXT NOT NULL,
			detail TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS repeat_groups (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL REFERENCES runs(id),
			scenario_id TEXT NOT NULL REFERENCES scenarios(id),
			object_key TEXT NOT NULL,
			submission_count INTEGER NOT NULL,
			unique_body_hashes INTEGER NOT NULL,
			unique_cache_statuses INTEGER NOT NULL,
			passed INTEGER NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS cleanup (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL REFERENCES runs(id),
			path TEXT NOT NULL,
			existed_before INTEGER NOT NULL,
			exists_after INTEGER NOT NULL,
			action TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			evidence_id TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS fuzz_runs (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL REFERENCES runs(id),
			tool TEXT NOT NULL,
			version TEXT NOT NULL,
			status TEXT NOT NULL,
			command TEXT NOT NULL,
			runs INTEGER NOT NULL,
			exit_code INTEGER NOT NULL,
			found INTEGER NOT NULL,
			artifact_path TEXT,
			artifact_sha256 TEXT,
			log_path TEXT NOT NULL,
			log_sha256 TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			skip_reason TEXT,
			assertion_text TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_steps_run ON steps(run_id, scenario_id, ordinal)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id, kind)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate sqlite: %w", err)
		}
	}
	return nil
}

func (s *Store) BeginRun(ctx context.Context, runID, dbPath, evidenceDir string, cfg any, at time.Time) error {
	raw, err := marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO runs
		(id, schema_version, status, started_at, db_path, evidence_dir, config_json)
		VALUES (?, ?, 'running', ?, ?, ?, ?)`,
		runID, model.SchemaVersion, formatTime(at), dbPath, evidenceDir, raw)
	return err
}

func (s *Store) FinishRun(ctx context.Context, runID, status string, summary any, at time.Time) error {
	raw, err := marshal(summary)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?`,
		status, formatTime(at), raw, runID)
	return err
}

func (s *Store) AddSnapshot(ctx context.Context, runID string, snap model.Snapshot) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO snapshots (run_id, id, label, created_at) VALUES (?, ?, ?, ?)`,
		runID, snap.ID, snap.Label, formatTime(snap.CreatedAt))
	return err
}

func (s *Store) AddObject(ctx context.Context, runID string, obj model.StoredObject) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO objects
		(run_id, key, snapshot_id, version, logical_path, file_name, extension,
		 known_extension, mime, size, sha256, captured_at, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, obj.Key, obj.SnapshotID, obj.Version, obj.LogicalPath, obj.FileName,
		obj.Extension, boolInt(obj.KnownExtension), obj.MIME, obj.Size, obj.SHA256,
		formatTime(obj.CapturedAt), obj.Body)
	return err
}

func (s *Store) AddScenario(ctx context.Context, runID string, plan model.ScenarioPlan, res model.ScenarioResult) error {
	raw, err := marshal(plan)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO scenarios
		(id, run_id, name, order_key, plan_json, status, step_count, error_count,
		 leak_count, temp_path, cleanup_ok, started_at, finished_at, error_detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		res.ID, runID, plan.Name, plan.Order, raw, res.Status, res.StepCount,
		res.ErrorCount, res.LeakCount, res.TempPath, boolInt(res.CleanupOK),
		formatTime(res.StartedAt), formatTime(res.FinishedAt), nullString(res.ErrorDetail))
	return err
}

func (s *Store) UpdateScenario(ctx context.Context, res model.ScenarioResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scenarios SET status = ?, step_count = ?,
		error_count = ?, leak_count = ?, cleanup_ok = ?, finished_at = ?, error_detail = ?
		WHERE id = ?`,
		res.Status, res.StepCount, res.ErrorCount, res.LeakCount, boolInt(res.CleanupOK),
		formatTime(res.FinishedAt), nullString(res.ErrorDetail), res.ID)
	return err
}

func (s *Store) AddStep(ctx context.Context, step model.Step) error {
	input, _ := marshal(step.Input)
	before, _ := marshal(step.StateBefore)
	after, _ := marshal(step.StateAfter)
	result, _ := marshal(step.Result)
	_, err := s.db.ExecContext(ctx, `INSERT INTO steps
		(run_id, scenario_id, ordinal, object_key, phase, input_json,
		 state_before_json, state_after_json, result_json, status, error_text,
		 object_sha256, response_body_sha256, cache_status, leaked,
		 evidence_id, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		step.RunID, step.ScenarioID, step.Ordinal, step.ObjectKey, step.Phase,
		input, before, after, result, step.Status, nullString(step.ErrorText),
		nullString(step.Input.Headers["X-Object-SHA256"]), nullString(step.Result.BodySHA256),
		step.Result.CacheStatus, boolInt(step.Result.Leaked), nullString(step.EvidenceID),
		formatTime(step.StartedAt), formatTime(step.FinishedAt))
	return err
}

func (s *Store) AddEvidence(ctx context.Context, ev model.Evidence) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO evidence
		(id, run_id, kind, path, sha256, size, immutable, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.RunID, ev.Kind, ev.Path, ev.SHA256, ev.Size, boolInt(ev.Immutable),
		ev.Description, formatTime(ev.CreatedAt))
	return err
}

func (s *Store) AddVerification(ctx context.Context, runID string, v model.Verification) error {
	expected, _ := marshal(v.Expected)
	actual, _ := marshal(v.Actual)
	_, err := s.db.ExecContext(ctx, `INSERT INTO verifications
		(id, run_id, kind, subject, expected_json, actual_json, passed,
		 evidence_id, created_at, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, runID, v.Kind, v.Subject, expected, actual, boolInt(v.Passed),
		nullString(v.EvidenceID), formatTime(v.CreatedAt), nullString(v.Detail))
	return err
}

func (s *Store) AddRepeatGroup(ctx context.Context, runID, id, scenarioID, objectKey string, count, bodies, statuses int, passed bool, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repeat_groups
		(id, run_id, scenario_id, object_key, submission_count, unique_body_hashes,
		 unique_cache_statuses, passed, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, runID, scenarioID, objectKey, count, bodies, statuses, boolInt(passed), formatTime(at))
	return err
}

func (s *Store) AddCleanup(ctx context.Context, runID string, rec model.CleanupRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cleanup
		(run_id, path, existed_before, exists_after, action, status, created_at, evidence_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, rec.Path, boolInt(rec.ExistedBefore), boolInt(rec.ExistsAfter),
		rec.Action, rec.Status, formatTime(rec.CreatedAt), nullString(rec.EvidenceID))
	return err
}

func (s *Store) AddFuzz(ctx context.Context, runID string, f model.FuzzResult) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO fuzz_runs
		(id, run_id, tool, version, status, command, runs, exit_code, found,
		 artifact_path, artifact_sha256, log_path, log_sha256, started_at,
		 finished_at, skip_reason, assertion_text)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, runID, f.Tool, f.Version, f.Status, f.Command, f.Runs, f.ExitCode,
		boolInt(f.Found), nullString(f.ArtifactPath), nullString(f.ArtifactSHA),
		f.LogPath, f.LogSHA256, formatTime(f.StartedAt), formatTime(f.FinishedAt),
		nullString(f.SkipReason), nullString(f.AssertionText))
	return err
}

func (s *Store) LatestRunID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM runs ORDER BY started_at DESC, rowid DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

func (s *Store) LoadSummary(ctx context.Context, runID string) (model.RunSummary, error) {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT summary_json FROM runs WHERE id = ?`, runID).Scan(&raw)
	if err != nil {
		return model.RunSummary{}, err
	}
	if !raw.Valid {
		return model.RunSummary{}, fmt.Errorf("run %s has no summary", runID)
	}
	var summary model.RunSummary
	if err := json.Unmarshal([]byte(raw.String), &summary); err != nil {
		return model.RunSummary{}, fmt.Errorf("decode summary: %w", err)
	}
	return summary, nil
}

func (s *Store) LoadObjects(ctx context.Context, runID string) ([]model.StoredObject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, snapshot_id, version, logical_path,
		file_name, extension, known_extension, mime, size, sha256, captured_at, body
		FROM objects WHERE run_id = ? ORDER BY key`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.StoredObject
	for rows.Next() {
		var obj model.StoredObject
		var known int
		var captured string
		if err := rows.Scan(&obj.Key, &obj.SnapshotID, &obj.Version, &obj.LogicalPath,
			&obj.FileName, &obj.Extension, &known, &obj.MIME, &obj.Size, &obj.SHA256,
			&captured, &obj.Body); err != nil {
			return nil, err
		}
		obj.KnownExtension = known != 0
		obj.CapturedAt, err = parseTime(captured)
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}
	return out, rows.Err()
}

func (s *Store) LoadSteps(ctx context.Context, runID string) ([]model.Step, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, scenario_id, ordinal,
		object_key, phase, input_json, state_before_json, state_after_json,
		result_json, status, error_text, cache_status, leaked, evidence_id,
		started_at, finished_at
		FROM steps WHERE run_id = ?
		ORDER BY scenario_id, ordinal`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Step
	for rows.Next() {
		var step model.Step
		var input, before, after, result string
		var errorText, evidenceID sql.NullString
		var leaked int
		var started, finished string
		if err := rows.Scan(&step.ID, &step.RunID, &step.ScenarioID, &step.Ordinal,
			&step.ObjectKey, &step.Phase, &input, &before, &after, &result,
			&step.Status, &errorText, &step.Result.CacheStatus, &leaked,
			&evidenceID, &started, &finished); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(input), &step.Input); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(before), &step.StateBefore); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(after), &step.StateAfter); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(result), &step.Result); err != nil {
			return nil, err
		}
		step.ErrorText = errorText.String
		step.EvidenceID = evidenceID.String
		step.Result.Leaked = leaked != 0
		step.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, err
		}
		step.FinishedAt, err = parseTime(finished)
		if err != nil {
			return nil, err
		}
		out = append(out, step)
	}
	return out, rows.Err()
}

func (s *Store) LoadScenarios(ctx context.Context, runID string) ([]model.ScenarioResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, order_key, status,
		step_count, error_count, leak_count, temp_path, cleanup_ok,
		started_at, finished_at, error_detail
		FROM scenarios WHERE run_id = ? ORDER BY started_at, rowid`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ScenarioResult
	for rows.Next() {
		var res model.ScenarioResult
		var cleanup int
		var started, finished string
		var detail sql.NullString
		if err := rows.Scan(&res.ID, &res.Name, &res.Order, &res.Status,
			&res.StepCount, &res.ErrorCount, &res.LeakCount, &res.TempPath,
			&cleanup, &started, &finished, &detail); err != nil {
			return nil, err
		}
		res.CleanupOK = cleanup != 0
		res.ErrorDetail = detail.String
		res.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, err
		}
		res.FinishedAt, err = parseTime(finished)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

func (s *Store) LoadEvidence(ctx context.Context, runID string) ([]model.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, kind, path, sha256,
		size, immutable, description, created_at FROM evidence
		WHERE run_id = ? ORDER BY created_at, id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Evidence
	for rows.Next() {
		var ev model.Evidence
		var immutable int
		var created string
		if err := rows.Scan(&ev.ID, &ev.RunID, &ev.Kind, &ev.Path, &ev.SHA256,
			&ev.Size, &immutable, &ev.Description, &created); err != nil {
			return nil, err
		}
		ev.Immutable = immutable != 0
		ev.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) LoadCleanup(ctx context.Context, runID string) ([]model.CleanupRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT path, existed_before, exists_after,
		action, status, created_at, evidence_id FROM cleanup
		WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CleanupRecord
	for rows.Next() {
		var rec model.CleanupRecord
		var before, after int
		var created string
		var evidenceID sql.NullString
		if err := rows.Scan(&rec.Path, &before, &after, &rec.Action, &rec.Status,
			&created, &evidenceID); err != nil {
			return nil, err
		}
		rec.ExistedBefore = before != 0
		rec.ExistsAfter = after != 0
		rec.EvidenceID = evidenceID.String
		rec.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) LoadVerifications(ctx context.Context, runID string) ([]model.Verification, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, subject, expected_json,
		actual_json, passed, evidence_id, created_at, detail FROM verifications
		WHERE run_id = ? ORDER BY created_at, id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Verification
	for rows.Next() {
		var v model.Verification
		var expected, actual string
		var passed int
		var evidenceID, detail sql.NullString
		var created string
		if err := rows.Scan(&v.ID, &v.Kind, &v.Subject, &expected, &actual,
			&passed, &evidenceID, &created, &detail); err != nil {
			return nil, err
		}
		v.Expected = json.RawMessage(expected)
		v.Actual = json.RawMessage(actual)
		v.Passed = passed != 0
		v.EvidenceID = evidenceID.String
		v.Detail = detail.String
		v.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) LoadFuzz(ctx context.Context, runID string) (*model.FuzzResult, error) {
	var f model.FuzzResult
	var found int
	var artifactPath, artifactSHA, skip, assertion sql.NullString
	var started, finished string
	err := s.db.QueryRowContext(ctx, `SELECT id, tool, version, status, command,
		runs, exit_code, found, artifact_path, artifact_sha256, log_path,
		log_sha256, started_at, finished_at, skip_reason, assertion_text
		FROM fuzz_runs WHERE run_id = ? ORDER BY started_at DESC LIMIT 1`, runID).
		Scan(&f.ID, &f.Tool, &f.Version, &f.Status, &f.Command, &f.Runs,
			&f.ExitCode, &found, &artifactPath, &artifactSHA, &f.LogPath,
			&f.LogSHA256, &started, &finished, &skip, &assertion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Found = found != 0
	f.ArtifactPath = artifactPath.String
	f.ArtifactSHA = artifactSHA.String
	f.SkipReason = skip.String
	f.AssertionText = assertion.String
	f.StartedAt, err = parseTime(started)
	if err != nil {
		return nil, err
	}
	f.FinishedAt, err = parseTime(finished)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *Store) CountRepeatGroups(ctx context.Context, runID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repeat_groups WHERE run_id = ?`, runID).Scan(&count)
	return count, err
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time %q: %w", value, err)
	}
	return t.UTC(), nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func marshal(v any) (string, error) {
	raw, err := jsonMarshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(raw), nil
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

var ErrNotFound = errors.New("not found")
