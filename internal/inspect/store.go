package inspect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	dbPath string
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dbPath: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Bootstrap(ctx context.Context) error {
	if err := s.migrate(ctx); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cases`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if err := s.seed(ctx); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
	}
	return s.recoverInterrupted(ctx)
}

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cases (
			id TEXT PRIMARY KEY, title TEXT NOT NULL, target TEXT NOT NULL,
			case_owner TEXT NOT NULL, opened_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS objects (
			id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
			kind TEXT NOT NULL, name TEXT NOT NULL, extension TEXT NOT NULL,
			media_type TEXT NOT NULL, version TEXT NOT NULL, source_locator TEXT NOT NULL,
			captured_at TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
			status TEXT NOT NULL, is_exception INTEGER NOT NULL DEFAULT 0,
			summary TEXT NOT NULL, sort_order INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			id TEXT PRIMARY KEY, object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
			version TEXT NOT NULL, captured_at TEXT NOT NULL, body TEXT NOT NULL,
			headers_json TEXT NOT NULL, signature TEXT NOT NULL, signature_alg TEXT NOT NULL,
			canonicalizer TEXT NOT NULL, verifier_source TEXT NOT NULL,
			source_line INTEGER NOT NULL, source_excerpt TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS conclusions (
			id TEXT PRIMARY KEY, object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
			verdict TEXT NOT NULL, confidence TEXT NOT NULL, summary TEXT NOT NULL,
			rationale TEXT NOT NULL, boundary_note TEXT NOT NULL, evidence_ids TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS processing_steps (
			id TEXT PRIMARY KEY, object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
			seq INTEGER NOT NULL, action TEXT NOT NULL, input_ref TEXT NOT NULL,
			output_ref TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL,
			evidence_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS evidence (
			id TEXT PRIMARY KEY, object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
			snapshot_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, label TEXT NOT NULL,
			value TEXT NOT NULL, sha256 TEXT NOT NULL, parent_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS fuzz_runs (
			id TEXT PRIMARY KEY, target TEXT NOT NULL, engine TEXT NOT NULL,
			corpus_entries INTEGER NOT NULL, executions INTEGER NOT NULL, crashes INTEGER NOT NULL,
			artifact_sha256 TEXT NOT NULL, artifact_hex TEXT NOT NULL, status TEXT NOT NULL,
			note TEXT NOT NULL, created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS temp_state (
			id TEXT PRIMARY KEY, path TEXT NOT NULL, reason TEXT NOT NULL,
			bytes INTEGER NOT NULL, created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS operations (
			id TEXT PRIMARY KEY, object_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
			outcome TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_objects_case ON objects(case_id, sort_order)`,
		`CREATE INDEX IF NOT EXISTS idx_steps_object ON processing_steps(object_id, seq)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_object ON evidence(object_id)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration: %w", err)
		}
	}
	return nil
}

func (s *Store) recoverInterrupted(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE objects SET status = 'pending'
		WHERE status = 'running'`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO operations (id, object_id, action, outcome, detail, created_at)
		SELECT 'recover-' || id, id, 'resume', 'ok', 'Interrupted run resumed during bootstrap.', ? FROM objects
		WHERE status = 'pending'`, nowUTC())
	return err
}

func (s *Store) Case(ctx context.Context) (Case, error) {
	var c Case
	err := s.db.QueryRowContext(ctx, `SELECT id, title, target, case_owner, opened_at FROM cases LIMIT 1`).
		Scan(&c.ID, &c.Title, &c.Target, &c.CaseOwner, &c.OpenedAt)
	if err != nil {
		return c, err
	}
	c.Objects, err = s.objects(ctx, c.ID)
	if err != nil {
		return c, err
	}
	c.FuzzRuns, err = s.fuzzRuns(ctx)
	if err != nil {
		return c, err
	}
	if c.Operations, err = s.operations(ctx); err != nil {
		return c, err
	}
	if c.Temporary, err = s.temporaryStates(ctx); err != nil {
		return c, err
	}
	for i := range c.Objects {
		c.Stats.Objects++
		c.Stats.Evidence += len(c.Objects[i].Evidence)
		c.Stats.Traced += len(c.Objects[i].Evidence)
		switch c.Objects[i].Status {
		case VerdictVerified:
			c.Stats.Verified++
		case VerdictIndeterminate:
			c.Stats.Indeterminate++
		case VerdictError:
			c.Stats.Errors++
		}
	}
	return c, nil
}

func (s *Store) operations(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_id, action, outcome, detail, created_at
		FROM operations ORDER BY created_at DESC, rowid DESC LIMIT 24`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ops []Operation
	for rows.Next() {
		var op Operation
		if err := rows.Scan(&op.ID, &op.ObjectID, &op.Action, &op.Outcome, &op.Detail,
			&op.CreatedAt); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

func (s *Store) temporaryStates(ctx context.Context) ([]TemporaryState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, path, reason, bytes, created_at
		FROM temp_state ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []TemporaryState
	for rows.Next() {
		var state TemporaryState
		if err := rows.Scan(&state.ID, &state.Path, &state.Reason, &state.Bytes,
			&state.CreatedAt); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (s *Store) objects(ctx context.Context, caseID string) ([]Object, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, name, extension, media_type, version,
		source_locator, captured_at, size_bytes, sha256, status, is_exception, summary
		FROM objects WHERE case_id = ? ORDER BY sort_order`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []Object
	for rows.Next() {
		var obj Object
		if err := rows.Scan(&obj.ID, &obj.Kind, &obj.Name, &obj.Extension, &obj.MediaType,
			&obj.Version, &obj.SourceLocator, &obj.CapturedAt, &obj.SizeBytes, &obj.SHA256,
			&obj.Status, &obj.IsException, &obj.Summary); err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range objects {
		if err := s.hydrateObject(ctx, &objects[i]); err != nil {
			return nil, err
		}
	}
	return objects, nil
}

func (s *Store) hydrateObject(ctx context.Context, obj *Object) error {
	var err error
	if obj.Snapshots, err = s.snapshots(ctx, obj.ID); err != nil {
		return err
	}
	if obj.Conclusion, err = s.conclusion(ctx, obj.ID); err != nil {
		return err
	}
	if obj.Steps, err = s.steps(ctx, obj.ID); err != nil {
		return err
	}
	obj.Evidence, err = s.evidence(ctx, obj.ID)
	return err
}

func (s *Store) snapshots(ctx context.Context, objectID string) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_id, version, captured_at, body,
		headers_json, signature, signature_alg, canonicalizer, verifier_source, source_line,
		source_excerpt FROM snapshots WHERE object_id = ? ORDER BY captured_at`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []Snapshot
	for rows.Next() {
		var snap Snapshot
		if err := rows.Scan(&snap.ID, &snap.ObjectID, &snap.Version, &snap.CapturedAt,
			&snap.Body, &snap.HeadersJSON, &snap.Signature, &snap.SignatureAlg,
			&snap.Canonicalizer, &snap.VerifierSource, &snap.SourceLine,
			&snap.SourceExcerpt); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots, rows.Err()
}

func (s *Store) conclusion(ctx context.Context, objectID string) (*Conclusion, error) {
	var c Conclusion
	var ids string
	err := s.db.QueryRowContext(ctx, `SELECT id, verdict, confidence, summary, rationale,
		boundary_note, evidence_ids, created_at FROM conclusions WHERE object_id = ?
		ORDER BY created_at DESC LIMIT 1`, objectID).Scan(&c.ID, &c.Verdict, &c.Confidence,
		&c.Summary, &c.Rationale, &c.BoundaryNote, &ids, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(ids), &c.EvidenceIDs)
	return &c, nil
}

func (s *Store) steps(ctx context.Context, objectID string) ([]ProcessingStep, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_id, seq, action, input_ref,
		output_ref, status, detail, evidence_id FROM processing_steps
		WHERE object_id = ? ORDER BY seq`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []ProcessingStep
	for rows.Next() {
		var step ProcessingStep
		if err := rows.Scan(&step.ID, &step.ObjectID, &step.Seq, &step.Action, &step.InputRef,
			&step.OutputRef, &step.Status, &step.Detail, &step.EvidenceID); err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

func (s *Store) evidence(ctx context.Context, objectID string) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_id, snapshot_id, kind, label,
		value, sha256, parent_id, created_at FROM evidence WHERE object_id = ?
		ORDER BY rowid`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Evidence
	for rows.Next() {
		var ev Evidence
		if err := rows.Scan(&ev.ID, &ev.ObjectID, &ev.SnapshotID, &ev.Kind, &ev.Label,
			&ev.Value, &ev.SHA256, &ev.ParentID, &ev.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, ev)
	}
	return items, rows.Err()
}

func (s *Store) fuzzRuns(ctx context.Context) ([]FuzzRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, target, engine, corpus_entries, executions,
		crashes, artifact_sha256, artifact_hex, status, note, created_at FROM fuzz_runs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []FuzzRun
	for rows.Next() {
		var run FuzzRun
		if err := rows.Scan(&run.ID, &run.Target, &run.Engine, &run.CorpusEntries,
			&run.Executions, &run.Crashes, &run.ArtifactSHA256, &run.ArtifactHex,
			&run.Status, &run.Note, &run.CreatedAt); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func cleanDBPath(path string) string {
	return filepath.Clean(strings.TrimSpace(path))
}

func (s *Store) cleanupFiles(paths []string) error {
	var errs []error
	for _, path := range paths {
		target := cleanDBPath(path)
		if target == "." || target == "/" || target == s.dbPath {
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
