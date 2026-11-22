package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"apiskew.local/apiskew/internal/domain"
)

const SchemaVersion = 1

var ErrNotFound = errors.New("not found")

type Store struct {
	db   *sql.DB
	path string
}

type Session struct {
	ID           string
	Name         string
	Status       string
	Scenario     domain.Scenario
	ScenarioJSON string
	ScenarioSHA  string
	NextOrdinal  int
	CreatedAt    string
	UpdatedAt    string
	PausedAt     string
	CompletedAt  string
}

type Sample struct {
	SessionID      string
	ID             string
	Ordinal        int
	Source         string
	Input          []byte
	InputSHA256    string
	Attack         domain.Attack
	Status         string
	FirstSeenAt    string
	LastReplayedAt string
}

type Run struct {
	ID                   int64
	SessionID            string
	SampleID             string
	Attempt              int
	Engine               string
	Status               string
	V1Allow              bool
	V2Allow              bool
	V1Reason             string
	V2Reason             string
	V1Replica            string
	V2Replica            string
	PermissionDifference bool
	Comparable           bool
	FuzzerDetected       bool
	EvidenceJSON         string
	EvidenceSHA256       string
	StartedAt            string
	CompletedAt          string
	DurationMS           int64
}

type Event struct {
	ID         int64
	SessionID  string
	SampleID   string
	Kind       string
	DetailJSON string
	CreatedAt  string
}

type Counts struct {
	Samples int
	Runs    int
}

type ImportItem struct {
	Source      string
	Input       []byte
	Attack      domain.Attack
	Run         Run
	EventKind   string
	EventDetail any
}

type ImportOutcome struct {
	Sample   Sample
	Run      Run
	Inserted bool
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	store := &Store{db: db, path: path}
	if err := store.Init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('active','paused','complete')),
			scenario_json TEXT NOT NULL,
			scenario_sha256 TEXT NOT NULL,
			next_ordinal INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			paused_at TEXT NOT NULL DEFAULT '',
			completed_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS samples (
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			id TEXT NOT NULL,
			ordinal INTEGER NOT NULL,
			source TEXT NOT NULL,
			input BLOB NOT NULL,
			input_sha256 TEXT NOT NULL,
			attack_json TEXT NOT NULL,
			status TEXT NOT NULL,
			first_seen_at TEXT NOT NULL,
			last_replayed_at TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (session_id, id),
			UNIQUE (session_id, ordinal),
			UNIQUE (session_id, input_sha256)
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			sample_id TEXT NOT NULL,
			attempt INTEGER NOT NULL,
			engine TEXT NOT NULL,
			status TEXT NOT NULL,
			v1_allow INTEGER NOT NULL,
			v2_allow INTEGER NOT NULL,
			v1_reason TEXT NOT NULL,
			v2_reason TEXT NOT NULL,
			v1_replica TEXT NOT NULL,
			v2_replica TEXT NOT NULL,
			permission_difference INTEGER NOT NULL,
			comparable INTEGER NOT NULL,
			fuzzer_detected INTEGER NOT NULL,
			evidence_json TEXT NOT NULL,
			evidence_sha256 TEXT NOT NULL,
			started_at TEXT NOT NULL,
			completed_at TEXT NOT NULL,
			duration_ms INTEGER NOT NULL,
			FOREIGN KEY (session_id, sample_id) REFERENCES samples(session_id, id) ON DELETE CASCADE,
			UNIQUE (session_id, sample_id, attempt)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			sample_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL,
			detail_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS samples_order_idx ON samples(session_id, ordinal)`,
		`CREATE INDEX IF NOT EXISTS runs_lookup_idx ON runs(session_id, sample_id, attempt)`,
		`CREATE INDEX IF NOT EXISTS events_order_idx ON events(session_id, id)`,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		fmt.Sprint(SchemaVersion),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func NewSessionID(t time.Time) string {
	return "sess-" + t.UTC().Format("20060102T150405") + "-" + strings.ToLower(randSuffix(6))
}

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "api-version-permission-diff"
	}
	return name
}

func randSuffix(n int) string {
	const alphabet = "0123456789abcdef"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1_000_000)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

func (s *Store) CreateSession(ctx context.Context, id, name string, scenario domain.Scenario) (Session, error) {
	if err := scenario.Validate(); err != nil {
		return Session{}, err
	}
	scenarioJSON, err := scenario.JSON()
	if err != nil {
		return Session{}, err
	}
	scenarioSHA, err := scenario.Hash()
	if err != nil {
		return Session{}, err
	}
	if id == "" {
		id = NewSessionID(time.Now())
	}
	timestamp := now()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions(
			id,name,status,scenario_json,scenario_sha256,next_ordinal,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?)`,
		id, normalizeName(name), "active", string(scenarioJSON), scenarioSHA, 1, timestamp, timestamp,
	)
	if err != nil {
		return Session{}, err
	}
	return s.GetSession(ctx, id)
}

func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,status,scenario_json,scenario_sha256,next_ordinal,created_at,updated_at,paused_at,completed_at
		 FROM sessions WHERE id=?`, id,
	)
	var session Session
	var scenarioJSON string
	if err := row.Scan(
		&session.ID, &session.Name, &session.Status, &scenarioJSON, &session.ScenarioSHA,
		&session.NextOrdinal, &session.CreatedAt, &session.UpdatedAt, &session.PausedAt, &session.CompletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("%w: session %s", ErrNotFound, id)
		}
		return Session{}, err
	}
	scenario, err := domain.DecodeScenarioJSON([]byte(scenarioJSON))
	if err != nil {
		return Session{}, fmt.Errorf("decode stored scenario: %w", err)
	}
	session.Scenario = scenario
	session.ScenarioJSON = scenarioJSON
	return session, nil
}

func (s *Store) LatestSession(ctx context.Context) (Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id FROM sessions ORDER BY created_at DESC, id DESC LIMIT 1`,
	)
	var id string
	if err := row.Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("%w: no sessions", ErrNotFound)
		}
		return Session{}, err
	}
	return s.GetSession(ctx, id)
}

func (s *Store) ListSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM sessions ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(ids))
	for _, id := range ids {
		session, err := s.GetSession(ctx, id)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s *Store) SetSessionStatus(ctx context.Context, id, status string) error {
	if status != "active" && status != "paused" && status != "complete" {
		return fmt.Errorf("invalid session status %q", status)
	}
	timestamp := now()
	query := `UPDATE sessions SET status=?,updated_at=? WHERE id=?`
	args := []any{status, timestamp, id}
	if status == "paused" {
		query = `UPDATE sessions SET status=?,updated_at=?,paused_at=? WHERE id=?`
		args = []any{status, timestamp, timestamp, id}
	}
	if status == "complete" {
		query = `UPDATE sessions SET status=?,updated_at=?,completed_at=? WHERE id=?`
		args = []any{status, timestamp, timestamp, id}
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: session %s", ErrNotFound, id)
	}
	return nil
}

func (s *Store) InsertSample(ctx context.Context, sessionID, source string, input []byte) (Sample, bool, error) {
	attack, err := domain.DecodeAttack(input)
	if err != nil {
		return Sample{}, false, err
	}
	attackJSON, err := json.Marshal(attack)
	if err != nil {
		return Sample{}, false, err
	}
	inputSHA := domain.SHA256Hex(input)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Sample{}, false, err
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM samples WHERE session_id=? AND input_sha256=?`,
		sessionID, inputSHA,
	).Scan(&existingID)
	if err == nil {
		sample, getErr := s.getSampleTx(ctx, tx, sessionID, existingID)
		if getErr != nil {
			return Sample{}, false, getErr
		}
		return sample, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Sample{}, false, err
	}

	var ordinal int
	if err := tx.QueryRowContext(ctx,
		`SELECT next_ordinal FROM sessions WHERE id=?`, sessionID,
	).Scan(&ordinal); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Sample{}, false, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
		}
		return Sample{}, false, err
	}
	id := fmt.Sprintf("s%04d", ordinal)
	timestamp := now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO samples(
			session_id,id,ordinal,source,input,input_sha256,attack_json,status,first_seen_at
		) VALUES(?,?,?,?,?,?,?,?,?)`,
		sessionID, id, ordinal, source, input, inputSHA, string(attackJSON), "discovered", timestamp,
	); err != nil {
		return Sample{}, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET next_ordinal=?,updated_at=? WHERE id=?`,
		ordinal+1, timestamp, sessionID,
	); err != nil {
		return Sample{}, false, err
	}
	sample, err := s.getSampleTx(ctx, tx, sessionID, id)
	if err != nil {
		return Sample{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Sample{}, false, err
	}
	return sample, true, nil
}

func (s *Store) getSampleTx(ctx context.Context, tx *sql.Tx, sessionID, id string) (Sample, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT session_id,id,ordinal,source,input,input_sha256,attack_json,status,first_seen_at,last_replayed_at
		 FROM samples WHERE session_id=? AND id=?`, sessionID, id,
	)
	return scanSample(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSample(row rowScanner) (Sample, error) {
	var sample Sample
	var attackJSON string
	if err := row.Scan(
		&sample.SessionID, &sample.ID, &sample.Ordinal, &sample.Source, &sample.Input,
		&sample.InputSHA256, &attackJSON, &sample.Status, &sample.FirstSeenAt, &sample.LastReplayedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Sample{}, ErrNotFound
		}
		return Sample{}, err
	}
	if err := json.Unmarshal([]byte(attackJSON), &sample.Attack); err != nil {
		return Sample{}, fmt.Errorf("decode sample %s attack: %w", sample.ID, err)
	}
	return sample, nil
}

func (s *Store) GetSample(ctx context.Context, sessionID, id string) (Sample, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_id,id,ordinal,source,input,input_sha256,attack_json,status,first_seen_at,last_replayed_at
		 FROM samples WHERE session_id=? AND id=?`, sessionID, id,
	)
	return scanSample(row)
}

func (s *Store) ListSamples(ctx context.Context, sessionID string) ([]Sample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id,id,ordinal,source,input,input_sha256,attack_json,status,first_seen_at,last_replayed_at
		 FROM samples WHERE session_id=? ORDER BY ordinal ASC`, sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var samples []Sample
	for rows.Next() {
		sample, err := scanSample(rows)
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

func (s *Store) MarkSampleReplayed(ctx context.Context, sessionID, sampleID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE samples SET status='replayed',last_replayed_at=? WHERE session_id=? AND id=?`,
		now(), sessionID, sampleID,
	)
	return err
}

func (s *Store) AddRun(ctx context.Context, run Run) (Run, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback()
	var attempt int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(attempt),0)+1 FROM runs WHERE session_id=? AND sample_id=?`,
		run.SessionID, run.SampleID,
	).Scan(&attempt); err != nil {
		return Run{}, err
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO runs(
			session_id,sample_id,attempt,engine,status,v1_allow,v2_allow,v1_reason,v2_reason,
			v1_replica,v2_replica,permission_difference,comparable,fuzzer_detected,
			evidence_json,evidence_sha256,started_at,completed_at,duration_ms
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		run.SessionID, run.SampleID, attempt, run.Engine, run.Status,
		boolInt(run.V1Allow), boolInt(run.V2Allow), run.V1Reason, run.V2Reason,
		run.V1Replica, run.V2Replica, boolInt(run.PermissionDifference), boolInt(run.Comparable),
		boolInt(run.FuzzerDetected), run.EvidenceJSON, run.EvidenceSHA256,
		run.StartedAt, run.CompletedAt, run.DurationMS,
	)
	if err != nil {
		return Run{}, err
	}
	run.ID, err = result.LastInsertId()
	if err != nil {
		return Run{}, err
	}
	run.Attempt = attempt
	if _, err := tx.ExecContext(ctx,
		`UPDATE samples SET status='replayed',last_replayed_at=? WHERE session_id=? AND id=?`,
		run.CompletedAt, run.SessionID, run.SampleID,
	); err != nil {
		return Run{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET updated_at=? WHERE id=?`, run.CompletedAt, run.SessionID,
	); err != nil {
		return Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return Run{}, err
	}
	return run, nil
}

func (s *Store) ImportSamples(ctx context.Context, sessionID string, items []ImportItem) ([]ImportOutcome, error) {
	if len(items) == 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var nextOrdinal int
	if err := tx.QueryRowContext(ctx,
		`SELECT next_ordinal FROM sessions WHERE id=?`, sessionID,
	).Scan(&nextOrdinal); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
		}
		return nil, err
	}
	timestamp := now()
	outcomes := make([]ImportOutcome, 0, len(items))
	insertedCount := 0
	for _, item := range items {
		attackJSON, err := json.Marshal(item.Attack)
		if err != nil {
			return nil, err
		}
		inputSHA := domain.SHA256Hex(item.Input)
		var existingID string
		err = tx.QueryRowContext(ctx,
			`SELECT id FROM samples WHERE session_id=? AND input_sha256=?`,
			sessionID, inputSHA,
		).Scan(&existingID)
		if err == nil {
			sample, err := s.getSampleTx(ctx, tx, sessionID, existingID)
			if err != nil {
				return nil, err
			}
			outcomes = append(outcomes, ImportOutcome{Sample: sample, Inserted: false})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		sampleID := fmt.Sprintf("s%04d", nextOrdinal)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO samples(
				session_id,id,ordinal,source,input,input_sha256,attack_json,status,first_seen_at,last_replayed_at
			) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			sessionID, sampleID, nextOrdinal, item.Source, item.Input, inputSHA,
			string(attackJSON), "replayed", timestamp, timestamp,
		); err != nil {
			return nil, err
		}
		run := item.Run
		run.SessionID = sessionID
		run.SampleID = sampleID
		run.Attempt = 1
		result, err := tx.ExecContext(ctx,
			`INSERT INTO runs(
				session_id,sample_id,attempt,engine,status,v1_allow,v2_allow,v1_reason,v2_reason,
				v1_replica,v2_replica,permission_difference,comparable,fuzzer_detected,
				evidence_json,evidence_sha256,started_at,completed_at,duration_ms
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			run.SessionID, run.SampleID, run.Attempt, run.Engine, run.Status,
			boolInt(run.V1Allow), boolInt(run.V2Allow), run.V1Reason, run.V2Reason,
			run.V1Replica, run.V2Replica, boolInt(run.PermissionDifference),
			boolInt(run.Comparable), boolInt(run.FuzzerDetected), run.EvidenceJSON,
			run.EvidenceSHA256, run.StartedAt, run.CompletedAt, run.DurationMS,
		)
		if err != nil {
			return nil, err
		}
		run.ID, err = result.LastInsertId()
		if err != nil {
			return nil, err
		}
		detailJSON := []byte("{}")
		if item.EventDetail != nil {
			detailJSON, err = json.Marshal(item.EventDetail)
			if err != nil {
				return nil, err
			}
		}
		eventKind := item.EventKind
		if eventKind == "" {
			eventKind = "sample_imported"
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events(session_id,sample_id,kind,detail_json,created_at) VALUES(?,?,?,?,?)`,
			sessionID, sampleID, eventKind, string(detailJSON), timestamp,
		); err != nil {
			return nil, err
		}
		sample := Sample{
			SessionID:      sessionID,
			ID:             sampleID,
			Ordinal:        nextOrdinal,
			Source:         item.Source,
			Input:          item.Input,
			InputSHA256:    inputSHA,
			Attack:         item.Attack,
			Status:         "replayed",
			FirstSeenAt:    timestamp,
			LastReplayedAt: timestamp,
		}
		outcomes = append(outcomes, ImportOutcome{Sample: sample, Run: run, Inserted: true})
		nextOrdinal++
		insertedCount++
	}
	if insertedCount > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET next_ordinal=?,updated_at=? WHERE id=?`,
			nextOrdinal, timestamp, sessionID,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return outcomes, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Store) ListRuns(ctx context.Context, sessionID, sampleID string) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,session_id,sample_id,attempt,engine,status,v1_allow,v2_allow,v1_reason,v2_reason,
		        v1_replica,v2_replica,permission_difference,comparable,fuzzer_detected,
		        evidence_json,evidence_sha256,started_at,completed_at,duration_ms
		 FROM runs WHERE session_id=? AND sample_id=? ORDER BY attempt ASC`,
		sessionID, sampleID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) LatestRun(ctx context.Context, sessionID, sampleID string) (Run, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,session_id,sample_id,attempt,engine,status,v1_allow,v2_allow,v1_reason,v2_reason,
		        v1_replica,v2_replica,permission_difference,comparable,fuzzer_detected,
		        evidence_json,evidence_sha256,started_at,completed_at,duration_ms
		 FROM runs WHERE session_id=? AND sample_id=? ORDER BY attempt DESC LIMIT 1`,
		sessionID, sampleID,
	)
	return scanRun(row)
}

func scanRun(row rowScanner) (Run, error) {
	var run Run
	var v1Allow, v2Allow, difference, comparable, fuzzerDetected int
	if err := row.Scan(
		&run.ID, &run.SessionID, &run.SampleID, &run.Attempt, &run.Engine, &run.Status,
		&v1Allow, &v2Allow, &run.V1Reason, &run.V2Reason, &run.V1Replica, &run.V2Replica,
		&difference, &comparable, &fuzzerDetected, &run.EvidenceJSON, &run.EvidenceSHA256,
		&run.StartedAt, &run.CompletedAt, &run.DurationMS,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Run{}, ErrNotFound
		}
		return Run{}, err
	}
	run.V1Allow = v1Allow != 0
	run.V2Allow = v2Allow != 0
	run.PermissionDifference = difference != 0
	run.Comparable = comparable != 0
	run.FuzzerDetected = fuzzerDetected != 0
	return run, nil
}

func (s *Store) AddEvent(ctx context.Context, sessionID, sampleID, kind string, detail any) error {
	var detailJSON []byte
	var err error
	if detail == nil {
		detailJSON = []byte("{}")
	} else if raw, ok := detail.([]byte); ok {
		detailJSON = raw
	} else {
		detailJSON, err = json.Marshal(detail)
		if err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO events(session_id,sample_id,kind,detail_json,created_at) VALUES(?,?,?,?,?)`,
		sessionID, sampleID, kind, string(detailJSON), now(),
	)
	return err
}

func (s *Store) ListEvents(ctx context.Context, sessionID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,session_id,sample_id,kind,detail_json,created_at
		 FROM events WHERE session_id=? ORDER BY id ASC`, sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.SessionID, &event.SampleID, &event.Kind, &event.DetailJSON, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) Counts(ctx context.Context, sessionID string) (Counts, error) {
	var counts Counts
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM samples WHERE session_id=?`, sessionID,
	).Scan(&counts.Samples); err != nil {
		return Counts{}, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM runs WHERE session_id=?`, sessionID,
	).Scan(&counts.Runs); err != nil {
		return Counts{}, err
	}
	return counts, nil
}

func (s *Store) Snapshot(ctx context.Context, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	escaped := strings.ReplaceAll(destination, "'", "''")
	_, err := s.db.ExecContext(ctx, `VACUUM INTO '`+escaped+`'`)
	return err
}
