package ledger

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"pathaliaslab/internal/model"
)

type Ledger struct {
	db   *sql.DB
	path string
}

type StepRecord struct {
	RunID             string
	StepNo            int
	OpID              string
	Kind              string
	InputJSON         string
	StateBeforeJSON   string
	ResultJSON        string
	StateAfterJSON    string
	StateBeforeSHA256 string
	ResultSHA256      string
	StateAfterSHA256  string
	EvidenceSHA256    string
}

type RunRecord struct {
	RunID            string
	ScenarioName     string
	Role             string
	ScenarioJSON     string
	Status           string
	FinalStateJSON   string
	InputSHA256      string
	FinalStateSHA256 string
	ResolutionSHA256 string
	EventSHA256      string
	StepCount        int
}

type CheckRecord struct {
	RunID     string
	CheckName string
	Scope     string
	Expected  string
	Actual    string
	Passed    bool
	Detail    string
}

type ReplayRecord struct {
	SourceRunID string
	ReplayRunID string
	InputMatch  bool
	StateMatch  bool
	ResultMatch bool
	Passed      bool
	Detail      string
}

func Open(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := "file:" + path + "?_busy_timeout=5000&_foreign_keys=on&_journal_mode=DELETE"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	ledger := &Ledger{db: db, path: path}
	if err := ledger.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return ledger, nil
}

func (l *Ledger) Close() error {
	return l.db.Close()
}

func (l *Ledger) Path() string {
	return l.path
}

func (l *Ledger) Meta(key string) (string, error) {
	var value string
	if err := l.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}

func (l *Ledger) Checkpoint() error {
	_, err := l.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

func (l *Ledger) ResetRun(runID string) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	for _, statement := range []string{
		`DELETE FROM steps WHERE run_id=?`,
		`DELETE FROM checks WHERE run_id=?`,
		`DELETE FROM runs WHERE run_id=?`,
	} {
		if _, err := tx.Exec(statement, runID); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (l *Ledger) BackupTo(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	escaped := strings.ReplaceAll(path, "'", "''")
	_, err := l.db.Exec(`VACUUM INTO '` + escaped + `'`)
	return err
}

func (l *Ledger) migrate() error {
	const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  scenario_name TEXT NOT NULL,
  role TEXT NOT NULL,
  scenario_json TEXT NOT NULL,
  started_at_utc TEXT NOT NULL,
  input_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  final_state_json TEXT NOT NULL,
  final_state_sha256 TEXT NOT NULL,
  resolution_sha256 TEXT NOT NULL,
  event_sha256 TEXT NOT NULL,
  step_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  step_no INTEGER NOT NULL,
  op_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  input_json TEXT NOT NULL,
  state_before_json TEXT NOT NULL,
  result_json TEXT NOT NULL,
  state_after_json TEXT NOT NULL,
  state_before_sha256 TEXT NOT NULL,
  result_sha256 TEXT NOT NULL,
  state_after_sha256 TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL,
  PRIMARY KEY (run_id, step_no)
);
CREATE TABLE IF NOT EXISTS checks (
  run_id TEXT NOT NULL,
  check_name TEXT NOT NULL,
  scope TEXT NOT NULL,
  expected TEXT NOT NULL,
  actual TEXT NOT NULL,
  passed INTEGER NOT NULL,
  detail TEXT NOT NULL,
  PRIMARY KEY (run_id, check_name)
);
CREATE TABLE IF NOT EXISTS replays (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_run_id TEXT NOT NULL,
  replay_run_id TEXT NOT NULL,
  input_match INTEGER NOT NULL,
  state_match INTEGER NOT NULL,
  result_match INTEGER NOT NULL,
  passed INTEGER NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
  path TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta(key, value) VALUES
  ('schema_version', '1'),
  ('sqlite_version', sqlite_version());
`
	if _, err := l.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func (l *Ledger) BeginRun(runID, scenarioName, role string, scenarioJSON []byte) error {
	inputHash := SHA256(scenarioJSON)
	_, err := l.db.Exec(`
INSERT INTO runs(
  run_id, scenario_name, role, scenario_json, started_at_utc, input_sha256,
  status, final_state_json, final_state_sha256, resolution_sha256,
  event_sha256, step_count
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		runID, scenarioName, role, string(scenarioJSON),
		time.Now().UTC().Format(time.RFC3339Nano), inputHash,
		"running", "{}", "", "", "", 0,
	)
	if err != nil {
		return fmt.Errorf("begin run %s: %w", runID, err)
	}
	return nil
}

func (l *Ledger) AddStep(runID string, stepNo int, inputJSON []byte, stateBefore, result, stateAfter []byte) (string, error) {
	var previous string
	err := l.db.QueryRow(`
SELECT evidence_sha256 FROM steps
WHERE run_id = ? ORDER BY step_no DESC LIMIT 1`, runID).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("read previous evidence: %w", err)
	}
	if previous == "" {
		previous = hex.EncodeToString(make([]byte, sha256.Size))
	}

	evidence := chainHash(previous, runID, stepNo, inputJSON, stateBefore, result, stateAfter)
	var opID, kind string
	var op model.Op
	if err := json.Unmarshal(inputJSON, &op); err != nil {
		return "", fmt.Errorf("decode input for step %d: %w", stepNo, err)
	}
	opID, kind = op.ID, string(op.Kind)

	_, err = l.db.Exec(`
INSERT INTO steps(
  run_id, step_no, op_id, kind, input_json, state_before_json,
  result_json, state_after_json, state_before_sha256, result_sha256,
  state_after_sha256, evidence_sha256
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		runID, stepNo, opID, kind, string(inputJSON), string(stateBefore),
		string(result), string(stateAfter), SHA256(stateBefore), SHA256(result),
		SHA256(stateAfter), evidence,
	)
	if err != nil {
		return "", fmt.Errorf("add step %d: %w", stepNo, err)
	}
	return evidence, nil
}

func (l *Ledger) FinishRun(runID, status string, finalState []byte, resolutionDigest, eventHash string, stepCount int) error {
	_, err := l.db.Exec(`
UPDATE runs SET status=?, final_state_json=?, final_state_sha256=?,
  resolution_sha256=?, event_sha256=?, step_count=?
WHERE run_id=?`,
		status, string(finalState), SHA256(finalState), resolutionDigest,
		eventHash, stepCount, runID,
	)
	if err != nil {
		return fmt.Errorf("finish run %s: %w", runID, err)
	}
	return nil
}

func (l *Ledger) SetRunStatus(runID, status string) error {
	_, err := l.db.Exec(`UPDATE runs SET status=? WHERE run_id=?`, status, runID)
	return err
}

func (l *Ledger) AddCheck(record CheckRecord) error {
	passed := 0
	if record.Passed {
		passed = 1
	}
	_, err := l.db.Exec(`
INSERT OR REPLACE INTO checks(
  run_id, check_name, scope, expected, actual, passed, detail
) VALUES(?,?,?,?,?,?,?)`,
		record.RunID, record.CheckName, record.Scope, record.Expected,
		record.Actual, passed, record.Detail,
	)
	if err != nil {
		return fmt.Errorf("add check %s/%s: %w", record.RunID, record.CheckName, err)
	}
	return nil
}

func (l *Ledger) AddReplay(record ReplayRecord) error {
	_, err := l.db.Exec(`
INSERT INTO replays(
  source_run_id, replay_run_id, input_match, state_match, result_match, passed, detail
) VALUES(?,?,?,?,?,?,?)`,
		record.SourceRunID, record.ReplayRunID, boolInt(record.InputMatch),
		boolInt(record.StateMatch), boolInt(record.ResultMatch),
		boolInt(record.Passed), record.Detail,
	)
	if err != nil {
		return fmt.Errorf("add replay %s: %w", record.SourceRunID, err)
	}
	return nil
}

func (l *Ledger) Run(runID string) (RunRecord, error) {
	var record RunRecord
	err := l.db.QueryRow(`
SELECT run_id, scenario_name, role, scenario_json, status, final_state_json,
  input_sha256, final_state_sha256, resolution_sha256, event_sha256, step_count
FROM runs WHERE run_id=?`, runID).Scan(
		&record.RunID, &record.ScenarioName, &record.Role, &record.ScenarioJSON,
		&record.Status, &record.FinalStateJSON, &record.InputSHA256,
		&record.FinalStateSHA256, &record.ResolutionSHA256, &record.EventSHA256,
		&record.StepCount,
	)
	if err != nil {
		return RunRecord{}, fmt.Errorf("read run %s: %w", runID, err)
	}
	return record, nil
}

func (l *Ledger) Steps(runID string) ([]StepRecord, error) {
	rows, err := l.db.Query(`
SELECT run_id, step_no, op_id, kind, input_json, state_before_json,
  result_json, state_after_json, state_before_sha256, result_sha256,
  state_after_sha256, evidence_sha256
FROM steps WHERE run_id=? ORDER BY step_no`, runID)
	if err != nil {
		return nil, fmt.Errorf("read steps for %s: %w", runID, err)
	}
	defer rows.Close()
	records := make([]StepRecord, 0)
	for rows.Next() {
		var record StepRecord
		if err := rows.Scan(
			&record.RunID, &record.StepNo, &record.OpID, &record.Kind,
			&record.InputJSON, &record.StateBeforeJSON, &record.ResultJSON,
			&record.StateAfterJSON, &record.StateBeforeSHA256,
			&record.ResultSHA256, &record.StateAfterSHA256, &record.EvidenceSHA256,
		); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (l *Ledger) Runs() ([]RunRecord, error) {
	rows, err := l.db.Query(`
SELECT run_id, scenario_name, role, scenario_json, status, final_state_json,
  input_sha256, final_state_sha256, resolution_sha256, event_sha256, step_count
FROM runs ORDER BY run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]RunRecord, 0)
	for rows.Next() {
		var record RunRecord
		if err := rows.Scan(
			&record.RunID, &record.ScenarioName, &record.Role, &record.ScenarioJSON,
			&record.Status, &record.FinalStateJSON, &record.InputSHA256,
			&record.FinalStateSHA256, &record.ResolutionSHA256, &record.EventSHA256,
			&record.StepCount,
		); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (l *Ledger) Checks() ([]CheckRecord, error) {
	rows, err := l.db.Query(`
SELECT run_id, check_name, scope, expected, actual, passed, detail
FROM checks ORDER BY run_id, check_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]CheckRecord, 0)
	for rows.Next() {
		var record CheckRecord
		var passed int
		if err := rows.Scan(
			&record.RunID, &record.CheckName, &record.Scope, &record.Expected,
			&record.Actual, &passed, &record.Detail,
		); err != nil {
			return nil, err
		}
		record.Passed = passed != 0
		records = append(records, record)
	}
	return records, rows.Err()
}

func (l *Ledger) Replays() ([]ReplayRecord, error) {
	rows, err := l.db.Query(`
SELECT source_run_id, replay_run_id, input_match, state_match, result_match, passed, detail
FROM replays ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]ReplayRecord, 0)
	for rows.Next() {
		var record ReplayRecord
		var inputMatch, stateMatch, resultMatch, passed int
		if err := rows.Scan(
			&record.SourceRunID, &record.ReplayRunID, &inputMatch, &stateMatch,
			&resultMatch, &passed, &record.Detail,
		); err != nil {
			return nil, err
		}
		record.InputMatch = inputMatch != 0
		record.StateMatch = stateMatch != 0
		record.ResultMatch = resultMatch != 0
		record.Passed = passed != 0
		records = append(records, record)
	}
	return records, rows.Err()
}

func (l *Ledger) VerifyEvidenceChain(runID string) error {
	run, err := l.Run(runID)
	if err != nil {
		return err
	}
	if SHA256([]byte(run.ScenarioJSON)) != run.InputSHA256 {
		return fmt.Errorf("run %s scenario hash mismatch", runID)
	}
	steps, err := l.Steps(runID)
	if err != nil {
		return err
	}
	if len(steps) != run.StepCount {
		return fmt.Errorf("run %s step count: recorded=%d stored=%d", runID, len(steps), run.StepCount)
	}
	previous := hex.EncodeToString(make([]byte, sha256.Size))
	for index, step := range steps {
		if step.StepNo != index+1 {
			return fmt.Errorf("run %s step sequence gap at %d", runID, step.StepNo)
		}
		if SHA256([]byte(step.StateBeforeJSON)) != step.StateBeforeSHA256 {
			return fmt.Errorf("run %s step %d state hash mismatch", runID, step.StepNo)
		}
		if SHA256([]byte(step.ResultJSON)) != step.ResultSHA256 {
			return fmt.Errorf("run %s step %d result hash mismatch", runID, step.StepNo)
		}
		if SHA256([]byte(step.StateAfterJSON)) != step.StateAfterSHA256 {
			return fmt.Errorf("run %s step %d state-after hash mismatch", runID, step.StepNo)
		}
		expected := chainHash(
			previous, runID, step.StepNo, []byte(step.InputJSON),
			[]byte(step.StateBeforeJSON), []byte(step.ResultJSON),
			[]byte(step.StateAfterJSON),
		)
		if expected != step.EvidenceSHA256 {
			return fmt.Errorf("run %s step %d evidence chain mismatch", runID, step.StepNo)
		}
		previous = expected
	}
	if previous != run.EventSHA256 {
		return fmt.Errorf("run %s event head mismatch", runID)
	}
	if SHA256([]byte(run.FinalStateJSON)) != run.FinalStateSHA256 {
		return fmt.Errorf("run %s final state hash mismatch", runID)
	}
	return nil
}

func (l *Ledger) IntegrityCheck() ([]string, error) {
	messages := make([]string, 0)
	rows, err := l.db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var message string
		if err := rows.Scan(&message); err != nil {
			rows.Close()
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = l.db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var table, parent string
		var rowID, fkID int64
		if err := rows.Scan(&table, &rowID, &parent, &fkID); err != nil {
			return nil, err
		}
		messages = append(messages, fmt.Sprintf("foreign key violation: %s row %d -> %s", table, rowID, parent))
	}
	return messages, rows.Err()
}

type ArtifactRecord struct {
	Path   string
	SHA256 string
	Bytes  int64
}

func (l *Ledger) AttachArtifact(path string) (ArtifactRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ArtifactRecord{}, err
	}
	record := ArtifactRecord{Path: path, SHA256: SHA256(data), Bytes: int64(len(data))}
	_, err = l.db.Exec(`
INSERT OR REPLACE INTO artifacts(path, sha256, bytes) VALUES(?,?,?)`,
		record.Path, record.SHA256, record.Bytes,
	)
	if err != nil {
		return ArtifactRecord{}, err
	}
	return record, nil
}

func (l *Ledger) Artifacts() ([]ArtifactRecord, error) {
	rows, err := l.db.Query(`SELECT path, sha256, bytes FROM artifacts ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]ArtifactRecord, 0)
	for rows.Next() {
		var record ArtifactRecord
		if err := rows.Scan(&record.Path, &record.SHA256, &record.Bytes); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func chainHash(previous, runID string, stepNo int, parts ...[]byte) string {
	h := sha256.New()
	h.Write([]byte(previous))
	h.Write([]byte{0})
	h.Write([]byte(runID))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", stepNo)))
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
