package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"depthlab/internal/graphql"
)

type Record struct {
	RecordID           string
	Kind               string
	OriginalSHA256     string
	TruncatedSHA256    string
	RecoverySHA256     string
	TruncationOffset   int
	OmittedSuffix      []byte
	Original           []byte
	Truncated          []byte
	Recovered          []byte
	FuzzerArtifactPath string
	CreatedAt          string
}

type Run struct {
	RunID            string
	RecordID         string
	Scenario         string
	SourceRunID      string
	Status           string
	FirstErrorSeq    int
	FirstErrorStage  string
	FirstErrorCode   string
	FirstErrorDetail string
	FinalStateJSON   json.RawMessage
	StepCount        int
	CreatedAt        string
}

type StoredStep struct {
	Step      graphql.Step
	PrevHash  string
	EntryHash string
}

type Submission struct {
	RunID          string
	Seq            int
	EntryHash      string
	IdempotencyKey string
	Decision       string
	ErrorCode      string
	ErrorDetail    string
	RecordedAt     string
}

type Check struct {
	CheckID          string
	Kind             string
	SourceRunID      string
	Status           string
	FirstErrorSeq    int
	FirstErrorStage  string
	FirstErrorCode   string
	FirstErrorDetail string
	ObservedJSON     json.RawMessage
	RecordedAt       string
}

type Violation struct {
	Seq    int
	Stage  string
	Code   string
	Detail string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%s at seq %d (%s): %s", v.Code, v.Seq, v.Stage, v.Detail)
}

type Store struct {
	DB *DB
}

func Open(path string) (*Store, error) {
	db, err := OpenDB(path, false)
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db}
	if err := s.InitSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func OpenReadOnly(path string) (*Store, error) {
	db, err := OpenDB(path, true)
	if err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error {
	return s.DB.Close()
}

func (s *Store) InitSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS records (
			record_id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			original_sha256 TEXT NOT NULL,
			truncated_sha256 TEXT NOT NULL,
			recovery_sha256 TEXT NOT NULL,
			truncation_offset INTEGER NOT NULL,
			omitted_suffix BLOB NOT NULL,
			original_bytes BLOB NOT NULL,
			truncated_bytes BLOB NOT NULL,
			recovered_bytes BLOB NOT NULL,
			fuzzer_artifact_path TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			run_id TEXT PRIMARY KEY,
			record_id TEXT NOT NULL,
			scenario TEXT NOT NULL,
			source_run_id TEXT NOT NULL,
			status TEXT NOT NULL,
			first_error_seq INTEGER NOT NULL,
			first_error_stage TEXT NOT NULL,
			first_error_code TEXT NOT NULL,
			first_error_detail TEXT NOT NULL,
			final_state_json TEXT NOT NULL,
			step_count INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(record_id) REFERENCES records(record_id)
		)`,
		`CREATE TABLE IF NOT EXISTS steps (
			run_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			stage TEXT NOT NULL,
			input_json TEXT NOT NULL,
			state_before_json TEXT NOT NULL,
			state_after_json TEXT NOT NULL,
			result_json TEXT NOT NULL,
			status TEXT NOT NULL,
			error_code TEXT NOT NULL,
			error_detail TEXT NOT NULL,
			prev_hash TEXT NOT NULL,
			entry_hash TEXT NOT NULL,
			PRIMARY KEY (run_id, seq),
			UNIQUE (run_id, entry_hash),
			FOREIGN KEY(run_id) REFERENCES runs(run_id)
		)`,
		`CREATE TABLE IF NOT EXISTS submissions (
			submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			entry_hash TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			decision TEXT NOT NULL,
			error_code TEXT NOT NULL,
			error_detail TEXT NOT NULL,
			recorded_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS checks (
			check_id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			source_run_id TEXT NOT NULL,
			status TEXT NOT NULL,
			first_error_seq INTEGER NOT NULL,
			first_error_stage TEXT NOT NULL,
			first_error_code TEXT NOT NULL,
			first_error_detail TEXT NOT NULL,
			observed_json TEXT NOT NULL,
			recorded_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_submissions_run ON submissions(run_id, seq)`,
		`CREATE INDEX IF NOT EXISTS idx_steps_run_hash ON steps(run_id, entry_hash)`,
	}
	for _, statement := range statements {
		if err := s.DB.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (s *Store) InsertRecord(record Record) error {
	if record.CreatedAt == "" {
		record.CreatedAt = Now()
	}
	return s.DB.Exec(`INSERT INTO records (
		record_id, kind, original_sha256, truncated_sha256, recovery_sha256,
		truncation_offset, omitted_suffix, original_bytes, truncated_bytes,
		recovered_bytes, fuzzer_artifact_path, created_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		record.RecordID, record.Kind, record.OriginalSHA256, record.TruncatedSHA256,
		record.RecoverySHA256, record.TruncationOffset, record.OmittedSuffix,
		record.Original, record.Truncated, record.Recovered,
		record.FuzzerArtifactPath, record.CreatedAt,
	)
}

func (s *Store) CreateRun(run Run) error {
	if run.CreatedAt == "" {
		run.CreatedAt = Now()
	}
	return s.DB.Exec(`INSERT INTO runs (
		run_id, record_id, scenario, source_run_id, status,
		first_error_seq, first_error_stage, first_error_code,
		first_error_detail, final_state_json, step_count, created_at
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		run.RunID, run.RecordID, run.Scenario, run.SourceRunID, run.Status,
		run.FirstErrorSeq, run.FirstErrorStage, run.FirstErrorCode,
		run.FirstErrorDetail, string(run.FinalStateJSON), run.StepCount, run.CreatedAt,
	)
}

func ComputeEntryHash(runID, prevHash string, step graphql.Step) string {
	payload := struct {
		RunID       string          `json:"run_id"`
		Seq         int             `json:"seq"`
		Stage       string          `json:"stage"`
		Input       json.RawMessage `json:"input"`
		StateBefore json.RawMessage `json:"state_before"`
		StateAfter  json.RawMessage `json:"state_after"`
		Result      json.RawMessage `json:"result"`
		Status      string          `json:"status"`
		ErrorCode   string          `json:"error_code"`
		ErrorDetail string          `json:"error_detail"`
	}{runID, step.Seq, step.Stage, step.Input, step.StateBefore, step.StateAfter,
		step.Result, step.Status, step.ErrorCode, step.ErrorDetail}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(append([]byte(prevHash+"\n"), body...))
	return hex.EncodeToString(sum[:])
}

func (s *Store) SubmitStep(runID string, step graphql.Step, idempotencyKey string) (StoredStep, error) {
	if err := s.DB.Begin(); err != nil {
		return StoredStep{}, err
	}
	committed := false
	defer func() {
		if !committed {
			s.DB.Rollback()
		}
	}()

	if err := s.rejectIdempotencyConflict(runID, idempotencyKey, step); err != nil {
		if violation, ok := err.(*Violation); ok {
			if err := s.recordSubmission(Submission{
				RunID: runID, Seq: step.Seq, EntryHash: "", IdempotencyKey: idempotencyKey,
				Decision: "rejected", ErrorCode: violation.Code, ErrorDetail: violation.Detail,
			}); err != nil {
				return StoredStep{}, err
			}
			if commitErr := s.DB.Commit(); commitErr != nil {
				return StoredStep{}, commitErr
			}
			committed = true
			return StoredStep{}, violation
		}
		return StoredStep{}, err
	}

	prevHash, expectedSeq, err := s.head(runID)
	if err != nil {
		return StoredStep{}, err
	}
	entryHash := ComputeEntryHash(runID, prevHash, step)

	existingHash, existing, err := s.findExistingStep(runID, step.Seq, entryHash)
	if err != nil {
		return StoredStep{}, err
	} else if existing {
		violation := &Violation{
			Seq: step.Seq, Stage: step.Stage, Code: "DUPLICATE_STEP",
			Detail: fmt.Sprintf("step seq %d was already accepted for run %s", step.Seq, runID),
		}
		if err := s.recordSubmission(Submission{
			RunID: runID, Seq: step.Seq, EntryHash: existingHash, IdempotencyKey: idempotencyKey,
			Decision: "rejected", ErrorCode: violation.Code, ErrorDetail: violation.Detail,
		}); err != nil {
			return StoredStep{}, err
		}
		if commitErr := s.DB.Commit(); commitErr != nil {
			return StoredStep{}, commitErr
		}
		committed = true
		return StoredStep{}, violation
	}

	if step.Seq != expectedSeq {
		violation := &Violation{
			Seq: step.Seq, Stage: step.Stage, Code: "STEP_OUT_OF_ORDER",
			Detail: fmt.Sprintf("expected seq %d, got %d", expectedSeq, step.Seq),
		}
		if err := s.recordSubmission(Submission{
			RunID: runID, Seq: step.Seq, EntryHash: entryHash, IdempotencyKey: idempotencyKey,
			Decision: "rejected", ErrorCode: violation.Code, ErrorDetail: violation.Detail,
		}); err != nil {
			return StoredStep{}, err
		}
		if commitErr := s.DB.Commit(); commitErr != nil {
			return StoredStep{}, commitErr
		}
		committed = true
		return StoredStep{}, violation
	}

	err = s.DB.Exec(`INSERT INTO steps (
		run_id, seq, stage, input_json, state_before_json, state_after_json,
		result_json, status, error_code, error_detail, prev_hash, entry_hash
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		runID, step.Seq, step.Stage, string(step.Input), string(step.StateBefore),
		string(step.StateAfter), string(step.Result), step.Status, step.ErrorCode,
		step.ErrorDetail, prevHash, entryHash,
	)
	if err != nil {
		return StoredStep{}, err
	}
	if err := s.recordSubmission(Submission{
		RunID: runID, Seq: step.Seq, EntryHash: entryHash, IdempotencyKey: idempotencyKey,
		Decision: "accepted",
	}); err != nil {
		return StoredStep{}, err
	}
	if err := s.DB.Commit(); err != nil {
		return StoredStep{}, err
	}
	committed = true
	return StoredStep{Step: step, PrevHash: prevHash, EntryHash: entryHash}, nil
}

func (s *Store) rejectIdempotencyConflict(runID, key string, step graphql.Step) error {
	rows, err := s.DB.Query(`SELECT seq, entry_hash FROM submissions
		WHERE run_id=? AND idempotency_key=? AND decision='accepted' LIMIT 1`, runID, key)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var seq int
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return err
		}
		return &Violation{
			Seq: step.Seq, Stage: step.Stage, Code: "IDEMPOTENCY_CONFLICT",
			Detail: fmt.Sprintf("idempotency key %q already accepted for seq %d", key, seq),
		}
	}
	return rows.Err()
}

func (s *Store) head(runID string) (string, int, error) {
	rows, err := s.DB.Query(`SELECT seq, entry_hash FROM steps
		WHERE run_id=? ORDER BY seq DESC LIMIT 1`, runID)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	if rows.Next() {
		var seq int
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return "", 0, err
		}
		return hash, seq + 1, nil
	}
	return "", 1, rows.Err()
}

func (s *Store) findExistingStep(runID string, seq int, hash string) (string, bool, error) {
	rows, err := s.DB.Query(`SELECT entry_hash FROM steps
		WHERE run_id=? AND (seq=? OR entry_hash=?) LIMIT 1`, runID, seq, hash)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	var existingHash string
	if err := rows.Scan(&existingHash); err != nil {
		return "", false, err
	}
	return existingHash, true, nil
}

func (s *Store) recordSubmission(submission Submission) error {
	if submission.RecordedAt == "" {
		submission.RecordedAt = Now()
	}
	return s.DB.Exec(`INSERT INTO submissions (
		run_id, seq, entry_hash, idempotency_key, decision,
		error_code, error_detail, recorded_at
	) VALUES (?,?,?,?,?,?,?,?)`,
		submission.RunID, submission.Seq, submission.EntryHash,
		submission.IdempotencyKey, submission.Decision, submission.ErrorCode,
		submission.ErrorDetail, submission.RecordedAt,
	)
}

func (s *Store) FinishRun(runID string, trace graphql.Trace) error {
	status := "ok"
	seq := 0
	stage := ""
	code := ""
	detail := ""
	if trace.FirstError != nil {
		status = "error"
		seq = trace.FirstError.Seq
		stage = trace.FirstError.Stage
		code = trace.FirstError.Code
		detail = trace.FirstError.Detail
	}
	rows, err := s.DB.Query(`SELECT COUNT(*) FROM steps WHERE run_id=?`, runID)
	if err != nil {
		return err
	}
	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return s.DB.Exec(`UPDATE runs SET
		status=?, first_error_seq=?, first_error_stage=?, first_error_code=?,
		first_error_detail=?, final_state_json=?, step_count=? WHERE run_id=?`,
		status, seq, stage, code, detail, string(trace.FinalState), count, runID,
	)
}

func (s *Store) LoadSteps(runID string) ([]StoredStep, error) {
	rows, err := s.DB.Query(`SELECT seq, stage, input_json, state_before_json,
		state_after_json, result_json, status, error_code, error_detail,
		prev_hash, entry_hash FROM steps WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []StoredStep
	for rows.Next() {
		var stored StoredStep
		err := rows.Scan(
			&stored.Step.Seq, &stored.Step.Stage, &stored.Step.Input,
			&stored.Step.StateBefore, &stored.Step.StateAfter, &stored.Step.Result,
			&stored.Step.Status, &stored.Step.ErrorCode, &stored.Step.ErrorDetail,
			&stored.PrevHash, &stored.EntryHash,
		)
		if err != nil {
			return nil, err
		}
		steps = append(steps, stored)
	}
	return steps, rows.Err()
}

func (s *Store) InsertCheck(check Check) error {
	if check.RecordedAt == "" {
		check.RecordedAt = Now()
	}
	return s.DB.Exec(`INSERT INTO checks (
		check_id, kind, source_run_id, status, first_error_seq,
		first_error_stage, first_error_code, first_error_detail,
		observed_json, recorded_at
	) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		check.CheckID, check.Kind, check.SourceRunID, check.Status,
		check.FirstErrorSeq, check.FirstErrorStage, check.FirstErrorCode,
		check.FirstErrorDetail, string(check.ObservedJSON), check.RecordedAt,
	)
}

func (s *Store) LoadCheck(checkID string) (Check, error) {
	rows, err := s.DB.Query(`SELECT check_id, kind, source_run_id, status,
		first_error_seq, first_error_stage, first_error_code, first_error_detail,
		observed_json, recorded_at FROM checks WHERE check_id=?`, checkID)
	if err != nil {
		return Check{}, err
	}
	defer rows.Close()
	var check Check
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Check{}, err
		}
		return Check{}, fmt.Errorf("check %s not found", checkID)
	}
	err = rows.Scan(
		&check.CheckID, &check.Kind, &check.SourceRunID, &check.Status,
		&check.FirstErrorSeq, &check.FirstErrorStage, &check.FirstErrorCode,
		&check.FirstErrorDetail, &check.ObservedJSON, &check.RecordedAt,
	)
	return check, err
}

func (s *Store) LoadRun(runID string) (Run, error) {
	rows, err := s.DB.Query(`SELECT run_id, record_id, scenario, source_run_id,
		status, first_error_seq, first_error_stage, first_error_code,
		first_error_detail, final_state_json, step_count, created_at
		FROM runs WHERE run_id=?`, runID)
	if err != nil {
		return Run{}, err
	}
	defer rows.Close()
	var run Run
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Run{}, err
		}
		return Run{}, fmt.Errorf("run %s not found", runID)
	}
	err = rows.Scan(
		&run.RunID, &run.RecordID, &run.Scenario, &run.SourceRunID, &run.Status,
		&run.FirstErrorSeq, &run.FirstErrorStage, &run.FirstErrorCode,
		&run.FirstErrorDetail, &run.FinalStateJSON, &run.StepCount, &run.CreatedAt,
	)
	return run, err
}

func (s *Store) Count(query string, args ...any) (int, error) {
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, err
	}
	return count, rows.Err()
}

func VerifyChain(runID string, steps []StoredStep) *Violation {
	prev := ""
	for i, stored := range steps {
		expectedSeq := i + 1
		if stored.Step.Seq != expectedSeq {
			return &Violation{
				Seq: expectedSeq, Stage: stored.Step.Stage, Code: "STEP_OUT_OF_ORDER",
				Detail: fmt.Sprintf("replay position %d expected seq %d, got %d",
					i+1, expectedSeq, stored.Step.Seq),
			}
		}
		if stored.PrevHash != prev {
			return &Violation{
				Seq: expectedSeq, Stage: stored.Step.Stage, Code: "BROKEN_HASH_CHAIN",
				Detail: fmt.Sprintf("step %d prev_hash %s does not match replay head %s",
					expectedSeq, shortHash(stored.PrevHash), shortHash(prev)),
			}
		}
		calculated := ComputeEntryHash(runID, prev, stored.Step)
		if stored.EntryHash != calculated {
			return &Violation{
				Seq: expectedSeq, Stage: stored.Step.Stage, Code: "TAMPERED_STEP",
				Detail: fmt.Sprintf("step %d entry hash mismatch: stored %s calculated %s",
					expectedSeq, shortHash(stored.EntryHash), shortHash(calculated)),
			}
		}
		prev = stored.EntryHash
	}
	return nil
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
