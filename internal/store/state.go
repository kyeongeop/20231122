package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Run states.
const (
	StateNew       = "NEW"
	StateRunning   = "RUNNING"
	StateSuspended = "SUSPENDED"
	StateDegraded  = "DEGRADED"
	StateCompleted = "COMPLETED"
	StateFailed    = "FAILED"
)

// Evidence kinds kept for independent review.
const (
	EvidenceRawCaptureA  = "RAW_CAPTURE_A"
	EvidenceRawCaptureB  = "RAW_CAPTURE_B"
	EvidenceParseResultA = "PARSE_RESULT_A"
	EvidenceParseResultB = "PARSE_RESULT_B"
	EvidenceCheckpoint   = "CHECKPOINT_STATE"
	EvidenceReport       = "REPORT_JSON"
	EvidenceDiff         = "BEFORE_AFTER_DIFF"
)

// ErrNotFound is returned when a run or checkpoint does not exist.
var ErrNotFound = errors.New("not found")

// RunRow mirrors the runs table in exact column order.
type RunRow struct {
	RunID             string
	ObjectID          string
	State             string
	CreatedUnixNano   int64
	UpdatedUnixNano   int64
	InputSHA256       string
	InputSize         int64
	InputTruncated    bool
	ParseErrorClass   string
	BudgetTokens      int64
	BudgetBytes       int64
	TokensUsed        int64
	BytesUsed         int64
	DegradeLevel      int
	LastCheckpointSeq int64
}

// Checkpoint is one persisted suspend boundary.
type Checkpoint struct {
	RunID       string
	Seq         int64
	FrameOffset int64
	FrameCRC32  uint32
	StateJSON   string
	StateSHA256 string
	CreatedNs   int64
}

// ProcessingState is the resumable middle state. JSON field order is fixed
// and never changed; reloading must yield byte-identical state.
type ProcessingState struct {
	RunID            string           `json:"run_id"`
	NextSeq          int64            `json:"next_seq"`
	ConsumedFrames   int64            `json:"consumed_frames"`
	Accumulator      map[string]int64 `json:"accumulator"`
	SeenCheckpoints  []int64          `json:"seen_checkpoints"`
	DegradeLevel     int              `json:"degrade_level"`
	InputFingerprint string           `json:"input_fingerprint"`
	Stage            string           `json:"stage"`
}

func nowNs() int64 { return time.Now().UTC().UnixNano() }

// CreateRun inserts a new run row.
func (s *Store) CreateRun(r RunRow, budgetTokens, budgetBytes int64) error {
	r.CreatedUnixNano = nowNs()
	r.UpdatedUnixNano = r.CreatedUnixNano
	r.BudgetTokens = budgetTokens
	r.BudgetBytes = budgetBytes
	_, err := s.db.Exec(`INSERT INTO runs(
		run_id,object_id,state,created_unix_nano,updated_unix_nano,
		input_sha256,input_size,input_truncated,parse_error_class,
		budget_tokens,budget_bytes,tokens_used,bytes_used,
		degrade_level,last_checkpoint_seq)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.RunID, r.ObjectID, r.State, r.CreatedUnixNano, r.UpdatedUnixNano,
		r.InputSHA256, r.InputSize, r.InputTruncated, r.ParseErrorClass,
		r.BudgetTokens, r.BudgetBytes, r.TokensUsed, r.BytesUsed,
		r.DegradeLevel, r.LastCheckpointSeq)
	return err
}

// GetRun loads a run row.
func (s *Store) GetRun(runID string) (RunRow, error) {
	var r RunRow
	err := s.db.QueryRow(`SELECT
		run_id,object_id,state,created_unix_nano,updated_unix_nano,
		input_sha256,input_size,input_truncated,parse_error_class,
		budget_tokens,budget_bytes,tokens_used,bytes_used,
		degrade_level,last_checkpoint_seq FROM runs WHERE run_id=?`, runID).Scan(
		&r.RunID, &r.ObjectID, &r.State, &r.CreatedUnixNano, &r.UpdatedUnixNano,
		&r.InputSHA256, &r.InputSize, &r.InputTruncated, &r.ParseErrorClass,
		&r.BudgetTokens, &r.BudgetBytes, &r.TokensUsed, &r.BytesUsed,
		&r.DegradeLevel, &r.LastCheckpointSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return RunRow{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	return r, err
}

// UpdateProgress persists counters, state and degradation level atomically.
func (s *Store) UpdateProgress(runID, state string, tokensUsed, bytesUsed int64, level int, lastSeq int64) error {
	_, err := s.db.Exec(`UPDATE runs SET state=?,updated_unix_nano=?,
		tokens_used=?,bytes_used=?,degrade_level=?,last_checkpoint_seq=?
		WHERE run_id=?`, state, nowNs(), tokensUsed, bytesUsed, level, lastSeq, runID)
	return err
}

// SaveCheckpoint writes a state snapshot and returns its sha256. The JSON
// is encoded deterministically (struct order, sorted map keys) so the hash
// is reproducible by a reviewer.
func (s *Store) SaveCheckpoint(cp Checkpoint, st ProcessingState) (string, error) {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	cp.StateJSON = string(raw)
	cp.StateSHA256 = hex.EncodeToString(sum[:])
	cp.CreatedNs = nowNs()
	_, err = s.db.Exec(`INSERT INTO checkpoints(
		run_id,seq,frame_offset,frame_crc32,state_json,state_sha256,created_unix_nano)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(run_id,seq) DO UPDATE SET
		frame_offset=excluded.frame_offset,
		frame_crc32=excluded.frame_crc32,
		state_json=excluded.state_json,
		state_sha256=excluded.state_sha256,
		created_unix_nano=excluded.created_unix_nano`,
		cp.RunID, cp.Seq, cp.FrameOffset, cp.FrameCRC32, cp.StateJSON,
		cp.StateSHA256, cp.CreatedNs)
	return cp.StateSHA256, err
}

// LatestCheckpoint returns the most recent snapshot for a run.
func (s *Store) LatestCheckpoint(runID string) (Checkpoint, ProcessingState, error) {
	var cp Checkpoint
	err := s.db.QueryRow(`SELECT run_id,seq,frame_offset,frame_crc32,
		state_json,state_sha256,created_unix_nano FROM checkpoints
		WHERE run_id=? ORDER BY seq DESC LIMIT 1`, runID).Scan(
		&cp.RunID, &cp.Seq, &cp.FrameOffset, &cp.FrameCRC32,
		&cp.StateJSON, &cp.StateSHA256, &cp.CreatedNs)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, ProcessingState{}, fmt.Errorf("%w: checkpoint for %s", ErrNotFound, runID)
	}
	if err != nil {
		return Checkpoint{}, ProcessingState{}, err
	}
	var st ProcessingState
	if err := json.Unmarshal([]byte(cp.StateJSON), &st); err != nil {
		return Checkpoint{}, ProcessingState{}, err
	}
	return cp, st, nil
}
