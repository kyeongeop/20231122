package experiment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"depthlab/internal/graphql"
	"depthlab/internal/store"
)

const (
	RecordID       = "rec_libfuzzer_query_depth"
	TruncatedRunID = "run_truncated"
	RecoveredRunID = "run_recovered"
)

type Options struct {
	OutDir         string
	FuzzRecordPath string
	Limit          int
}

type ErrorView struct {
	Seq         int    `json:"seq"`
	Stage       string `json:"stage"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
	Position    int    `json:"position,omitempty"`
	ExpectedSeq int    `json:"expected_seq,omitempty"`
	ObservedSeq int    `json:"observed_seq,omitempty"`
}

type RunView struct {
	RunID      string         `json:"run_id"`
	Scenario   string         `json:"scenario"`
	Status     string         `json:"status"`
	StepCount  int            `json:"step_count"`
	FirstError *ErrorView     `json:"first_error,omitempty"`
	Steps      []graphql.Step `json:"steps"`
}

type CheckView struct {
	CheckID    string          `json:"check_id"`
	Kind       string          `json:"kind"`
	Status     string          `json:"status"`
	FirstError *ErrorView      `json:"first_error,omitempty"`
	Observed   json.RawMessage `json:"observed"`
}

type RecordView struct {
	RecordID                string `json:"record_id"`
	Kind                    string `json:"kind"`
	OriginalSHA256          string `json:"original_sha256"`
	TruncatedSHA256         string `json:"truncated_sha256"`
	RecoverySHA256          string `json:"recovery_sha256"`
	TruncationOffset        int    `json:"truncation_offset"`
	OmittedSuffix           string `json:"omitted_suffix"`
	OriginalBytes           int    `json:"original_bytes"`
	TruncatedBytes          int    `json:"truncated_bytes"`
	RecoveredEqualsOriginal bool   `json:"recovered_equals_original"`
	OriginalPath            string `json:"original_path"`
	TruncatedPath           string `json:"truncated_path"`
	RecoveredPath           string `json:"recovered_path"`
}

type Report struct {
	Experiment     string                `json:"experiment"`
	EvaluationMode string                `json:"evaluation_mode"`
	GeneratedAt    string                `json:"generated_at"`
	Limit          int                   `json:"limit"`
	Record         RecordView            `json:"record"`
	Runs           []RunView             `json:"runs"`
	Checks         []CheckView           `json:"checks"`
	FirstErrors    map[string]*ErrorView `json:"first_errors"`
	DatabasePath   string                `json:"database_path"`
	ManifestPath   string                `json:"manifest_path"`
}

func Execute(options Options) (*Report, error) {
	if options.OutDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}
	if options.FuzzRecordPath == "" {
		return nil, fmt.Errorf("libFuzzer crash record is required")
	}
	if options.Limit <= 0 {
		options.Limit = graphql.DefaultLimit
	}
	original, err := os.ReadFile(options.FuzzRecordPath)
	if err != nil {
		return nil, fmt.Errorf("read fuzzer record: %w", err)
	}
	if len(original) == 0 {
		return nil, fmt.Errorf("fuzzer record is empty")
	}

	offset, err := chooseTruncation(original, options.Limit)
	if err != nil {
		return nil, err
	}
	truncated := append([]byte(nil), original[:offset]...)
	suffix := append([]byte(nil), original[offset:]...)
	recovered := append(append([]byte(nil), truncated...), suffix...)
	if !bytes.Equal(recovered, original) {
		return nil, fmt.Errorf("internal recovery mismatch")
	}

	truncatedTrace := graphql.Analyze(string(truncated), options.Limit)
	recoveredTrace := graphql.Analyze(string(recovered), options.Limit)
	if err := validateTraces(truncatedTrace, recoveredTrace, options.Limit); err != nil {
		return nil, err
	}

	recordsDir := filepath.Join(options.OutDir, "records")
	if err := os.MkdirAll(recordsDir, 0o755); err != nil {
		return nil, err
	}
	originalPath := filepath.Join(recordsDir, "fuzzer-crash.graphql")
	truncatedPath := filepath.Join(recordsDir, "truncated.graphql")
	recoveredPath := filepath.Join(recordsDir, "recovered.graphql")
	suffixPath := filepath.Join(recordsDir, "omitted-suffix.bin")
	for path, data := range map[string][]byte{
		originalPath: original, truncatedPath: truncated, recoveredPath: recovered, suffixPath: suffix,
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
	}

	dbPath := filepath.Join(options.OutDir, "evidence.sqlite")
	if err := removeIfExists(dbPath); err != nil {
		return nil, err
	}
	for _, suffixName := range []string{"-journal", "-wal", "-shm"} {
		if err := removeIfExists(dbPath + suffixName); err != nil {
			return nil, err
		}
	}
	evidence, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer evidence.Close()

	record := store.Record{
		RecordID: RecordID, Kind: "libfuzzer_crash_truncated",
		OriginalSHA256: hashBytes(original), TruncatedSHA256: hashBytes(truncated),
		RecoverySHA256: hashBytes(recovered), TruncationOffset: offset,
		OmittedSuffix: suffix, Original: original, Truncated: truncated,
		Recovered: recovered, FuzzerArtifactPath: options.FuzzRecordPath,
	}
	if err := evidence.InsertRecord(record); err != nil {
		return nil, err
	}

	truncatedRun, err := recordRun(evidence, TruncatedRunID, "", "truncated_record", truncatedTrace)
	if err != nil {
		return nil, err
	}
	recoveredRun, err := recordRun(evidence, RecoveredRunID, TruncatedRunID,
		"recovered_replay_control", recoveredTrace)
	if err != nil {
		return nil, err
	}

	truncatedSteps, err := evidence.LoadSteps(TruncatedRunID)
	if err != nil {
		return nil, err
	}
	recoveredSteps, err := evidence.LoadSteps(RecoveredRunID)
	if err != nil {
		return nil, err
	}

	checks, err := runChecks(evidence, options.Limit, truncatedSteps, recoveredSteps)
	if err != nil {
		return nil, err
	}

	report := &Report{
		Experiment:     "graphql-query-depth-replay",
		EvaluationMode: "first-error-only",
		GeneratedAt:    store.Now(),
		Limit:          options.Limit,
		Record: RecordView{
			RecordID: RecordID, Kind: record.Kind,
			OriginalSHA256: record.OriginalSHA256, TruncatedSHA256: record.TruncatedSHA256,
			RecoverySHA256: record.RecoverySHA256, TruncationOffset: offset,
			OmittedSuffix: string(suffix), OriginalBytes: len(original),
			TruncatedBytes: len(truncated), RecoveredEqualsOriginal: bytes.Equal(recovered, original),
			OriginalPath: originalPath, TruncatedPath: truncatedPath, RecoveredPath: recoveredPath,
		},
		Runs:         []RunView{truncatedRun, recoveredRun},
		Checks:       checks,
		FirstErrors:  map[string]*ErrorView{},
		DatabasePath: dbPath,
		ManifestPath: filepath.Join(options.OutDir, "manifest.sha256"),
	}
	if truncatedTrace.FirstError != nil {
		report.FirstErrors["truncated"] = failureView(truncatedTrace.FirstError)
	}
	if recoveredTrace.FirstError != nil {
		report.FirstErrors["recovered_control"] = failureView(recoveredTrace.FirstError)
	}
	for _, check := range checks {
		report.FirstErrors[check.CheckID] = check.FirstError
	}

	if err := writeReportFiles(report, options.OutDir); err != nil {
		return nil, err
	}
	if err := evidence.Close(); err != nil {
		return nil, err
	}
	if err := writeManifest(options.OutDir, report.ManifestPath); err != nil {
		return nil, err
	}
	return report, nil
}

func chooseTruncation(original []byte, limit int) (int, error) {
	if len(original) < 4 {
		return 0, fmt.Errorf("fuzzer record is too short to truncate")
	}
	target := len(original) * 3 / 5
	best := -1
	for offset := 1; offset < len(original); offset++ {
		trace := graphql.Analyze(string(original[:offset]), limit)
		if trace.FirstError == nil || trace.FirstError.Stage != "syntax" {
			continue
		}
		code := trace.FirstError.Code
		if code != "UNCLOSED_DELIMITER" && code != "MISMATCHED_DELIMITER" {
			continue
		}
		if best == -1 || abs(offset-target) < abs(best-target) {
			best = offset
		}
	}
	if best == -1 {
		return 0, fmt.Errorf("no truncation point produces a syntax first error")
	}
	return best, nil
}

func validateTraces(truncated, recovered graphql.Trace, limit int) error {
	if truncated.FirstError == nil || truncated.FirstError.Stage != "syntax" {
		return fmt.Errorf("truncated record must first fail at syntax, got %+v", truncated.FirstError)
	}
	if recovered.FirstError == nil || recovered.FirstError.Stage != "policy" ||
		recovered.FirstError.Code != "DEPTH_LIMIT_EXCEEDED" {
		return fmt.Errorf("recovered control must first fail at depth policy, got %+v", recovered.FirstError)
	}
	var depth struct {
		MaxDepth int `json:"max_depth"`
	}
	if err := json.Unmarshal(recovered.Steps[3].Result, &depth); err != nil {
		return err
	}
	if depth.MaxDepth <= limit {
		return fmt.Errorf("fuzzer record depth %d does not exceed limit %d", depth.MaxDepth, limit)
	}
	return nil
}

func recordRun(s *store.Store, runID, sourceRunID, scenario string, trace graphql.Trace) (RunView, error) {
	if err := s.CreateRun(store.Run{
		RunID: runID, RecordID: RecordID, Scenario: scenario, SourceRunID: sourceRunID,
		Status: "running",
	}); err != nil {
		return RunView{}, err
	}
	for _, step := range trace.Steps {
		key := fmt.Sprintf("%s/%d/%s", runID, step.Seq, step.Stage)
		if _, err := s.SubmitStep(runID, step, key); err != nil {
			return RunView{}, fmt.Errorf("record %s: %w", runID, err)
		}
	}
	if err := s.FinishRun(runID, trace); err != nil {
		return RunView{}, err
	}
	steps, err := s.LoadSteps(runID)
	if err != nil {
		return RunView{}, err
	}
	view := RunView{
		RunID: runID, Scenario: scenario, Status: "ok", StepCount: len(steps),
		Steps: make([]graphql.Step, 0, len(steps)),
	}
	for _, stored := range steps {
		view.Steps = append(view.Steps, stored.Step)
	}
	if trace.FirstError != nil {
		view.Status = "error"
		view.FirstError = failureView(trace.FirstError)
	}
	return view, nil
}

func failureView(f *graphql.Failure) *ErrorView {
	return &ErrorView{Seq: f.Seq, Stage: f.Stage, Code: f.Code, Detail: f.Detail}
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func relTo(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return strings.ReplaceAll(rel, string(filepath.Separator), "/")
}
