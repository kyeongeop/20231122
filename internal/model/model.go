// Package model defines the stable, versioned records used by the corpus
// pipeline and by independent export verification.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	SchemaVersion = "corpusd/v1"
	RecordType    = "fuzz_corpus_object"
	ExportSchema  = "corpusd-export/v1"

	ModeFull     = "full"
	ModeDegraded = "degraded"

	DecisionAnalyzed       = "analyzed"
	DecisionAnalyzedRepeat = "analyzed_repeat"
	DecisionMetadataOnly   = "metadata_only"
	DecisionMetadataRepeat = "metadata_only_repeat"
)

// Config is the deterministic part of a run. Changing it for an existing run
// is rejected so a resumed result is always comparable with its baseline.
type Config struct {
	Schema            string `json:"schema"`
	BaseTimeUTC       string `json:"base_time_utc"`
	SampleIntervalMS  int64  `json:"sample_interval_ms"`
	ClockSkewMS       int64  `json:"clock_skew_ms"`
	MemoryBudgetBytes int64  `json:"memory_budget_bytes"`
	MaxInputBytes     int64  `json:"max_input_bytes"`
	CheckpointEvery   int    `json:"checkpoint_every"`
}

// ClockObservation preserves the raw clock reading and the correction used to
// place an observation on the run's canonical timeline.
type ClockObservation struct {
	DeviceID      string `json:"device_id"`
	ClockRole     string `json:"clock_role"`
	RawTSNS       int64  `json:"raw_ts_ns"`
	ClockOffsetNS int64  `json:"clock_offset_ns"`
	CorrectedTSNS int64  `json:"corrected_ts_ns"`
	SkewMS        int64  `json:"skew_ms"`
}

// Analysis is deliberately small and deterministic. The same bytes and mode
// always produce the same values, whether processed before or after a pause.
type Analysis struct {
	Format        string `json:"format"`
	Features      int    `json:"features"`
	CoverageBytes int    `json:"coverage_bytes"`
	ContentSHA256 string `json:"content_sha256"`
	ResultSHA256  string `json:"result_sha256"`
}

// Evidence keeps the facts needed to review a record without opening SQLite.
type Evidence struct {
	CorpusIndex          int64  `json:"corpus_index"`
	SourcePath           string `json:"source_path"`
	MemoryBudgetBytes    int64  `json:"memory_budget_bytes"`
	MemoryRemainingBytes int64  `json:"memory_remaining_bytes"`
	EstimatedBytes       int64  `json:"estimated_bytes"`
	ClockCorrectionNS    int64  `json:"clock_correction_ns"`
	FirstSeenSeq         int64  `json:"first_seen_seq"`
	AnalysisReused       bool   `json:"analysis_reused"`
	ReusedFromSeq        int64  `json:"reused_from_seq"`
}

// Record is one independently reviewable corpus object result. Field order is
// part of the wire contract and is checked when artifacts are loaded.
type Record struct {
	Schema          string             `json:"schema"`
	RecordType      string             `json:"record_type"`
	RunID           string             `json:"run_id"`
	Seq             int64              `json:"seq"`
	ObjectID        string             `json:"object_id"`
	InputName       string             `json:"input_name"`
	InputSHA256     string             `json:"input_sha256"`
	InputBytes      int64              `json:"input_bytes"`
	Observations    []ClockObservation `json:"observations"`
	CanonicalDevice string             `json:"canonical_device"`
	CanonicalTSNS   int64              `json:"canonical_ts_ns"`
	Duplicate       bool               `json:"duplicate"`
	DuplicateOfSeq  int64              `json:"duplicate_of_seq"`
	Mode            string             `json:"mode"`
	DegradedReason  string             `json:"degraded_reason"`
	Decision        string             `json:"decision"`
	Analysis        Analysis           `json:"analysis"`
	Evidence        Evidence           `json:"evidence"`
}

// RecordFields is the exact top-level field order for records.jsonl.
var RecordFields = []string{
	"schema", "record_type", "run_id", "seq", "object_id", "input_name",
	"input_sha256", "input_bytes", "observations", "canonical_device",
	"canonical_ts_ns", "duplicate", "duplicate_of_seq", "mode",
	"degraded_reason", "decision", "analysis", "evidence",
}

// ObservationFields is the exact field order for each observation.
var ObservationFields = []string{
	"device_id", "clock_role", "raw_ts_ns", "clock_offset_ns",
	"corrected_ts_ns", "skew_ms",
}

var AnalysisFields = []string{
	"format", "features", "coverage_bytes", "content_sha256", "result_sha256",
}

var EvidenceFields = []string{
	"corpus_index", "source_path", "memory_budget_bytes",
	"memory_remaining_bytes", "estimated_bytes", "clock_correction_ns",
	"first_seen_seq", "analysis_reused", "reused_from_seq",
}

func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func ParseBaseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse base time: %w", err)
	}
	return t.UTC(), nil
}

func ObjectID(sha string) string { return "sha256:" + sha }

func MarshalRecord(r Record) ([]byte, error) {
	return json.Marshal(r)
}

// RecordDigest ignores run-specific and wall-clock fields so it can compare
// the same object sequence across runs and across pause/resume boundaries.
func RecordDigest(r Record) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%d\x00%s\x00%d\x00%t\x00%d\x00%s\x00%s\x00%s\x00",
		r.Seq, r.ObjectID, r.InputName, r.InputSHA256, r.InputBytes,
		r.CanonicalDevice, r.CanonicalTSNS, r.Duplicate, r.DuplicateOfSeq,
		r.Mode, r.DegradedReason, r.Decision)
	for _, o := range r.Observations {
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00",
			o.DeviceID, o.ClockRole, o.RawTSNS, o.ClockOffsetNS,
			o.CorrectedTSNS, o.SkewMS)
	}
	fmt.Fprintf(h, "%s\x00%d\x00%d\x00%s\x00%s\x00%d\x00%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%t\x00%d\x00",
		r.Analysis.Format, r.Analysis.Features, r.Analysis.CoverageBytes,
		r.Analysis.ContentSHA256, r.Analysis.ResultSHA256,
		r.Evidence.CorpusIndex, r.Evidence.SourcePath,
		r.Evidence.MemoryBudgetBytes, r.Evidence.MemoryRemainingBytes,
		r.Evidence.EstimatedBytes, r.Evidence.ClockCorrectionNS,
		r.Evidence.FirstSeenSeq, r.Evidence.AnalysisReused,
		r.Evidence.ReusedFromSeq)
	return hex.EncodeToString(h.Sum(nil))
}

// ResultDigest binds an ordered record sequence into one stable value.
func ResultDigest(records []Record) string {
	h := sha256.New()
	for _, r := range records {
		fmt.Fprintf(h, "%d:%s\n", r.Seq, RecordDigest(r))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func CheckpointDigest(c Checkpoint) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%d\x00%d\x00%t\x00%s\x00%s\x00%s\x00%s\x00",
		c.Seq, c.Cursor, c.CompletedCount, c.Degraded, c.Mode,
		c.ResultDigest, c.TSUTC, c.Reason)
	return hex.EncodeToString(h.Sum(nil))
}
