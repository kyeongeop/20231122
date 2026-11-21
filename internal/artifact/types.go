// Package artifact writes and verifies self-contained corpus evidence bundles.
package artifact

import "corpusd/internal/model"

const Generator = "corpusd-export-go-sqlite"

type FileEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

var FileEntryFields = []string{"name", "sha256", "bytes"}

type InputFile struct {
	Seq    int64  `json:"seq"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

var InputFileFields = []string{"seq", "name", "sha256", "bytes"}

// Manifest makes the bundle reviewable without SQLite or the original corpus.
type Manifest struct {
	Schema            string      `json:"schema"`
	RecordType        string      `json:"record_type"`
	Generator         string      `json:"generator"`
	RunID             string      `json:"run_id"`
	Status            string      `json:"status"`
	ExportedTS        string      `json:"exported_ts"`
	CorpusFingerprint string      `json:"corpus_fingerprint"`
	RecordFields      []string    `json:"record_fields"`
	ObservationFields []string    `json:"observation_fields"`
	AnalysisFields    []string    `json:"analysis_fields"`
	EvidenceFields    []string    `json:"evidence_fields"`
	RecordCount       int         `json:"record_count"`
	CheckpointCount   int         `json:"checkpoint_count"`
	EventCount        int         `json:"event_count"`
	ComparisonCount   int         `json:"comparison_count"`
	InputCount        int         `json:"input_count"`
	ResultDigest      string      `json:"result_digest"`
	RecordsSHA256     string      `json:"records_sha256"`
	ComparisonsPass   bool        `json:"comparisons_pass"`
	Finalized         bool        `json:"finalized"`
	Files             []FileEntry `json:"files"`
	Inputs            []InputFile `json:"inputs"`
}

var ManifestFields = []string{
	"schema", "record_type", "generator", "run_id", "status", "exported_ts",
	"corpus_fingerprint", "record_fields", "observation_fields",
	"analysis_fields", "evidence_fields", "record_count", "checkpoint_count",
	"event_count", "comparison_count", "input_count", "result_digest",
	"records_sha256", "comparisons_pass", "finalized", "files", "inputs",
}

type Export struct {
	Dir         string
	Manifest    Manifest
	Records     []model.Record
	Checkpoints []model.Checkpoint
	Events      []model.Event
	Comparisons []model.Comparison
}

type VerifyReport struct {
	RunID           string `json:"run_id"`
	Status          string `json:"status"`
	Records         int    `json:"records"`
	Inputs          int    `json:"inputs"`
	Checkpoints     int    `json:"checkpoints"`
	Events          int    `json:"events"`
	Comparisons     int    `json:"comparisons"`
	RestoreCompared bool   `json:"restore_compared"`
	FinalCompared   bool   `json:"final_compared"`
	ResultDigest    string `json:"result_digest"`
	FilesVerified   int    `json:"files_verified"`
}
