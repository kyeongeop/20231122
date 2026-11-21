package model

import "encoding/json"

// Checkpoint is the resumable state boundary. ResultDigest covers all records
// before Cursor; StateDigest covers the checkpoint itself.
type Checkpoint struct {
	Schema         string `json:"schema"`
	RecordType     string `json:"record_type"`
	RunID          string `json:"run_id"`
	Seq            int64  `json:"seq"`
	Cursor         int64  `json:"cursor"`
	CompletedCount int64  `json:"completed_count"`
	Degraded       bool   `json:"degraded"`
	Mode           string `json:"mode"`
	ResultDigest   string `json:"result_digest"`
	Reason         string `json:"reason"`
	TSUTC          string `json:"ts_utc"`
	StateDigest    string `json:"state_digest"`
}

var CheckpointFields = []string{
	"schema", "record_type", "run_id", "seq", "cursor", "completed_count",
	"degraded", "mode", "result_digest", "reason", "ts_utc", "state_digest",
}

func NewCheckpoint(runID string) Checkpoint {
	return Checkpoint{
		Schema:     SchemaVersion,
		RecordType: "checkpoint",
		RunID:      runID,
	}
}

// Event is append-only evidence for lifecycle, degradation, and comparisons.
type Event struct {
	Schema        string `json:"schema"`
	RecordType    string `json:"record_type"`
	RunID         string `json:"run_id"`
	Seq           int64  `json:"seq"`
	Kind          string `json:"kind"`
	Cursor        int64  `json:"cursor"`
	TSUTC         string `json:"ts_utc"`
	Mode          string `json:"mode"`
	Reason        string `json:"reason"`
	ObjectID      string `json:"object_id"`
	InputName     string `json:"input_name"`
	InputSHA256   string `json:"input_sha256"`
	CheckpointSeq int64  `json:"checkpoint_seq"`
	ResultDigest  string `json:"result_digest"`
	Detail        string `json:"detail"`
}

var EventFields = []string{
	"schema", "record_type", "run_id", "seq", "kind", "cursor", "ts_utc",
	"mode", "reason", "object_id", "input_name", "input_sha256",
	"checkpoint_seq", "result_digest", "detail",
}

// Comparison proves a checkpoint or final state matches a recomputation.
type Comparison struct {
	Schema          string `json:"schema"`
	RecordType      string `json:"record_type"`
	RunID           string `json:"run_id"`
	Seq             int64  `json:"seq"`
	Phase           string `json:"phase"`
	BeforeDigest    string `json:"before_digest"`
	AfterDigest     string `json:"after_digest"`
	Match           bool   `json:"match"`
	ComparedRecords int64  `json:"compared_records"`
	Cursor          int64  `json:"cursor"`
	TSUTC           string `json:"ts_utc"`
	Detail          string `json:"detail"`
}

var ComparisonFields = []string{
	"schema", "record_type", "run_id", "seq", "phase", "before_digest",
	"after_digest", "match", "compared_records", "cursor", "ts_utc", "detail",
}

func MarshalCheckpoint(c Checkpoint) ([]byte, error) { return json.Marshal(c) }
func MarshalEvent(e Event) ([]byte, error)           { return json.Marshal(e) }
func MarshalComparison(c Comparison) ([]byte, error) { return json.Marshal(c) }

// RunSummary is the CLI-visible result of one invocation.
type RunSummary struct {
	RunID           string `json:"run_id"`
	Status          string `json:"status"`
	TotalEntries    int64  `json:"total_entries"`
	CompletedCount  int64  `json:"completed_count"`
	Paused          bool   `json:"paused"`
	Degraded        bool   `json:"degraded"`
	Cursor          int64  `json:"cursor"`
	CheckpointSeq   int64  `json:"checkpoint_seq"`
	ResultDigest    string `json:"result_digest"`
	RestoreCompared bool   `json:"restore_compared"`
	FinalCompared   bool   `json:"final_compared"`
}
