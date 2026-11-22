package export

import "taintlab/internal/model"

const (
	ToolVersion  = "taintlab/0.1.0"
	RecordSchema = "taintlab-record/v1"
	EventSchema  = "taintlab-event/v1"
)

type Options struct {
	ExportedAt string
}

type Record struct {
	RecordSchema string       `json:"record_schema"`
	RunID        int64        `json:"run_id"`
	CreatedAt    string       `json:"created_at"`
	CaseID       string       `json:"case_id"`
	TraceID      string       `json:"trace_id"`
	InputSHA256  string       `json:"input_sha256"`
	ResultSHA256 string       `json:"result_sha256"`
	RecordSHA256 string       `json:"record_sha256"`
	Result       model.Result `json:"result"`
}

type EventRecord struct {
	RecordSchema  string `json:"record_schema"`
	RunID         int64  `json:"run_id"`
	CaseID        string `json:"case_id"`
	TraceID       string `json:"trace_id"`
	EventOrdinal  int    `json:"event_ordinal"`
	EventID       string `json:"event_id"`
	DeviceID      string `json:"device_id"`
	Kind          string `json:"kind"`
	CausalOrder   int    `json:"causal_order"`
	WallTime      string `json:"wall_time"`
	MonotonicNS   int64  `json:"monotonic_ns"`
	PayloadSHA256 string `json:"payload_sha256"`
	Detail        string `json:"detail"`
	RecordSHA256  string `json:"record_sha256"`
}

type FileDigest struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format      string       `json:"format"`
	ToolVersion string       `json:"tool_version"`
	ExportedAt  string       `json:"exported_at"`
	RunCount    int          `json:"run_count"`
	EventCount  int          `json:"event_count"`
	Ordering    string       `json:"ordering"`
	Files       []FileDigest `json:"files"`
}

type Verification struct {
	Runs           int
	Events         int
	ReplayedRuns   int
	IncompleteRuns int
}
