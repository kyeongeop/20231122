package model

const (
	ToolVersion   = "0.1.0"
	SchemaVersion = "auditfix.sqlite.v1"
)

type Case struct {
	CaseID           string `json:"case_id"`
	CreatedAt        string `json:"created_at"`
	Description      string `json:"description"`
	Status           string `json:"status"`
	AnalyzerVersion  string `json:"analyzer_version"`
	ClockOffsetNS    int64  `json:"clock_offset_ns"`
	ChainStatus      string `json:"chain_status"`
	AnchorPairCount  int    `json:"anchor_pair_count"`
	DeviceAEventRows int    `json:"device_a_event_rows"`
	DeviceBEventRows int    `json:"device_b_event_rows"`
	CorrectionCount  int    `json:"correction_count"`
}

type Event struct {
	Device        string `json:"device"`
	Ordinal       int    `json:"ordinal"`
	Seq           int64  `json:"seq"`
	TimeUnixNS    int64  `json:"time_unix_ns"`
	CorrectedNS   int64  `json:"corrected_time_unix_ns"`
	Kind          string `json:"kind"`
	AnchorID      string `json:"anchor_id"`
	Subject       string `json:"subject"`
	PayloadSHA256 string `json:"payload_sha256"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
	LineNo        int    `json:"line_no"`
	RawLine       string `json:"raw_line"`
	HashValid     bool   `json:"hash_valid"`
	ChainRelation string `json:"chain_relation"`
}

type Correction struct {
	CorrectionID      string `json:"correction_id"`
	CaseID            string `json:"case_id"`
	Device            string `json:"device"`
	SeqFrom           int64  `json:"seq_from"`
	SeqTo             int64  `json:"seq_to"`
	MissingCount      int64  `json:"missing_count"`
	LeftSeq           int64  `json:"left_seq"`
	LeftHash          string `json:"left_hash"`
	RightSeq          int64  `json:"right_seq"`
	RightPrevHash     string `json:"right_prev_hash"`
	CorrectedTimeFrom int64  `json:"corrected_time_from_unix_ns"`
	CorrectedTimeTo   int64  `json:"corrected_time_to_unix_ns"`
	AnchorPairsUsed   int    `json:"anchor_pairs_used"`
	RationaleCode     string `json:"rationale_code"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
}

type Evidence struct {
	BlobID     int64  `json:"blob_id"`
	CaseID     string `json:"case_id"`
	Role       string `json:"role"`
	SourceName string `json:"source_name"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

type Sample struct {
	SampleID    string `json:"sample_id"`
	CaseID      string `json:"case_id"`
	SampleIndex int    `json:"sample_index"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	SourceName  string `json:"source_name"`
	ImportedAt  string `json:"imported_at"`
}

type Run struct {
	RunID          string `json:"run_id"`
	CaseID         string `json:"case_id"`
	HarnessSHA256  string `json:"harness_sha256"`
	HarnessPath    string `json:"harness_path"`
	TimeoutMS      int64  `json:"timeout_ms"`
	FuzzArgs       string `json:"fuzz_args"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	RequestedLimit int    `json:"requested_limit"`
	CompletedCount int    `json:"completed_count"`
	AttemptCount   int    `json:"attempt_count"`
	ResumedCount   int    `json:"resumed_count"`
	SchemaVersion  string `json:"schema_version"`
}

type Attempt struct {
	AttemptID      int64  `json:"attempt_id"`
	RunID          string `json:"run_id"`
	SampleID       string `json:"sample_id"`
	SampleIndex    int    `json:"sample_index"`
	AttemptNo      int    `json:"attempt_no"`
	Status         string `json:"status"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	ExitCode       int    `json:"exit_code"`
	Signal         int    `json:"signal"`
	TimedOut       bool   `json:"timed_out"`
	Stdout         []byte `json:"stdout"`
	Stderr         []byte `json:"stderr"`
	StdoutSHA256   string `json:"stdout_sha256"`
	StderrSHA256   string `json:"stderr_sha256"`
	HarnessOutput  string `json:"harness_output"`
	ResultJSON     string `json:"result_json"`
	Error          string `json:"error"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
