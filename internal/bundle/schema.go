package bundle

const (
	FormatSchema = "auditfix.bundle.v1"
	ManifestName = "manifest.json"
	DigestName   = "manifest.sha256"
	DatabaseName = "state.sqlite"
)

type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type FieldOrders struct {
	Case       []string `json:"case"`
	Event      []string `json:"event"`
	Correction []string `json:"correction"`
	Evidence   []string `json:"evidence"`
	Sample     []string `json:"sample"`
	Run        []string `json:"run"`
	Attempt    []string `json:"attempt"`
}

type RowCounts struct {
	Events      int `json:"events"`
	Corrections int `json:"corrections"`
	Evidence    int `json:"evidence"`
	Samples     int `json:"samples"`
	Attempts    int `json:"attempts"`
}

type Manifest struct {
	Schema        string      `json:"schema"`
	ToolVersion   string      `json:"tool_version"`
	SQLiteSchema  string      `json:"sqlite_schema"`
	CaseID        string      `json:"case_id"`
	RunID         string      `json:"run_id"`
	RunStatus     string      `json:"run_status"`
	ExportedAt    string      `json:"exported_at"`
	HarnessSHA256 string      `json:"harness_sha256"`
	HarnessPath   string      `json:"harness_path"`
	TimeoutMS     int64       `json:"timeout_ms"`
	FuzzArgs      string      `json:"fuzz_args"`
	FieldOrders   FieldOrders `json:"field_orders"`
	RowCounts     RowCounts   `json:"row_counts"`
	Files         []FileEntry `json:"files"`
	Database      FileEntry   `json:"database"`
	ReviewNotes   []string    `json:"review_notes"`
}

type EvidenceRow struct {
	BlobID     int64  `json:"blob_id"`
	CaseID     string `json:"case_id"`
	Role       string `json:"role"`
	SourceName string `json:"source_name"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	BundlePath string `json:"bundle_path"`
}

type SampleRow struct {
	SampleID    string `json:"sample_id"`
	CaseID      string `json:"case_id"`
	SampleIndex int    `json:"sample_index"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	SourceName  string `json:"source_name"`
	ImportedAt  string `json:"imported_at"`
	BundlePath  string `json:"bundle_path"`
}

type AttemptRow struct {
	RunID          string `json:"run_id"`
	SampleID       string `json:"sample_id"`
	SampleIndex    int    `json:"sample_index"`
	SampleName     string `json:"sample_name"`
	AttemptNo      int    `json:"attempt_no"`
	Status         string `json:"status"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	ExitCode       int    `json:"exit_code"`
	Signal         int    `json:"signal"`
	TimedOut       bool   `json:"timed_out"`
	StdoutSHA256   string `json:"stdout_sha256"`
	StderrSHA256   string `json:"stderr_sha256"`
	StdoutPath     string `json:"stdout_path"`
	StderrPath     string `json:"stderr_path"`
	HarnessOutput  string `json:"harness_output"`
	ResultJSON     string `json:"result_json"`
	Error          string `json:"error"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

func expectedFieldOrders() FieldOrders {
	return FieldOrders{
		Case: []string{
			"case_id", "created_at", "description", "status", "analyzer_version",
			"clock_offset_ns", "chain_status", "anchor_pair_count",
			"device_a_event_rows", "device_b_event_rows", "correction_count",
		},
		Event: []string{
			"device", "ordinal", "seq", "time_unix_ns", "corrected_time_unix_ns",
			"kind", "anchor_id", "subject", "payload_sha256", "prev_hash",
			"record_hash", "line_no", "raw_line", "hash_valid", "chain_relation",
		},
		Correction: []string{
			"correction_id", "case_id", "device", "seq_from", "seq_to",
			"missing_count", "left_seq", "left_hash", "right_seq",
			"right_prev_hash", "corrected_time_from_unix_ns",
			"corrected_time_to_unix_ns", "anchor_pairs_used",
			"rationale_code", "status", "created_at",
		},
		Evidence: []string{
			"blob_id", "case_id", "role", "source_name", "sha256", "size",
			"bundle_path",
		},
		Sample: []string{
			"sample_id", "case_id", "sample_index", "name", "sha256", "size",
			"source_name", "imported_at", "bundle_path",
		},
		Run: runFields(),
		Attempt: []string{
			"run_id", "sample_id", "sample_index", "sample_name", "attempt_no",
			"status", "started_at", "finished_at", "exit_code", "signal",
			"timed_out", "stdout_sha256", "stderr_sha256", "stdout_path",
			"stderr_path", "harness_output", "result_json", "error",
			"evidence_sha256",
		},
	}
}

func runFields() []string {
	return []string{
		"run_id", "case_id", "harness_sha256", "harness_path", "timeout_ms",
		"fuzz_args", "status", "created_at", "started_at", "finished_at",
		"requested_limit", "completed_count", "attempt_count", "resumed_count",
		"schema_version",
	}
}

func fieldOrderForCase() []string {
	return expectedFieldOrders().Case
}

func fieldOrderForEvent() []string {
	return expectedFieldOrders().Event
}

func fieldOrderForCorrection() []string {
	return expectedFieldOrders().Correction
}

func fieldOrderForEvidence() []string {
	return expectedFieldOrders().Evidence
}

func fieldOrderForSample() []string {
	return expectedFieldOrders().Sample
}

func fieldOrderForRun() []string {
	return expectedFieldOrders().Run
}

func fieldOrderForAttempt() []string {
	return expectedFieldOrders().Attempt
}
